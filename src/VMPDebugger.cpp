#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <vector>
#include <fstream>
#include <sstream>
#include "vmprotectunpacker/VMPDebugger.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"
#include <capstone/capstone.h>
#include <iomanip>


static bool TextSectionPopulated(HANDLE hProcess, LPVOID imageBase, DWORD textRVA, size_t checkBytes = 256)
{
    std::vector<BYTE> buf(checkBytes, 0);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProcess, (BYTE *)imageBase + textRVA, buf.data(), checkBytes, &r) || r == 0)
        return false;
    for (size_t i = 0; i < r; ++i)
        if (buf[i] != 0)
            return true;
    return false;
}

static void SuspendAllThreads(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;
    THREADENTRY32 te = {sizeof(te)};
    if (Thread32First(hSnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid)
            {
                HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hT)
                {
                    SuspendThread(hT);
                    CloseHandle(hT);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

bool VMPDebugger::Run(const std::string &exePath)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};

    Logger::Log("[*] Launching target suspended (no debug attach)...");
    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        Logger::Log("[-] Failed to launch target", LogLevel::Error);
        return false;
    }

    using pNtQIP = NTSTATUS(WINAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = (pNtQIP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {};
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    PVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(PVOID), nullptr);

    BYTE headers[0x1000] = {};
    ReadProcessMemory(pi.hProcess, imageBase, headers, sizeof(headers), nullptr);

    auto *dos = (IMAGE_DOS_HEADER *)headers;
    auto *nt_generic = (IMAGE_NT_HEADERS32 *)((BYTE *)headers + dos->e_lfanew);

    // --- PEB Anti-Debug Flag Scrubbing ---
    BYTE zeroByte = 0;
    DWORD zeroDword = 0;
    uintptr_t pebAddr = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);

    // Clear BeingDebugged (PEB + 0x02)
    WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pebAddr + 2), &zeroByte, sizeof(zeroByte), nullptr);

    // Clear NtGlobalFlag (PEB + 0xBC on x64, PEB + 0x68 on x86)
    BOOL isTarget64 = (nt_generic->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    uintptr_t ntGlobalFlagOffset = pebAddr + (isTarget64 ? 0xBC : 0x68);
    WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(ntGlobalFlagOffset), &zeroDword, sizeof(zeroDword), nullptr);
    Logger::Log("[+] Patched PEB: BeingDebugged and NtGlobalFlag successfully cleared.");

    // Determine Capstone mode and section metadata
    cs_mode capstoneMode = CS_MODE_64;
    SIZE_T imgSize = nt_generic->OptionalHeader.SizeOfImage;
    DWORD oepRVA = nt_generic->OptionalHeader.AddressOfEntryPoint;
    LPVOID oepVA = (BYTE *)imageBase + oepRVA;
    int numberOfSections = (int)nt_generic->FileHeader.NumberOfSections;

    if (nt_generic->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto *nt32 = (IMAGE_NT_HEADERS32 *)nt_generic;
        capstoneMode = CS_MODE_32;
        imgSize = nt32->OptionalHeader.SizeOfImage;
        oepRVA = nt32->OptionalHeader.AddressOfEntryPoint;
        oepVA = (BYTE *)imageBase + oepRVA;
        numberOfSections = (int)nt32->FileHeader.NumberOfSections;
    }
    else if (nt_generic->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto *nt64 = (IMAGE_NT_HEADERS64 *)nt_generic;
        capstoneMode = CS_MODE_64;
        imgSize = nt64->OptionalHeader.SizeOfImage;
        oepRVA = nt64->OptionalHeader.AddressOfEntryPoint;
        oepVA = (BYTE *)imageBase + oepRVA;
        numberOfSections = (int)nt64->FileHeader.NumberOfSections;
    }

    // Find .text section RVA
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt_generic);
    DWORD textRVA = 0x1000;
    for (int i = 0; i < numberOfSections; ++i)
    {
        char name[9] = {};
        memcpy(name, secs[i].Name, 8);
        if (strcmp(name, ".text") == 0)
        {
            textRVA = secs[i].VirtualAddress;
            break;
        }
    }

    Logger::Log("[+] ImageBase: " + ToHex((uintptr_t)imageBase));
    Logger::Log("[+] OEP RVA:   " + ToHex((uintptr_t)oepRVA));
    Logger::Log("[+] .text RVA: " + ToHex((uintptr_t)textRVA));

    ResumeThread(pi.hThread);
    Logger::Log("[+] Process resumed - polling .text for VMP stub writes (max 30s)...");

    bool dumpDone = false;
    const int MAX_POLLS = 3000; // 30 seconds

    for (int poll = 0; poll < MAX_POLLS; ++poll)
    {
        Sleep(10);

        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        bool dead = (exitCode != STILL_ACTIVE);

        if (TextSectionPopulated(pi.hProcess, imageBase, textRVA, 256))
        {
            Logger::Log("[+] .text populated after ~" + std::to_string(poll * 10) + "ms");

            if (!dead)
            {
                Sleep(50);
                SuspendAllThreads(pi.dwProcessId);
            }

            BYTE hdrBuf[0x1000] = {};
            SIZE_T hr = 0;
            ReadProcessMemory(pi.hProcess, imageBase, hdrBuf, sizeof(hdrBuf), &hr);
            SIZE_T finalSize = imgSize;
            if (hr > 0x40)
            {
                auto *dos2 = (IMAGE_DOS_HEADER *)hdrBuf;
                if (dos2->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    auto* nt_generic2 = (IMAGE_NT_HEADERS32*)((BYTE*)hdrBuf + dos2->e_lfanew);
                    if (nt_generic2->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                        auto* nt32 = (IMAGE_NT_HEADERS32*)nt_generic2;
                        if (nt32->OptionalHeader.SizeOfImage > 0)
                            finalSize = nt32->OptionalHeader.SizeOfImage;
                    }
                    else if (nt_generic2->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                        auto* nt64 = (IMAGE_NT_HEADERS64*)nt_generic2;
                        if (nt64->OptionalHeader.SizeOfImage > 0)
                            finalSize = nt64->OptionalHeader.SizeOfImage;
                    }
                }
            }

            dumpDone = DumpProcessImage(pi.hProcess, imageBase, finalSize, "unpacked_dump.bin");
            if (!dead)
                TerminateProcess(pi.hProcess, 0);
            break;
        }

        if (dead)
        {
            Logger::Log("[!] Process exited (" + ToHex((uintptr_t)exitCode) +
                        ") before .text was populated — VMP killed itself pre-initialization.");
            // Last-chance dump even if .text is zero
            dumpDone = DumpProcessImage(pi.hProcess, imageBase, imgSize, "unpacked_dump.bin");
            break;
        }
    }

    if (!dumpDone && !TextSectionPopulated(pi.hProcess, imageBase, textRVA, 32))
        Logger::Log("[-] Poll timed out or .text never populated.", LogLevel::Error);

    // Disassemble OEP from live/terminated process for diagnostics
    processHandle = pi.hProcess;
    Disassemble(oepVA, 0x40, capstoneMode);

    processHandle = pi.hProcess;
    threadHandle = pi.hThread;

    return dumpDone;
}

bool VMPDebugger::DumpProcessImage(HANDLE hProcess, LPVOID baseAddress, SIZE_T imageSize, const std::string &dumpPath)
{
    std::vector<BYTE> buffer(imageSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, baseAddress, buffer.data(), imageSize, &bytesRead) || bytesRead == 0)
    {
        Logger::Log("[-] ReadProcessMemory failed.", LogLevel::Error);
        return false;
    }
    if (bytesRead < imageSize)
    {
        Logger::Log("[*] Partial read: " + std::to_string(bytesRead) + "/" + std::to_string(imageSize) + " bytes");
        buffer.resize(bytesRead);
    }

    std::ofstream outFile(dumpPath, std::ios::binary);
    if (!outFile)
    {
        Logger::Log("[-] Failed to open dump file: " + dumpPath, LogLevel::Error);
        return false;
    }

    outFile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    outFile.close();
    Logger::Log("[+] Dumped " + std::to_string(buffer.size()) + " bytes to: " + dumpPath);

    std::ostringstream oss;
    size_t preview = std::min<size_t>(128, buffer.size());
    for (size_t i = 0; i < preview; ++i)
    {
        if (i % 16 == 0)
            oss << "\n"
                << std::hex << std::setw(8) << std::setfill('0') << i << ": ";
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
    }
    Logger::Log("[*] Dump hex preview:" + oss.str());
    return true;
}

bool VMPDebugger::Disassemble(LPVOID address, size_t size, cs_mode mode)
{
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle, address, buffer.data(), size, &bytesRead))
    {
        Logger::Log("[-] Failed to read memory for disassembly", LogLevel::Error);
        return false;
    }

    int major = 0;
    int minor = 0;
    cs_version(&major, &minor);

    Logger::Log(Utils::Format(
        "[*] Capstone config: arch=%d, mode=%d, version=%d.%d, supports-x86=%d",
        static_cast<int>(CS_ARCH_X86),
        static_cast<int>(mode),
        major,
        minor,
        cs_support(CS_ARCH_X86) ? 1 : 0));

    csh handle;
    cs_insn *insn;
    cs_err err = cs_open(CS_ARCH_X86, mode, &handle);
    if (err != CS_ERR_OK)
    {
        Logger::Log(
            Utils::Format("[-] Capstone init failed. Error Code: %d (Mode: %d)", (int)err, (int)mode),
            LogLevel::Error);
        return false;
    }

    size_t count = cs_disasm(handle, buffer.data(), bytesRead, (uint64_t)address, 0, &insn);
    if (count > 0)
    {
        Logger::Log("[+] OEP disassembly:");
        for (size_t i = 0; i < count && i < 16; i++)
        {
            std::ostringstream oss;
            oss << "  0x" << std::hex << insn[i].address << ": "
                << insn[i].mnemonic << " " << insn[i].op_str;
            Logger::Log(oss.str());
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
    return count > 0;
}
