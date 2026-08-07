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

static bool TextSectionStable(HANDLE hProcess, LPVOID imageBase, DWORD textRVA, DWORD textSize,
                              size_t sampleBytes, DWORD stabilityDelayMs)
{
    size_t n = std::min<size_t>(sampleBytes, textSize);
    std::vector<BYTE> before(n), after(n);
    SIZE_T r1 = 0, r2 = 0;

    if (!ReadProcessMemory(hProcess, (BYTE *)imageBase + textRVA, before.data(), n, &r1) || r1 == 0)
        return false;

    bool anyNonZero = false;
    for (size_t i = 0; i < r1; ++i)
        if (before[i] != 0)
        {
            anyNonZero = true;
            break;
        }
    if (!anyNonZero)
        return false;

    Sleep(stabilityDelayMs);

    if (!ReadProcessMemory(hProcess, (BYTE *)imageBase + textRVA, after.data(), n, &r2) || r2 != r1)
        return false;

    return memcmp(before.data(), after.data(), r1) == 0;
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

DWORD VMPDebugger::FindRealOEP(HANDLE hProcess, LPVOID imageBase, DWORD codeRVA, DWORD codeSize, bool is64)
{
    if (codeSize == 0)
        codeSize = 0x00100000;
    std::vector<BYTE> codeBuf(codeSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, (BYTE *)imageBase + codeRVA, codeBuf.data(), codeSize, &bytesRead) || bytesRead < 16)
    {
        Logger::Log("[-] Failed to read code section memory for OEP scanning.", LogLevel::WARNING);
        return codeRVA;
    }

    // 1. Scan for Delphi / standard x86 prologue: 55 8B EC (push ebp; mov ebp, esp)
    for (size_t i = 0; i < bytesRead - 8; ++i)
    {
        if (codeBuf[i] == 0x55 && codeBuf[i + 1] == 0x8B && codeBuf[i + 2] == 0xEC)
        {
            BYTE b3 = codeBuf[i + 3];
            // Delphi / C++ function prologues: add esp (-XX), push ebx, mov eax, push esi, push edi
            if (b3 == 0x83 || b3 == 0x53 || b3 == 0xB8 || b3 == 0x56 || b3 == 0x57 || b3 == 0xA1)
            {
                DWORD foundOEP = codeRVA + static_cast<DWORD>(i);
                Logger::Log("[+] Detected real OEP pattern (55 8B EC) at RVA: " + ToHex((uintptr_t)foundOEP));
                return foundOEP;
            }
        }
    }

    // 2. Scan for x64 MSVC entry point pattern: 48 83 EC (sub rsp, imm8)
    if (is64)
    {
        for (size_t i = 0; i < bytesRead - 8; ++i)
        {
            if (codeBuf[i] == 0x48 && codeBuf[i + 1] == 0x83 && codeBuf[i + 2] == 0xEC)
            {
                DWORD foundOEP = codeRVA + static_cast<DWORD>(i);
                Logger::Log("[+] Detected real x64 OEP pattern (48 83 EC) at RVA: " + ToHex((uintptr_t)foundOEP));
                return foundOEP;
            }
        }
    }

    // 3. Fallback: First non-zero code block
    for (size_t i = 0; i < bytesRead - 4; ++i)
    {
        if (codeBuf[i] != 0x00 && codeBuf[i] != 0x90)
        {
            DWORD foundOEP = codeRVA + static_cast<DWORD>(i);
            Logger::Log("[*] Fallback: Using first code block as OEP RVA: " + ToHex((uintptr_t)foundOEP));
            return foundOEP;
        }
    }

    return codeRVA;
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

    BOOL isTargetWow64 = FALSE;
    IsWow64Process(pi.hProcess, &isTargetWow64);
    Logger::Log(Utils::Format("[DEBUG] isTargetWow64=%d, PebBaseAddress=0x%p, ImageBase=0x%p",
                              isTargetWow64, pbi.PebBaseAddress, imageBase),
                LogLevel::INFO);

    BYTE headers[0x1000] = {};
    ReadProcessMemory(pi.hProcess, imageBase, headers, sizeof(headers), nullptr);

    auto *dos = (IMAGE_DOS_HEADER *)headers;
    auto *nt_generic = (IMAGE_NT_HEADERS32 *)((BYTE *)headers + dos->e_lfanew);

    Logger::Log(Utils::Format("[DEBUG] DOS e_magic=0x%04X, e_lfanew=0x%X, NT Signature=0x%08X, Magic=0x%04X",
                              dos->e_magic, dos->e_lfanew, nt_generic->Signature, nt_generic->OptionalHeader.Magic),
                LogLevel::INFO);

    // Patch PEB Anti-Debug Flags
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

    // Dynamic code section discovery via stub section exclusion
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt_generic);
    DWORD codeRVA = 0x1000;
    DWORD codeSize = 0;
    std::string codeSectionName = ".text";

    // 1. Dynamically locate the protector stub section (the section owning the OEP RVA)
    const IMAGE_SECTION_HEADER *stubSection = nullptr;
    for (int i = 0; i < numberOfSections; ++i)
    {
        DWORD secStart = secs[i].VirtualAddress;
        DWORD secSize = secs[i].Misc.VirtualSize ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
        if (oepRVA >= secStart && oepRVA < secStart + secSize)
        {
            stubSection = &secs[i];
            char stubName[9] = {};
            memcpy(stubName, secs[i].Name, 8);
            Logger::Log("[*] Identified protector stub section dynamically: " + std::string(stubName) +
                            " (RVA: " + ToHex((uintptr_t)secStart) + ")",
                        LogLevel::INFO);
            break;
        }
    }

    // 2. Select the main application payload code section (executable section distinct from the stub)
    for (int i = 0; i < numberOfSections; ++i)
    {
        // Skip the protector stub section
        if (&secs[i] == stubSection)
            continue;

        char name[9] = {};
        memcpy(name, secs[i].Name, 8);
        std::string sName(name);

        bool isExecutableCode = (secs[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                                (secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                                (sName == "CODE" || sName == ".text");

        if (isExecutableCode)
        {
            codeRVA = secs[i].VirtualAddress;
            codeSize = secs[i].Misc.VirtualSize ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
            codeSectionName = sName;
            break;
        }
    }

    Logger::Log("[+] ImageBase: " + ToHex((uintptr_t)imageBase));
    Logger::Log("[+] Stub OEP RVA: " + ToHex((uintptr_t)oepRVA));
    Logger::Log("[+] Target Code Section (" + codeSectionName + ") RVA: " + ToHex((uintptr_t)codeRVA));

    ResumeThread(pi.hThread);
    Logger::Log("[+] Process resumed - polling code section for VMP stub writes (max 30s)...");

    bool dumpDone = false;
    const int MAX_POLLS = 3000;

    for (int poll = 0; poll < MAX_POLLS; ++poll)
    {
        Sleep(10);

        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        bool dead = (exitCode != STILL_ACTIVE);

        if (TextSectionPopulated(pi.hProcess, imageBase, codeRVA, 256))
        {
            Logger::Log("[+] Code section populated after ~" + std::to_string(poll * 10) + "ms");

            // --- DIAGNOSTIC: confirm whether the section is still being written to ---
            {
                std::vector<BYTE> snap1(std::min<DWORD>(codeSize ? codeSize : 0x10000, 0x10000));
                ReadProcessMemory(pi.hProcess, (BYTE *)imageBase + codeRVA, snap1.data(), snap1.size(), nullptr);
                Sleep(300);
                std::vector<BYTE> snap2(snap1.size());
                ReadProcessMemory(pi.hProcess, (BYTE *)imageBase + codeRVA, snap2.data(), snap2.size(), nullptr);
                bool stable = (snap1 == snap2);
                Logger::Log(Utils::Format("[DEBUG] Code section stability check: %s after extra 300ms",
                                          stable ? "STABLE (no change)" : "STILL CHANGING"),
                            LogLevel::WARNING);
            }
            // --- END DIAGNOSTIC ---

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
                    auto *nt_generic2 = (IMAGE_NT_HEADERS32 *)((BYTE *)hdrBuf + dos2->e_lfanew);
                    if (nt_generic2->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    {
                        auto *nt32 = (IMAGE_NT_HEADERS32 *)nt_generic2;
                        if (nt32->OptionalHeader.SizeOfImage > 0)
                            finalSize = nt32->OptionalHeader.SizeOfImage;
                    }
                    else if (nt_generic2->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        auto *nt64 = (IMAGE_NT_HEADERS64 *)nt_generic2;
                        if (nt64->OptionalHeader.SizeOfImage > 0)
                            finalSize = nt64->OptionalHeader.SizeOfImage;
                    }
                }
            }

            dumpDone = DumpProcessImage(pi.hProcess, imageBase, finalSize, "unpacked_dump.bin");

            Logger::Log(Utils::Format("[DEBUG] Dump complete: dumpDone=%d, finalSize=%zu, realOEP RVA=0x%08X",
                                      dumpDone, finalSize, realOEP),
                        LogLevel::INFO);

            // Scan process memory for real OEP
            realOEP = FindRealOEP(pi.hProcess, imageBase, codeRVA, codeSize, (capstoneMode == CS_MODE_64));

            if (!dead)
                TerminateProcess(pi.hProcess, 0);
            break;
        }

        if (dead)
        {
            Logger::Log("[!] Process exited (" + ToHex((uintptr_t)exitCode) +
                        ") before code section was populated — VMP killed itself pre-initialization.");
            dumpDone = DumpProcessImage(pi.hProcess, imageBase, imgSize, "unpacked_dump.bin");

            break;
        }
    }

    if (!dumpDone && !TextSectionPopulated(pi.hProcess, imageBase, codeRVA, 32))
        Logger::Log("[-] Poll timed out or code section never populated.", LogLevel::Error);

    // Disassemble OEP from live/terminated process for diagnostics
    processHandle = pi.hProcess;
    LPVOID realOEP_VA = (BYTE *)imageBase + (realOEP ? realOEP : oepRVA);
    Disassemble(realOEP_VA, 0x40, capstoneMode);

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
