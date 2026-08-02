#include "vmprotectunpacker/PEParser.h"
#include <iostream>
#include <fstream>
#include "vmprotectunpacker/Logger.h"
#include <winternl.h>

PEParser::PEParser() : filePath(""), hFile(NULL), hMapping(NULL), mappedImage(nullptr), imageSize(0) {}

PEParser::~PEParser()
{
    if (mappedImage)
        delete[] mappedImage;
    if (hMapping)
        CloseHandle(hMapping);
    if (hFile)
        CloseHandle(hFile);
}

bool PEParser::Load(const std::string &filepath)
{
    filePath = filepath;

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    std::string cmdLine = "\"" + filepath + "\"";

    if (!CreateProcessA(
            filePath.c_str(),
            NULL,
            NULL, NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi))
    {
        Logger::Log("[-] Failed to create process in suspended mode.", LogLevel::Error);
        return false;
    }

    // Save the handle
    HANDLE hProcess = pi.hProcess;

    typedef NTSTATUS(NTAPI * pfnNtQueryInformationProcess)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    pfnNtQueryInformationProcess NtQueryInformationProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess)
    {
        Logger::Log("[-] Failed to resolve NtQueryInformationProcess.", LogLevel::Error);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen);

    if (!NT_SUCCESS(status))
    {
        Logger::Log("[-] NtQueryInformationProcess failed.", LogLevel::Error);
        return false;
    }

    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID imageBaseAddr = nullptr;
    SIZE_T bytesRead = 0;

    // Detect target WoW64 status (32-bit process on 64-bit Windows)
    BOOL isWow64 = FALSE;
    IsWow64Process(pi.hProcess, &isWow64);

    // Offset of ImageBaseAddress in 32-bit PEB is 0x08; in 64-bit PEB it is 0x10
    DWORD imageBaseOffset = isWow64 ? 0x08 : 0x10;

    if (isWow64) {
        DWORD imageBase32 = 0;
        if (!ReadProcessMemory(pi.hProcess, (BYTE *)pebAddress + imageBaseOffset, &imageBase32, sizeof(imageBase32), &bytesRead)) {
            Logger::Log("[-] Failed to read 32-bit ImageBaseAddress from PEB.", LogLevel::Error);
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        imageBaseAddr = reinterpret_cast<PVOID>(static_cast<uintptr_t>(imageBase32));
    } else {
        if (!ReadProcessMemory(pi.hProcess, (BYTE *)pebAddress + imageBaseOffset, &imageBaseAddr, sizeof(imageBaseAddr), &bytesRead)) {
            Logger::Log("[-] Failed to read 64-bit ImageBaseAddress from PEB.", LogLevel::Error);
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
    }

    BYTE dosHeader[0x1000] = {};
    if (!ReadProcessMemory(pi.hProcess, imageBaseAddr, dosHeader, sizeof(dosHeader), &bytesRead))
    {
        Logger::Log("[-] Failed to read DOS header.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)dosHeader;
    BYTE ntHeaderBuf[sizeof(IMAGE_NT_HEADERS64)] = {};
    if (!ReadProcessMemory(pi.hProcess, (BYTE *)imageBaseAddr + idh->e_lfanew, ntHeaderBuf, sizeof(ntHeaderBuf), &bytesRead))
    {
        Logger::Log("[-] Failed to read NT headers.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    WORD optMagic = *reinterpret_cast<WORD *>(ntHeaderBuf + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    SIZE_T imageSize = 0;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        imageSize = ((PIMAGE_NT_HEADERS64)ntHeaderBuf)->OptionalHeader.SizeOfImage;
    else
        imageSize = ((PIMAGE_NT_HEADERS32)ntHeaderBuf)->OptionalHeader.SizeOfImage;
    mappedImage = new BYTE[imageSize];

    if (!ReadProcessMemory(pi.hProcess, imageBaseAddr, mappedImage, imageSize, &bytesRead))
    {
        Logger::Log("[-] Failed to read full image from target process.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        delete[] mappedImage;
        return false;
    }

    this->imageSize = imageSize;
    this->isSuspendedDump = true;

    Logger::Log("[+] Dumped process memory from suspended process.", LogLevel::INFO);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true;
}

bool PEParser::LoadF(const std::string &filepath, bool isMemoryLayout)
{
    filePath = filepath;

    hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        Logger::Log("[-] Failed to open file: " + filepath, LogLevel::Error);
        return false;
    }

    WORD signature = 0;
    DWORD bytesRead = 0;
    BOOL readOk = ReadFile(hFile, &signature, sizeof(WORD), &bytesRead, NULL);

    if (!readOk || signature != IMAGE_DOS_SIGNATURE)
    {
        Logger::Log("[-] File is not a valid PE (missing MZ header): " + filepath, LogLevel::Error);
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    imageSize = GetFileSize(hFile, NULL);
    if (imageSize == INVALID_FILE_SIZE || imageSize == 0)
    {
        Logger::Log("[-] Failed to get file size.", LogLevel::Error);
        CloseHandle(hFile);
        return false;
    }

    // Read into a heap buffer so callers can modify headers in-place.
    mappedImage = new BYTE[imageSize];
    DWORD bytesRead2 = 0;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, mappedImage, (DWORD)imageSize, &bytesRead2, NULL) || bytesRead2 != imageSize)
    {
        Logger::Log("[-] Failed to read file into buffer.", LogLevel::Error);
        delete[] mappedImage;
        mappedImage = nullptr;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    hFile = NULL;

    this->isSuspendedDump = isMemoryLayout;

    Logger::Log("[+] Successfully loaded PE file: " + filepath, LogLevel::INFO);

    return true;
}

BYTE *PEParser::GetMappedImage()
{
    return mappedImage;
}

size_t PEParser::GetImageSize()
{
    return imageSize;
}

PIMAGE_NT_HEADERS PEParser::GetNtHeadersRaw()
{
    if (!mappedImage)
        return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mappedImage;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return nt;
}

bool PEParser::IsPE64() const
{
    if (!mappedImage)
        return false;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mappedImage;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    return nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

PIMAGE_NT_HEADERS32 PEParser::GetNtHeaders32()
{
    PIMAGE_NT_HEADERS nt = GetNtHeadersRaw();
    return (nt && !IsPE64()) ? (PIMAGE_NT_HEADERS32)nt : nullptr;
}

PIMAGE_NT_HEADERS64 PEParser::GetNtHeaders64()
{
    PIMAGE_NT_HEADERS nt = GetNtHeadersRaw();
    return (nt && IsPE64()) ? (PIMAGE_NT_HEADERS64)nt : nullptr;
}

PIMAGE_SECTION_HEADER PEParser::GetSectionHeader(const std::string &name)
{
    PIMAGE_NT_HEADERS nt = GetNtHeadersRaw();
    if (!nt)
        return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (std::string((char *)section->Name, strnlen((char *)section->Name, 8)) == name)
            return section;
    }

    return nullptr;
}

std::vector<IMAGE_SECTION_HEADER> PEParser::GetAllSectionHeaders()
{
    std::vector<IMAGE_SECTION_HEADER> sections;

    IMAGE_NT_HEADERS *ntHeaders = GetNtHeadersRaw();
    if (!ntHeaders)
        return sections;

    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        sections.push_back(section[i]);
    }

    return sections;
}

std::string PEParser::SectionName(const IMAGE_SECTION_HEADER *section) const
{
    if (!section)
        return "";

    char name[9] = {0};
    memcpy(name, section->Name, 8);

    return std::string(name);
}

bool PEParser::ReplaceImage(BYTE *newData, size_t newSize)
{

    if (mappedImage)
    {
        delete[] mappedImage;
        mappedImage = nullptr;
    }

    if (hMapping)
    {
        CloseHandle(hMapping);
        hMapping = nullptr;
    }

    if (hFile)
    {
        CloseHandle(hFile);
        hFile = nullptr;
    }

    mappedImage = new BYTE[newSize];
    if (!mappedImage)
        return false;

    memcpy(mappedImage, newData, newSize);
    imageSize = newSize;

    hFile = nullptr;
    hMapping = nullptr;

    return true;
}

BYTE *PEParser::RvaToVa(DWORD rva)
{
    PIMAGE_NT_HEADERS nt = GetNtHeadersRaw();
    if (!nt)
        return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        DWORD sectionStart = section->VirtualAddress;
        DWORD sectionEnd = sectionStart + max(section->Misc.VirtualSize, section->SizeOfRawData);

        if (rva >= sectionStart && rva < sectionEnd)
        {
            DWORD offset = rva - section->VirtualAddress;
            DWORD base;
            if (isSuspendedDump)
                base = section->VirtualAddress; // memory-dump: offset == RVA
            else
                base = section->PointerToRawData ? section->PointerToRawData : section->VirtualAddress;
            return mappedImage + base + offset;
        }
    }

    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return mappedImage + rva;

    return nullptr;
}

std::pair<std::string, std::string> PEParser::ResolveIAT(uint64_t addr)
{
    bool is64 = IsPE64();
    IMAGE_DATA_DIRECTORY importDir;
    ULONGLONG imageBase;

    if (is64)
    {
        PIMAGE_NT_HEADERS64 nt = GetNtHeaders64();
        if (!nt)
            return {"", ""};
        importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageBase = nt->OptionalHeader.ImageBase;
    }
    else
    {
        PIMAGE_NT_HEADERS32 nt = GetNtHeaders32();
        if (!nt)
            return {"", ""};
        importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageBase = nt->OptionalHeader.ImageBase;
    }

    if (importDir.VirtualAddress == 0 || importDir.Size == 0)
        return {"", ""};

    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)RvaToVa(importDir.VirtualAddress);
    if (!importDesc)
        return {"", ""};

    while (importDesc->Name)
    {
        const char *dllName = (const char *)RvaToVa(importDesc->Name);

        if (is64)
        {
            IMAGE_THUNK_DATA64 *origThunk = (IMAGE_THUNK_DATA64 *)RvaToVa(importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)RvaToVa(importDesc->FirstThunk);
            if (!thunk)
            {
                importDesc++;
                continue;
            }

            for (; origThunk && thunk && origThunk->u1.AddressOfData; ++origThunk, ++thunk)
            {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    continue;
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)RvaToVa((DWORD)origThunk->u1.AddressOfData);
                if (!ibn)
                    continue;
                uint64_t iatAddress = imageBase + thunk->u1.Function;
                if (iatAddress == addr)
                    return {std::string(dllName), std::string((char *)ibn->Name)};
            }
        }
        else
        {
            IMAGE_THUNK_DATA32 *origThunk = (IMAGE_THUNK_DATA32 *)RvaToVa(importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA32 *thunk = (IMAGE_THUNK_DATA32 *)RvaToVa(importDesc->FirstThunk);
            if (!thunk)
            {
                importDesc++;
                continue;
            }

            for (; origThunk && thunk && origThunk->u1.AddressOfData; ++origThunk, ++thunk)
            {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    continue;
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)RvaToVa(origThunk->u1.AddressOfData);
                if (!ibn)
                    continue;
                uint64_t iatAddress = imageBase + thunk->u1.Function;
                if (iatAddress == addr)
                    return {std::string(dllName), std::string((char *)ibn->Name)};
            }
        }

        importDesc++;
    }

    return {"", ""};
}

std::string &PEParser::GetFilePath()
{
    return filePath;
}

void PEParser::SetFilePath(std::string &outPath)
{
    filePath = outPath;
    Load(filePath);
}

bool PEParser::Save(const std::string &outputPath) const
{
    if (!mappedImage || imageSize == 0)
    {
        return false;
    }

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile)
    {
        return false;
    }

    outFile.write(reinterpret_cast<const char *>(mappedImage), imageSize);
    return outFile.good();
}

DWORD PEParser::GetOEP()
{
    DWORD addressofentrypoint = GetNtHeadersRaw()->OptionalHeader.AddressOfEntryPoint;
    return (!addressofentrypoint) ? 0 : addressofentrypoint;
}

ULONGLONG PEParser::GetImageBase()
{
    if (IsPE64())
    {
        PIMAGE_NT_HEADERS64 nt64 = GetNtHeaders64();
        return nt64 ? nt64->OptionalHeader.ImageBase : 0;
    }
    else
    {
        PIMAGE_NT_HEADERS32 nt32 = GetNtHeaders32();
        return nt32 ? nt32->OptionalHeader.ImageBase : 0;
    }
}

PIMAGE_SECTION_HEADER PEParser::GetSectionContainingRVA(DWORD rva)
{
    PIMAGE_NT_HEADERS nt = GetNtHeadersRaw();
    if (!nt)
        return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        DWORD start = section->VirtualAddress;
        DWORD end = start + max(section->Misc.VirtualSize, section->SizeOfRawData);
        if (rva >= start && rva < end)
        {
            return section;
        }
    }
    return nullptr;
}
