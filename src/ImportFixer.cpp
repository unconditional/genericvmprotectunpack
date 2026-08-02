#include "vmprotectunpacker/ImportFixer.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <Psapi.h>
#include "vmprotectunpacker/PEParser.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"

#pragma comment(lib, "Psapi.lib")

ImportFixer::ImportFixer(const std::string &dumpedExePath)
    : dumpedPath(dumpedExePath) {}

bool ImportFixer::LoadBinary()
{
    std::ifstream file(dumpedPath, std::ios::binary);
    if (!file)
        return false;

    binary = std::vector<BYTE>(std::istreambuf_iterator<char>(file), {});
    return true;
}

bool ImportFixer::FixImports()
{
    if (!LoadBinary())
        return false;
    Logger::Log("[*] Loaded dumped binary. Fixing imports...");
    return RebuildImportTable();
}

bool ImportFixer::RebuildImportTable()
{
    Logger::Log("[*] Rebuilding Import Table...");
    return true;
}

bool ImportFixer::SaveFixedBinary(const std::string &outputPath)
{
    std::ofstream out(outputPath, std::ios::binary);
    if (!out)
        return false;

    out.write(reinterpret_cast<const char *>(binary.data()), binary.size());
    return true;
}

DWORD ImportFixer::RVAToOffset(DWORD rva)
{
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(binary.data());
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(binary.data() + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        DWORD sectionStartRVA = section->VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + section->Misc.VirtualSize;
        if (rva >= sectionStartRVA && rva < sectionEndRVA)
        {
            return rva - sectionStartRVA + section->PointerToRawData;
        }
    }
    return 0;
}

std::pair<std::string, std::string> ImportFixer::ResolveVirtualAddressToAPI(uintptr_t va)
{
    if (va == 0)
        return {"", ""};

    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            MODULEINFO modInfo = {0};
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            {
                uintptr_t modBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                uintptr_t modEnd = modBase + modInfo.SizeOfImage;

                if (va >= modBase && va < modEnd)
                {
                    char modName[MAX_PATH] = {0};
                    if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName)))
                    {
                        std::string dllName = modName;
                        size_t lastSlash = dllName.find_last_of("\\/");
                        if (lastSlash != std::string::npos)
                            dllName = dllName.substr(lastSlash + 1);

                        // Parse Export Directory of the DLL in memory
                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modBase;
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                        {
                            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(modBase + dos->e_lfanew);
                            DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

                            if (exportRVA != 0)
                            {
                                PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(modBase + exportRVA);
                                DWORD *functions = (DWORD *)(modBase + exports->AddressOfFunctions);
                                DWORD *names = (DWORD *)(modBase + exports->AddressOfNames);
                                WORD *ordinals = (WORD *)(modBase + exports->AddressOfNameOrdinals);

                                for (DWORD j = 0; j < exports->NumberOfNames; j++)
                                {
                                    uintptr_t funcVA = modBase + functions[ordinals[j]];
                                    if (funcVA == va)
                                    {
                                        const char *funcName = (const char *)(modBase + names[j]);
                                        return {dllName, std::string(funcName)};
                                    }
                                }
                            }
                        }
                        return {dllName, ""};
                    }
                }
            }
        }
    }
    return {"", ""};
}

std::map<std::string, std::set<std::string>> ImportFixer::ScanForImports(PEParser &parser)
{
    std::map<std::string, std::set<std::string>> importMap;
    PIMAGE_NT_HEADERS nt = parser.GetNtHeadersRaw();
    if (!nt)
        return importMap;

    bool is64 = parser.IsPE64();
    IMAGE_DATA_DIRECTORY importDir;
    if (is64)
        importDir = parser.GetNtHeaders64()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    else
        importDir = parser.GetNtHeaders32()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress == 0 || importDir.Size == 0)
        return importMap;

    BYTE *base = parser.GetMappedImage();
    size_t imgSize = parser.GetImageSize();

    if (importDir.VirtualAddress >= imgSize)
        return importMap;

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + importDir.VirtualAddress);

    while (desc->Name != 0 && desc->Name < imgSize)
    {
        const char *dllName = (const char *)(base + desc->Name);

        // Prefer OriginalFirstThunk (INT), fall back to FirstThunk (IAT)
        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        if (thunkRva != 0 && thunkRva < imgSize)
        {
            if (is64)
            {
                IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(base + thunkRva);
                while (thunk && thunk->u1.AddressOfData != 0)
                {
                    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    {
                        WORD ord = (WORD)(thunk->u1.Ordinal & 0xFFFF);
                        importMap[dllName].insert("Ordinal#" + std::to_string(ord));
                    }
                    else
                    {
                        DWORD nameRva = static_cast<DWORD>(thunk->u1.AddressOfData);
                        if (nameRva < imgSize)
                        {
                            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + nameRva);
                            if ((BYTE *)ibn->Name < base + imgSize)
                            {
                                importMap[dllName].insert(std::string((char *)ibn->Name));
                            }
                        }
                        else
                        {
                            uintptr_t va = static_cast<uintptr_t>(thunk->u1.Function);
                            auto res = ResolveVirtualAddressToAPI(va);
                            if (!res.first.empty())
                            {
                                std::string funcName = res.second.empty() ? "UnknownAPI" : res.second;
                                importMap[res.first].insert(funcName);
                            }
                        }
                    }
                    ++thunk;
                }
            }
            else
            {
                IMAGE_THUNK_DATA32 *thunk = (IMAGE_THUNK_DATA32 *)(base + thunkRva);
                while (thunk && thunk->u1.AddressOfData != 0)
                {
                    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    {
                        WORD ord = (WORD)(thunk->u1.Ordinal & 0xFFFF);
                        importMap[dllName].insert("Ordinal#" + std::to_string(ord));
                    }
                    else
                    {
                        DWORD nameRva = thunk->u1.AddressOfData;
                        if (nameRva < imgSize)
                        {
                            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + nameRva);
                            if ((BYTE *)ibn->Name < base + imgSize)
                            {
                                importMap[dllName].insert(std::string((char *)ibn->Name));
                            }
                        }
                        else
                        {
                            uintptr_t va = static_cast<uintptr_t>(thunk->u1.Function);
                            auto res = ResolveVirtualAddressToAPI(va);
                            if (!res.first.empty())
                            {
                                std::string funcName = res.second.empty() ? "UnknownAPI" : res.second;
                                importMap[res.first].insert(funcName);
                            }
                        }
                    }
                    ++thunk;
                }
            }
        }
        ++desc;
    }

    Logger::Log(Utils::Format("[*] Found %u import DLLs during import table scan.", (unsigned)importMap.size()), LogLevel::INFO);
    return importMap;
}

void ImportFixer::Fix(PEParser &parser)
{
    auto importMap = ScanForImports(parser);

    if (importMap.empty())
    {
        Logger::Log("[-] No valid imports resolved.", LogLevel::WARNING);
        return;
    }

    Logger::Log("[+] Rebuilding import table (.idata)...", LogLevel::INFO);

    BYTE *image = parser.GetMappedImage();
    size_t imageSize = parser.GetImageSize();
    PIMAGE_NT_HEADERS nt = parser.GetNtHeadersRaw();
    bool is64 = parser.IsPE64();
    size_t thunkSize = is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    DWORD descBytes = (DWORD)(importMap.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD dataBytes = 0;
    for (auto &kv : importMap)
    {
        dataBytes += (DWORD)(kv.second.size() + 1) * (DWORD)thunkSize; // INT
        dataBytes += (DWORD)(kv.second.size() + 1) * (DWORD)thunkSize; // IAT
        for (auto &fn : kv.second)
            dataBytes += 2 + (DWORD)fn.size() + 1;
        dataBytes += (DWORD)kv.first.size() + 1;
    }

    DWORD fileAlignment = is64 ? parser.GetNtHeaders64()->OptionalHeader.FileAlignment : parser.GetNtHeaders32()->OptionalHeader.FileAlignment;
    DWORD sectionAlignment = is64 ? parser.GetNtHeaders64()->OptionalHeader.SectionAlignment : parser.GetNtHeaders32()->OptionalHeader.SectionAlignment;
    DWORD sizeOfImage = is64 ? parser.GetNtHeaders64()->OptionalHeader.SizeOfImage : parser.GetNtHeaders32()->OptionalHeader.SizeOfImage;

    DWORD idataRawSize = ALIGN(descBytes + dataBytes, fileAlignment);
    if (idataRawSize < 0x1000)
        idataRawSize = 0x1000;

    IMAGE_SECTION_HEADER newSec = {};
    strcpy_s((char *)newSec.Name, 8, ".idata");
    newSec.Misc.VirtualSize = idataRawSize;
    newSec.SizeOfRawData = idataRawSize;
    newSec.VirtualAddress = ALIGN(sizeOfImage, sectionAlignment);
    newSec.PointerToRawData = ALIGN((DWORD)imageSize, fileAlignment);
    newSec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    size_t totalSize = (size_t)newSec.PointerToRawData + newSec.SizeOfRawData;
    BYTE *extImage = new BYTE[totalSize]();
    memcpy(extImage, image, imageSize);

    BYTE *idataBase = extImage + newSec.PointerToRawData;
    DWORD idataRVA = newSec.VirtualAddress;
    DWORD writePos = descBytes;
    std::vector<IMAGE_IMPORT_DESCRIPTOR> descs;

    for (auto &kv : importMap)
    {
        const std::string &dll = kv.first;
        const auto &funcs = kv.second;

        DWORD intLocalOff = writePos;
        writePos += (DWORD)(funcs.size() + 1) * (DWORD)thunkSize;
        DWORD iatLocalOff = writePos;
        writePos += (DWORD)(funcs.size() + 1) * (DWORD)thunkSize;

        DWORD funcIdx = 0;
        for (const auto &fn : funcs)
        {
            DWORD ibnRVA = idataRVA + writePos;

            if (is64)
            {
                IMAGE_THUNK_DATA64 t = {};
                t.u1.AddressOfData = ibnRVA;
                memcpy(idataBase + intLocalOff + funcIdx * thunkSize, &t, thunkSize);
                memcpy(idataBase + iatLocalOff + funcIdx * thunkSize, &t, thunkSize);
            }
            else
            {
                IMAGE_THUNK_DATA32 t = {};
                t.u1.AddressOfData = ibnRVA;
                memcpy(idataBase + intLocalOff + funcIdx * thunkSize, &t, thunkSize);
                memcpy(idataBase + iatLocalOff + funcIdx * thunkSize, &t, thunkSize);
            }

            WORD hint = 0;
            memcpy(idataBase + writePos, &hint, 2);
            memcpy(idataBase + writePos + 2, fn.c_str(), fn.size() + 1);
            writePos += 2 + (DWORD)fn.size() + 1;
            ++funcIdx;
        }

        DWORD dllNameRVA = idataRVA + writePos;
        memcpy(idataBase + writePos, dll.c_str(), dll.size() + 1);
        writePos += (DWORD)dll.size() + 1;

        IMAGE_IMPORT_DESCRIPTOR desc = {};
        desc.OriginalFirstThunk = idataRVA + intLocalOff;
        desc.FirstThunk = idataRVA + iatLocalOff;
        desc.Name = dllNameRVA;
        descs.push_back(desc);
    }

    for (size_t i = 0; i < descs.size(); ++i)
        memcpy(idataBase + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), &descs[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));

    PIMAGE_DOS_HEADER extDos = (PIMAGE_DOS_HEADER)extImage;
    PIMAGE_NT_HEADERS extNt = (PIMAGE_NT_HEADERS)(extImage + extDos->e_lfanew);
    extNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataRVA;
    extNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descBytes + dataBytes;
    PIMAGE_SECTION_HEADER newSecPtr = IMAGE_FIRST_SECTION(extNt) + extNt->FileHeader.NumberOfSections;
    *newSecPtr = newSec;
    extNt->FileHeader.NumberOfSections++;

    if (is64)
        ((PIMAGE_NT_HEADERS64)extNt)->OptionalHeader.SizeOfImage = newSec.VirtualAddress + ALIGN(newSec.SizeOfRawData, sectionAlignment);
    else
        ((PIMAGE_NT_HEADERS32)extNt)->OptionalHeader.SizeOfImage = newSec.VirtualAddress + ALIGN(newSec.SizeOfRawData, sectionAlignment);

    parser.ReplaceImage(extImage, totalSize);
    delete[] extImage;

    Logger::Log(Utils::Format("[+] Import table rebuilt: %u DLLs injected into .idata section.", (unsigned)descs.size()), LogLevel::INFO);
}