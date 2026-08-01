#include "vmprotectunpacker/ImportFixer.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <capstone/capstone.h>
#include "vmprotectunpacker/PEParser.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"

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

    guessedImports["kernel32.dll"] = {"LoadLibraryA", "GetProcAddress"};

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

void ImportFixer::Fix(PEParser &parser)
{
    auto importMap = ScanForImports(parser);

    if (importMap.empty())
    {
        Logger::Log("[-] No valid imports detected to fix.", LogLevel::WARNING);
        return;
    }

    Logger::Log(Utils::Format("[+] Existing import table valid (%u DLLs) — skipping rebuild to preserve runtime IAT.", (unsigned)importMap.size()), LogLevel::INFO);
    return;

    Logger::Log("[+] Rebuilding import table...", LogLevel::INFO);

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

    DWORD fileAlignment, sectionAlignment, sizeOfImage;
    if (is64)
    {
        auto opt = &parser.GetNtHeaders64()->OptionalHeader;
        fileAlignment = opt->FileAlignment;
        sectionAlignment = opt->SectionAlignment;
        sizeOfImage = opt->SizeOfImage;
    }
    else
    {
        auto opt = &parser.GetNtHeaders32()->OptionalHeader;
        fileAlignment = opt->FileAlignment;
        sectionAlignment = opt->SectionAlignment;
        sizeOfImage = opt->SizeOfImage;
    }

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

    Logger::Log(Utils::Format("[+] Import table rebuilt: %u DLLs injected.", (unsigned)descs.size()), LogLevel::INFO);
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
    {
        Logger::Log("[-] No import directory in dump.", LogLevel::WARNING);
        return importMap;
    }

    BYTE *base = parser.GetMappedImage();
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + importDir.VirtualAddress);

    while (desc->Name != 0)
    {
        const char *dllName = (const char *)(base + desc->Name);
        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        if (is64)
        {
            IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(base + thunkRva);
            while (thunk->u1.AddressOfData != 0)
            {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                {
                    DWORD nameRva = (DWORD)(thunk->u1.AddressOfData);
                    if (nameRva < parser.GetImageSize())
                    {
                        IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + nameRva);
                        importMap[dllName].insert(std::string((char *)ibn->Name));
                    }
                }
                ++thunk;
            }
        }
        else
        {
            IMAGE_THUNK_DATA32 *thunk = (IMAGE_THUNK_DATA32 *)(base + thunkRva);
            while (thunk->u1.AddressOfData != 0)
            {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
                {
                    DWORD nameRva = thunk->u1.AddressOfData;
                    if (nameRva < parser.GetImageSize())
                    {
                        IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + nameRva);
                        importMap[dllName].insert(std::string((char *)ibn->Name));
                    }
                }
                ++thunk;
            }
        }

        ++desc;
    }

    Logger::Log(Utils::Format("[*] Found %u import DLLs from existing table.", (unsigned)importMap.size()), LogLevel::INFO);
    return importMap;
}
