#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include "vmprotectunpacker/Peparser.h"

class ImportFixer {
public:
    ImportFixer(const std::string& dumpedExePath);

    bool FixImports();
    bool SaveFixedBinary(const std::string& outputPath);
    static void Fix(PEParser& parser);

private:
    std::string dumpedPath;
    std::vector<BYTE> binary;

    #define ALIGN(val, align) (((val) + ((align)-1)) & ~((align)-1))

    bool LoadBinary();
    bool RebuildImportTable();
    static std::map<std::string, std::set<std::string>> ScanForImports(PEParser& parser);
    static std::pair<std::string, std::string> ResolveVirtualAddressToAPI(uintptr_t va);
    DWORD RVAToOffset(DWORD rva);

    std::map<std::string, std::vector<std::string>> guessedImports;
};