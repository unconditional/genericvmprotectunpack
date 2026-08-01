#pragma once
#include <windows.h>
#include <string>
#include <vector>

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool Load(const std::string& filepath);
    bool LoadF(const std::string &filepath, bool isMemoryLayout = false);
    BYTE* GetMappedImage();
    size_t GetImageSize();
    bool IsPE64() const;                      // true = PE32+ (64-bit), false = PE32
    PIMAGE_NT_HEADERS32 GetNtHeaders32();      // valid only if !IsPE64()
    PIMAGE_NT_HEADERS64 GetNtHeaders64();      // valid only if IsPE64()
    PIMAGE_NT_HEADERS   GetNtHeadersRaw();     // untyped, only for Signature/FileHeader access
    ULONGLONG GetImageBase();                  // widen return type (was DWORD)
    PIMAGE_SECTION_HEADER GetSectionHeader(const std::string& name);
    std::vector<IMAGE_SECTION_HEADER> GetAllSectionHeaders();
    std::string SectionName(const IMAGE_SECTION_HEADER* section) const;
    bool ReplaceImage(BYTE* newData, size_t newSize);
    BYTE* RvaToVa(DWORD rva);
    std::pair<std::string, std::string> ResolveIAT(uint64_t addr);
    std::string& GetFilePath();
    bool Save(const std::string& outputPath) const;
    DWORD GetOEP();
    void SetFilePath(std::string& outPath);
    bool IsSuspendedDump() const { return isSuspendedDump; }
    PIMAGE_SECTION_HEADER GetSectionContainingRVA(DWORD rva);

private:
    std::string filePath;
    HANDLE hFile;
    HANDLE hMapping;
    BYTE* mappedImage;
    size_t imageSize;
    bool isSuspendedDump = false;
};
