#pragma once
#include <windows.h>
#include <string>
#include <vector>

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool Load(const std::string& filepath);
    BYTE* GetMappedImage();
    size_t GetImageSize();
    bool IsPE64() const;                      // true = PE32+ (64-bit), false = PE32
    PIMAGE_NT_HEADERS32 GetNtHeaders32();      // valid only if !IsPE64()
    PIMAGE_NT_HEADERS64 GetNtHeaders64();      // valid only if IsPE64()
    PIMAGE_NT_HEADERS   GetNtHeadersRaw();     // untyped, only for Signature/FileHeader access
    ULONGLONG GetImageBase();                  // widen return type (was DWORD)
    PIMAGE_SECTION_HEADER GetSectionHeader(const std::string& name);
    std::vector<IMAGE_SECTION_HEADER> GetAllSectionHeaders();
    // Returns the name of a given IMAGE_SECTION_HEADER
    std::string SectionName(const IMAGE_SECTION_HEADER* section) const;
    bool PEParser::ReplaceImage(BYTE* newData, size_t newSize);
    BYTE* PEParser::RvaToVa(DWORD rva);
    std::pair<std::string, std::string> PEParser::ResolveIAT(uint64_t addr);
    std::string& PEParser::GetFilePath();
    bool Save(const std::string& outputPath) const;
    bool PEParser::LoadF(const std::string& filepath);
    DWORD GetOEP();
    void PEParser::SetFilePath(std::string& outPath);
    bool IsSuspendedDump() const { return isSuspendedDump; }

private:
    std::string filePath;
    HANDLE hFile;
    HANDLE hMapping;
    BYTE* mappedImage;
    size_t imageSize;
    bool isSuspendedDump = false;
};
