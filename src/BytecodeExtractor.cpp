#include "vmprotectunpacker/BytecodeExtractor.h"
#include <fstream>
#include <iostream>
#include <capstone/capstone.h>
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"


BytecodeExtractor::BytecodeExtractor(PEParser* parser)
    : parser(parser) {}

bool BytecodeExtractor::ExtractVMBytecode() {
    auto sections = parser->GetAllSectionHeaders();
    BYTE* base = parser->GetMappedImage();
    DWORD oepRva = parser->GetOEP();

    if (oepRva != 0) {
        for (auto& sec : sections) {
            bool isExec = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            if (!isExec) continue;

            DWORD secEnd = sec.VirtualAddress + max(sec.Misc.VirtualSize, sec.SizeOfRawData);
            if (oepRva >= sec.VirtualAddress && oepRva < secEnd) {
                DWORD dataSize   = sec.SizeOfRawData ? sec.SizeOfRawData : sec.Misc.VirtualSize;
                DWORD dataOffset = sec.SizeOfRawData ? sec.PointerToRawData : sec.VirtualAddress;
                std::string secName = parser->SectionName(&sec);
                Logger::Log(Utils::Format("[+] OEP section identified as VMP region: %s (size: %u)", secName.c_str(), dataSize), LogLevel::INFO);
                extractedBytecode.assign(base + dataOffset, base + dataOffset + dataSize);
                return true;
            }
        }
    }
    for (auto& sec : sections) {
        std::string secName = parser->SectionName(&sec);

        DWORD dataSize   = sec.SizeOfRawData ? sec.SizeOfRawData : sec.Misc.VirtualSize;
        DWORD dataOffset = sec.SizeOfRawData ? sec.PointerToRawData : sec.VirtualAddress;

        if (dataSize == 0) {
            Logger::Log(Utils::Format("[!] Skipping section %s: no data", secName.c_str()), LogLevel::WARNING);
            continue;
        }

        BYTE* data = base + dataOffset;
        Logger::Log(Utils::Format("[+] Checking section: %s, size: %u", secName.c_str(), dataSize), LogLevel::DEBUG);

        if (IsLikelyVMBytecode(data, dataSize)) {
            extractedBytecode.assign(data, data + dataSize);
            Logger::Log(Utils::Format("[+] Extracted suspicious VM bytecode from: %s", secName.c_str()), LogLevel::INFO);
            return true;
        }
    }

    Logger::Log("[-] No candidate section matched VM bytecode heuristics.", LogLevel::Error);
    return false;
}



const std::vector<BYTE>& BytecodeExtractor::GetExtractedBytecode() const {
    return extractedBytecode;
}

bool BytecodeExtractor::SaveBytecodeToFile(const std::string& outputPath) {
    std::ofstream ofs(outputPath, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(extractedBytecode.data()), extractedBytecode.size());
    return true;
}

bool BytecodeExtractor::FindVMProtectSection(std::string& sectionName) {
    static const std::vector<std::string> vmpSections = {
        ".vmp0", ".vmp1", ".vmp2", ".themida", ".secure"
    };

    for (const auto& name : vmpSections) {
        if (parser->GetSectionHeader(name)) {
            sectionName = name;
            return true;
        }
    }
    return false;
}

bool BytecodeExtractor::IsLikelyVMBytecode(BYTE* data, DWORD size) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    count = cs_disasm(handle, data, size, 0x0, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        Logger::Log("[-] Failed to disassemble bytecode as count is zero = suspicious: " + std::string(cs_strerror(cs_errno(handle))), LogLevel::Error);
        return true; // Failed to decode = suspicious
    }

    size_t invalidCount = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == X86_INS_INVALID)
            invalidCount++;
    }
    double ratio = (double)invalidCount / count;

    cs_free(insn, count);
    cs_close(&handle);

    return ratio > 0.3; // Arbitrary threshold
}

bool BytecodeExtractor::IsRWX(const IMAGE_SECTION_HEADER* section) {
    DWORD characteristics = section->Characteristics;

    bool isReadable  = (characteristics & IMAGE_SCN_MEM_READ)    != 0;
    bool isWritable  = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
    bool isExecutable= (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    return isReadable && isWritable && isExecutable;
}
bool BytecodeExtractor::IsExecutableSection(const IMAGE_SECTION_HEADER* section) {
    return (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}