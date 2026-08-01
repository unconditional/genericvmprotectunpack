#include "vmprotectunpacker/Devirtualizer.h"
#include "vmprotectunpacker/Logger.h"
#include <capstone/capstone.h>
#include <fstream>
#include <windows.h>
#include "vmprotectunpacker/Utils.h"



std::unordered_map<uint64_t, Devirtualizer::HandlerEntry> Devirtualizer::handlerMap;


Devirtualizer::Devirtualizer(BytecodeExtractor* extractor) : extractor(extractor) {
    bytecode = extractor->GetExtractedBytecode();
}

bool Devirtualizer::AnalyzeHandlers() {
    if (bytecode.empty()) return false;
    BuildHandlerMap();
    return true;
}

void Devirtualizer::BuildHandlerMap() {
    // Example static mapping - to be replaced with more accurate analysis
    handlerOpcodes[0x01] = "MOV";
    handlerOpcodes[0x02] = "ADD";
    handlerOpcodes[0x03] = "SUB";
    handlerOpcodes[0x04] = "XOR";
    handlerOpcodes[0x05] = "JMP";
    // Add more as discovered
}

std::string Devirtualizer::DisassembleInstruction(BYTE opcode) {
    if (handlerOpcodes.count(opcode))
        return handlerOpcodes[opcode];
    else
        return "UNKNOWN";
}

bool Devirtualizer::DevirtualizeToFile(const std::string& outPath) {
    std::ofstream out(outPath);
    if (!out.is_open()) return false;

    for (BYTE b : bytecode) {
        std::string instr = DisassembleInstruction(b);
        out << instr << "\n";
    }

    out.close();
    return true;
}

bool Devirtualizer::Devirtualize(PEParser* parser, const BYTE* region, size_t regionSize) {

    csh handle;
    cs_insn* insn;
    size_t count;
    cs_mode mode = CS_MODE_64;     // Default to 64-bit
    cs_arch arch = CS_ARCH_X86;    // Architecture is x86 for both (x86 & x64)

    // Check PE Magic Number to detect 32-bit
    // Assuming 'pNtHeaders' is the pointer to IMAGE_NT_HEADERS
    // If you only have 'pDosHeader', define pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
    
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) { // 0x10B
        mode = CS_MODE_32;
        Log("[INFO] [+] Detected 32-bit PE (CS_MODE_32)\n");
    } else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { // 0x20B
        mode = CS_MODE_64;
        Log("[INFO] [+] Detected 64-bit PE (CS_MODE_64)\n");
    } else {
        Log("[Error] [-] Unknown PE Magic: 0x%X\n", pNtHeaders->OptionalHeader.Magic);
        return false;
    }
    
    // 3. Initialize Capstone with the detected mode
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        // Print the specific error code to debug further issues
        Log("[Error] [-] Capstone init failed. Error Code: %d (Mode: %d)\n", err, mode);
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    Logger::Log("[*] Disassembling VM region for handler stubs...");

    const size_t scanSize = regionSize;  
    count = cs_disasm(handle, region, scanSize, (uint64_t)region, 0, &insn);

    if (count > 1) {
        for (size_t i = 0; i < count - 1; ++i) {
            cs_insn& movInst = insn[i];
            cs_insn& jmpInst = insn[i + 1];

            if (movInst.id == X86_INS_MOV && jmpInst.id == X86_INS_JMP &&
                movInst.detail && jmpInst.detail) {

                auto& movOps = movInst.detail->x86.operands;
                auto& jmpOps = jmpInst.detail->x86.operands;

                if (movInst.detail->x86.op_count == 2 &&
                    movOps[0].type == X86_OP_REG &&
                    movOps[1].type == X86_OP_IMM &&
                    jmpInst.detail->x86.op_count == 1 &&
                    jmpOps[0].type == X86_OP_REG &&
                    movOps[0].reg == jmpOps[0].reg) {

                    HandlerEntry entry;
                    entry.address = movInst.address;
                    entry.target = movOps[1].imm;
                    entry.vOpcode = static_cast<uint32_t>(movOps[1].imm);

                    handlerMap[entry.address] = entry;

                    Logger::Log(
                        Utils::Format("[*] Handler found: VirtualOpcode=0x%02X at 0x%p → Handler=0x%p",
                            entry.vOpcode, entry.address, entry.target),
                        LogLevel::INFO
                    );
                }
            }
        }

        cs_free(insn, count);
    }
    else {
        Logger::Log("[-] Failed to disassemble VM region.", LogLevel::Error);
        cs_close(&handle);
        return false;
    }

    cs_close(&handle);
}
