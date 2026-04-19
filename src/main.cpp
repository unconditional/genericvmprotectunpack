#include <iostream>
#include <string>
#include <sstream>
#include <cstring>

#include "vmprotectunpacker/PEParser.h"
#include "vmprotectunpacker/VMProtectDetector.h"
#include "vmprotectunpacker/BytecodeExtractor.h"
#include "vmprotectunpacker/Devirtualizer.h"
#include "vmprotectunpacker/ImportFixer.h"
#include "vmprotectunpacker/ShellcodeDumper.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"
#include "vmprotectunpacker/VMPDebugger.h"
#include "vmprotectunpacker/Analyzer.h"



int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: unpacker.exe <malware.exe>" << std::endl;
        return 1;
    }

    const char* exePath = argv[1];
    Logger::Log(Utils::Format("[*] Loading executable: %s", exePath), LogLevel::INFO);

    std::string target = argv[1];

    
    VMPDebugger debugger;
    if (!debugger.Run(target)) {
        Logger::Log("[-] Debugging failed.", LogLevel::Error);
        return 1;
    }

    
    PEParser parser;
    std::string dumpedFile = "unpacked_dump.bin";

    if (!parser.LoadF(dumpedFile)) {
        Logger::Log("[-] Failed to load dumped PE. Trying shellcode disassembly...", LogLevel::Error);

        if (!Analyzer::AnalyzeDump(dumpedFile)) {
            Logger::Log("[-] Shellcode analysis failed.", LogLevel::Error);
            return 1;
        }

        return 0; 
    }

   
    std::string reason;
    if (!VMProtectDetector::Detect(parser, reason)) {
        Logger::Log("[-] VMProtect not detected. Exiting.", LogLevel::INFO);
        return 0;
    }

    Logger::Log("[+] VMProtect detected. Extracting bytecode...", LogLevel::INFO);
    auto bytecodeRegions = BytecodeExtractor::Extract(&parser);

    if (bytecodeRegions.empty()) {
        Logger::Log("[-] Failed to extract VMProtect bytecode.", LogLevel::Error);
        return 1;
    }

    Logger::Log("[+] Bytecode extracted. Devirtualizing...", LogLevel::INFO);
    Devirtualizer::Devirtualize(&parser, bytecodeRegions.data(), bytecodeRegions.size());

    Logger::Log("[+] Devirtualization complete. Fixing imports...", LogLevel::INFO);
    ImportFixer::Fix(parser);

    Logger::Log("[+] Dumping decrypted shellcode (if any)...", LogLevel::INFO);
    ShellcodeDumper shellCodeDump(parser.GetFilePath());
    shellCodeDump.Dump(parser);

    std::string output = "unpacked_";
    output += std::string(strrchr(exePath, '\\') ? strrchr(exePath, '\\') + 1 : exePath);

    {
        PIMAGE_NT_HEADERS nt = parser.GetNtHeaders();
        if (nt) {
            ULONGLONG runtimeBase = nt->OptionalHeader.ImageBase;
            if (runtimeBase >= 0x7FF000000000ULL) {
                nt->OptionalHeader.ImageBase = 0x140000000ULL;
                Logger::Log(Utils::Format("[+] ImageBase restored: 0x%llx -> 0x140000000", runtimeBase), LogLevel::INFO);
            }

            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                if (sec->Misc.VirtualSize != 0) {
                    sec->PointerToRawData = sec->VirtualAddress;
                    sec->SizeOfRawData    = sec->Misc.VirtualSize;
                }
            }
        }
    }

    if (!parser.Save(output.c_str())) {
        Logger::Log("[-] Failed to save unpacked file.", LogLevel::Error);
        return 1;
    }

    Logger::Log(Utils::Format("[+] Unpacking complete. Output: %s", output.c_str()), LogLevel::INFO);
    return 0;
}

