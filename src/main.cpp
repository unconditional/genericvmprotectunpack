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

#ifndef GIT_COMMIT_HASH
    #define GIT_COMMIT_HASH "unknown"
#endif


int main(int argc, char *argv[])
{
    Logger::Log(Utils::Format("[*] VMProtect Unpacker Version (Git Commit): %s", GIT_COMMIT_HASH), LogLevel::INFO);

    if (argc < 2)
    {
        std::cout << "Usage: unpacker.exe <malware.exe>" << std::endl;
        return 1;
    }

    const char *exePath = argv[1];
    Logger::Log(Utils::Format("[*] Loading executable: %s", exePath), LogLevel::INFO);

    std::string target = argv[1];

    VMPDebugger debugger;
    if (!debugger.Run(target))
    {
        Logger::Log("[-] Debugging failed.", LogLevel::Error);
        return 1;
    }

    PEParser parser;
    std::string dumpedFile = "unpacked_dump.bin";

    if (!parser.LoadF(dumpedFile, true))
    {
        Logger::Log("[-] Failed to load dumped PE. Trying shellcode disassembly...", LogLevel::Error);

        if (!Analyzer::AnalyzeDump(dumpedFile))
        {
            Logger::Log("[-] Shellcode analysis failed.", LogLevel::Error);
            return 1;
        }

        return 0;
    }


    // Patch PE Header AddressOfEntryPoint with detected real OEP
    DWORD realOEP = debugger.GetDetectedOEP();
    if (realOEP != 0)
    {
        parser.SetOEP(realOEP);
        Logger::Log(Utils::Format("[+] Patched PE Header AddressOfEntryPoint to Real OEP RVA: 0x%08X", realOEP), LogLevel::INFO);
    }


    std::string reason;
    if (!VMProtectDetector::Detect(parser, reason))
    {
        Logger::Log("[-] VMProtect not detected. Exiting.", LogLevel::INFO);
        return 0;
    }

    Logger::Log("[+] VMProtect detected. Extracting bytecode...", LogLevel::INFO);
    auto bytecodeRegions = BytecodeExtractor::Extract(&parser);

    if (bytecodeRegions.empty())
    {
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
        PIMAGE_NT_HEADERS nt = parser.GetNtHeadersRaw();
        if (nt)
        {
            if (parser.IsPE64())
            {
                PIMAGE_NT_HEADERS64 nt64 = parser.GetNtHeaders64();
                ULONGLONG runtimeBase = nt64->OptionalHeader.ImageBase;

                if (runtimeBase >= 0x7FF000000000ULL)
                {
                    nt64->OptionalHeader.ImageBase = 0x140000000ULL;
                    Logger::Log(Utils::Format("[+] ImageBase restored: 0x%llx -> 0x140000000", runtimeBase), LogLevel::INFO);
                }
            }
            else
            {
                PIMAGE_NT_HEADERS32 nt32 = parser.GetNtHeaders32();
                DWORD runtimeBase = nt32->OptionalHeader.ImageBase;

                // 32-bit processes rarely get relocated above 2GB unless ASLR/high-entropy is in play,
                // but any base above the typical 0x400000 default is worth restoring.
                if (runtimeBase >= 0x10000000UL)
                {
                    nt32->OptionalHeader.ImageBase = 0x400000UL;
                    Logger::Log(Utils::Format("[+] ImageBase restored: 0x%lx -> 0x400000", runtimeBase), LogLevel::INFO);
                }
            }

            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            DWORD fileAlignment = parser.IsPE64() ?
                parser.GetNtHeaders64()->OptionalHeader.FileAlignment :
                parser.GetNtHeaders32()->OptionalHeader.FileAlignment;

            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
            {
                if (sec->Misc.VirtualSize != 0)
                {
                    sec->PointerToRawData = sec->VirtualAddress;
                    // Properly align SizeOfRawData using FileAlignment to avoid PE loader corruption
                    sec->SizeOfRawData = (sec->Misc.VirtualSize + fileAlignment - 1) & ~(fileAlignment - 1);
                }
            }
        }
    }

    if (!parser.Save(output.c_str()))
    {
        Logger::Log("[-] Failed to save unpacked file.", LogLevel::Error);
        return 1;
    }

    Logger::Log(Utils::Format("[+] Unpacking complete. Output: %s", output.c_str()), LogLevel::INFO);
    return 0;
}
