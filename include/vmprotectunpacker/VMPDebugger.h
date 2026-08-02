#pragma once

#include <windows.h>
#include <string>
#include <capstone/capstone.h>

class VMPDebugger {
public:
    VMPDebugger() : processHandle(NULL), threadHandle(NULL), realOEP(0) {}
    bool Run(const std::string &exePath);
    bool DumpProcessImage(HANDLE hProcess, LPVOID baseAddress, SIZE_T imageSize, const std::string &dumpPath);
    bool Disassemble(LPVOID address, size_t size, cs_mode mode);
    DWORD GetDetectedOEP() const { return realOEP; }

private:
    DWORD FindRealOEP(HANDLE hProcess, LPVOID imageBase, DWORD codeRVA, DWORD codeSize, bool is64);

private:
    HANDLE processHandle;
    HANDLE threadHandle;
    DWORD realOEP;
};