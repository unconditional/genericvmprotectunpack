#pragma once
#include <windows.h>
#include <string>
#include "PEParser.h"

class VMProtectDetector {
public:
    VMProtectDetector(PEParser* parser);
    bool IsVMProtectPresent();
    std::string GetDetectionReason();
    static bool Detect(PEParser& parser, std::string& reason);

private:
    PEParser* parser;
    std::string detectionReason;

    double ComputeEntropy(const IMAGE_SECTION_HEADER *sec);
    bool CheckSectionEntropy();
    bool CheckGhostSections();
    bool CheckEntryPointLocation();
    bool CheckVMProtectSignature();
};