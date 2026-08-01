#include "vmprotectunpacker/VMProtectDetector.h"
#include <iostream>
#include <cmath>
#include <map>
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"

VMProtectDetector::VMProtectDetector(PEParser *parser) : parser(parser) {}

bool VMProtectDetector::IsVMProtectPresent()
{
    if (CheckVMProtectSignature())
        return true;
    if (CheckSectionEntropy())
        return true;
    if (CheckEntryPointLocation())
        return true;
    if (CheckGhostSections())
        return true;
    return false;
}

std::string VMProtectDetector::GetDetectionReason()
{
    return detectionReason;
}

double VMProtectDetector::ComputeEntropy(const IMAGE_SECTION_HEADER *sec)
{
    BYTE *image = parser->GetMappedImage();
    if (!image || !sec)
        return 0.0;

    DWORD offset, size;
    if (parser->IsSuspendedDump())
    {
        // Memory dump: byte offset in buffer == RVA (VirtualAddress-based)
        offset = sec->VirtualAddress;
        size = sec->Misc.VirtualSize;
    }
    else
    {
        // On-disk file: use raw/file-aligned layout
        offset = sec->PointerToRawData;
        size = sec->SizeOfRawData;
    }

    if (size == 0 || offset + size > parser->GetImageSize())
        return 0.0;

    BYTE *sectionData = image + offset;

    std::map<BYTE, int> freq;
    for (DWORD i = 0; i < size; ++i)
        freq[sectionData[i]]++;

    double entropy = 0.0;
    for (const auto &pair : freq)
    {
        double p = (double)pair.second / size;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

bool VMProtectDetector::CheckVMProtectSignature()
{
    auto section = parser->GetSectionHeader(".vmp0");
    if (section)
    {
        detectionReason = ".vmp0 section found (VMProtect)";
        return true;
    }
    section = parser->GetSectionHeader(".vmp1");
    if (section)
    {
        detectionReason = ".vmp1 section found (VMProtect)";
        return true;
    }
    section = parser->GetSectionHeader(".themida");
    if (section)
    {
        detectionReason = ".themida section found (VMProtect/Themida)";
        return true;
    }
    return false;
}

bool VMProtectDetector::CheckEntryPointLocation()
{
    DWORD epRVA = parser->GetOEP();
    auto sec = parser->GetSectionContainingRVA(epRVA);

    // If no section owns the OEP RVA at all, that's itself a red flag —
    // means the loader/protector placed code outside declared sections.
    if (!sec)
    {
        detectionReason = "Entry point not contained in any declared section";
        return true;
    }
    return false;
}

bool VMProtectDetector::CheckSectionEntropy()
{
    DWORD epRVA = parser->GetOEP();
    auto sec = parser->GetSectionContainingRVA(epRVA);
    if (!sec)
        return false;

    double entropy = ComputeEntropy(sec);

    if (entropy > 7.5)
    {
        detectionReason = "High entropy in entry-point section (Possible VMProtect)";
        return true;
    }
    return false;
}

bool VMProtectDetector::CheckGhostSections()
{
    auto sections = parser->GetAllSectionHeaders();
    bool hasGhostSection = false;
    bool hasHighEntropyPayload = false;

    for (auto &sec : sections)
    {
        bool isCodeExec = (sec.Characteristics & IMAGE_SCN_CNT_CODE) &&
                          (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE);

        // Ghost section: no raw data on disk but a large runtime footprint —
        // typical of a protector's "unpack target" section.
        bool isGhost = (sec.SizeOfRawData == 0 && sec.Misc.VirtualSize > 0x10000);
        if (isGhost && isCodeExec)
            hasGhostSection = true;

        // Payload section: large, executable, and near-maximum entropy —
        // typical of an encrypted/compressed VM bytecode blob.
        if (isCodeExec && sec.SizeOfRawData > 1000000)
        {
            double entropy = ComputeEntropy(&sec);
            if (entropy > 7.5)
                hasHighEntropyPayload = true;
        }
    }

    if (hasGhostSection && hasHighEntropyPayload)
    {
        detectionReason = "Ghost code section + high-entropy payload section (VM-protector pattern)";
        return true;
    }
    return false;
}

bool VMProtectDetector::Detect(PEParser &parser, std::string &reason)
{
    Logger::Log("[*] Starting VMProtectDetector::Detect...", LogLevel::INFO);

    VMProtectDetector detector(&parser);
    bool result = detector.IsVMProtectPresent();
    if (result)
    {
        reason = detector.GetDetectionReason();
        Logger::Log(Utils::Format("[+] VMProtect detected: %s", reason.c_str()), LogLevel::INFO);
    }

    return result;
}
