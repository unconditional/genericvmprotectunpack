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

    std::string secName = parser->SectionName(sec);
    Logger::Log(Utils::Format("[*] Section containing OEP RVA:: %s", secName.c_str()), LogLevel::INFO);

    return false;
}

bool VMProtectDetector::CheckSectionEntropy()
{
    DWORD epRVA = parser->GetOEP();
    auto sec = parser->GetSectionContainingRVA(epRVA);
    if (!sec)
        return false;

    double entropy = ComputeEntropy(sec);
    std::string secName = parser->SectionName(sec);
    Logger::Log(Utils::Format("[*] Section containing OEP RVA: %s has entropy: %f", secName.c_str(), entropy), LogLevel::INFO);

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

    Logger::Log(Utils::Format("[DEBUG] IsSuspendedDump=%d, ImageSize=%zu",
        parser->IsSuspendedDump(), parser->GetImageSize()), LogLevel::INFO);

    for (auto &sec : sections)
    {
        std::string name = parser->SectionName(&sec);
        bool isCodeExec = (sec.Characteristics & IMAGE_SCN_CNT_CODE) &&
                           (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        bool isGhost = (sec.SizeOfRawData == 0 && sec.Misc.VirtualSize > 0x10000);

        double entropy = 0.0;
        bool entropyChecked = false;
        if (isCodeExec && sec.SizeOfRawData > 1000000)
        {
            entropy = ComputeEntropy(&sec);
            entropyChecked = true;
        }

        Logger::Log(Utils::Format(
            "[DEBUG] Section=%-8s Characteristics=0x%08X isCodeExec=%d RawSize=%u VirtSize=%u VA=0x%X isGhost=%d entropy=%.3f (%s)",
            name.c_str(), sec.Characteristics, isCodeExec, sec.SizeOfRawData,
            sec.Misc.VirtualSize, sec.VirtualAddress, isGhost, entropy,
            entropyChecked ? "computed" : "skipped"),
            LogLevel::INFO);

        if (isGhost && isCodeExec)
            hasGhostSection = true;

        if (entropyChecked && entropy > 7.5)
            hasHighEntropyPayload = true;
    }

    Logger::Log(Utils::Format("[DEBUG] hasGhostSection=%d hasHighEntropyPayload=%d",
        hasGhostSection, hasHighEntropyPayload), LogLevel::INFO);

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
