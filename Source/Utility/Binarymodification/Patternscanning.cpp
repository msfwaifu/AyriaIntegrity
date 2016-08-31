/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Scans a range (.text or .data) for a pattern.
        Mask is `0x01` for active and `0x00` for inactive.
        Mask should not start with an inactive byte, not checked.
*/

#include <Configuration\All.h>
#include <Utility\All.h>
#include <algorithm>
#include <future>

// Calculate the ranges every 10 scans.
static size_t Scancount = 0;
static size_t Textstart = 0;
static size_t Datastart = 0;
static size_t Textend = 0;
static size_t Dataend = 0;
void Getmodulerange();

#ifdef _WIN32
#include <Windows.h>
#undef min

void Getmodulerange()
{
    // Check if we need to update.
    if (0 != Scancount++ % 10)
        return;

    // Get the modulebase.
    HMODULE Module = GetModuleHandleA(NULL);
    if (!Module) return;

    // PE+ headers.
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)Module + DOSHeader->e_lfanew);

    // Ranges from the header.
    Textstart = size_t(Module) + NTHeader->OptionalHeader.BaseOfCode;
    Textend = Textstart + NTHeader->OptionalHeader.SizeOfCode;
    Datastart = Textend;
    Dataend = Datastart + NTHeader->OptionalHeader.SizeOfInitializedData;
}
#else
void Getmodulerange()
{
    /*
        TODO(Convery):
        Implement when we officially support Nix.
    */
}
#endif

// Basic scanning.
size_t Findpattern(size_t Start, size_t End, std::string Pattern, std::string Mask)
{
    size_t Locallength = std::min(Pattern.size(), Mask.size());
    const char *Localpattern = Pattern.data();
    const char *Localmask = Mask.data();    
    uint8_t Firstbyte = Pattern[0];

    // Local lambda for cleaner code.
    auto Lambda = [=](size_t Address, size_t Length, const char *Pattern, const char *Mask) -> bool
    {
        for (size_t i = 1; i < Length; ++i)
        {
            // Skip inactive bytes.
            if (Mask[i] == '\x00') continue;

            // Break on invalid compare.
            if (((uint8_t *)Address)[i] != Pattern[i])
                return false;
        }

        return true;
    };

    // Iterate over the range.
    for (; Start < End; ++Start)
    {
        // Skip to the relevant part.
        if (*(uint8_t *)Start != Firstbyte) continue;

        // Compare the range.
        if (Lambda(Start, Locallength, Localpattern, Localmask))
            return Start;
    }

    // Return an invalid address.
    return 0;
}
std::vector<size_t> FindpatternMultiple(size_t Start, size_t End, std::string Pattern, std::string Mask)
{
    std::vector<size_t> Results;
    size_t Lastscan = 0;

    do
    {
        // Scan until there is no more results.
        Lastscan = Findpattern(Start + Lastscan, End, Pattern, Mask);
        if (Lastscan) Results.push_back(Lastscan);

    } while (Lastscan);
    
    return Results;
}

// Range limited.
size_t FindpatternText(std::string Pattern, std::string Mask, size_t Offset)
{
    // Update the ranges if needed.
    Getmodulerange();

    return Findpattern(Textstart + Offset, Textend, Pattern, Mask);
}
size_t FindpatternData(std::string Pattern, std::string Mask, size_t Offset)
{
    // Update the ranges if needed.
    Getmodulerange();

    return Findpattern(Datastart + Offset, Dataend, Pattern, Mask);
}
std::vector<size_t> FindpatternTextMultiple(std::string Pattern, std::string Mask)
{
    std::vector<size_t> Results;
    size_t Lastscan = 0;

    do
    {
        // Scan until there is no more results.
        Lastscan = FindpatternText(Pattern, Mask, Lastscan);
        if (Lastscan) Results.push_back(Lastscan);

    } while (Lastscan);
    
    return Results;
}
std::vector<size_t> FindpatternDataMultiple(std::string Pattern, std::string Mask)
{
    std::vector<size_t> Results;
    size_t Lastscan = 0;

    do
    {
        // Scan until there is no more results.
        Lastscan = FindpatternData(Pattern, Mask, Lastscan);
        if (Lastscan) Results.push_back(Lastscan);

    } while (Lastscan);
    
    return Results;
}

// Formatted scan, e.g. "00 04 EB 84 ? ? 32"
size_t FindpatternFormat(std::string Readablepattern)
{
    const char *Iterator = Readablepattern.c_str();
    std::string Pattern;
    std::string Mask;
    
    // Iterate through the string.
    while (Iterator++)
    {
        // Skip spaces.
        if (*Iterator == ' ')
            continue;

        // Check for inactive bytes.
        if (*Iterator == '?')
        {
            Mask.append(1, '\x00');
            Pattern.append(1, '\x00');
            continue;
        }

        // Else we grab two bytes.
        Mask.append(1, '\x01');
        Pattern.append(1, char(strtoul(Iterator, nullptr, 16)));
        Iterator++;
    }

    return Findpattern(Textstart, Dataend, Pattern, Mask);
}
std::vector<size_t> FindpatternFormatMultiple(std::string Readablepattern)
{
    const char *Iterator = Readablepattern.c_str();
    std::string Pattern;
    std::string Mask;
    
    // Iterate through the string.
    while (Iterator++)
    {
        // Skip spaces.
        if (*Iterator == ' ')
            continue;

        // Check for inactive bytes.
        if (*Iterator == '?')
        {
            Mask.append(1, '\x00');
            Pattern.append(1, '\x00');
            continue;
        }

        // Else we grab two bytes.
        Mask.append(1, '\x01');
        Pattern.append(1, char(strtoul(Iterator, nullptr, 16)));
        Iterator++;
    }

    return FindpatternMultiple(Textstart, Dataend, Pattern, Mask);
}
