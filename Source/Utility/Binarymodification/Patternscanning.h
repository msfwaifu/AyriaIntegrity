/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Scans a range (.text or .data) for a pattern.
        Mask is `0x01` for active and `0x00` for inactive.
        Mask should not start with an inactive byte, not checked.
*/

#pragma once
#include <stdint.h>
#include <vector>

// Basic scanning.
size_t Findpattern(size_t Start, size_t End, std::string Pattern, std::string Mask);
std::vector<size_t> FindpatternMultiple(size_t Start, size_t End, std::string Pattern, std::string Mask);

// Range limited.
size_t FindpatternText(std::string Pattern, std::string Mask, size_t Offset = 0);
size_t FindpatternData(std::string Pattern, std::string Mask, size_t Offset = 0);
std::vector<size_t> FindpatternTextMultiple(std::string Pattern, std::string Mask);
std::vector<size_t> FindpatternDataMultiple(std::string Pattern, std::string Mask);

// Formatted scan, e.g. "00 04 EB 84 ? ? 32"
size_t FindpatternFormat(std::string Readablepattern);
std::vector<size_t> FindpatternFormatMultiple(std::string Readablepattern);
