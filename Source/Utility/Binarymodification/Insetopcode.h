/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Writes an opcode (and args) to the specified address.
*/

#pragma once
#include <stdint.h>
#include <Configuration\All.h>

void Insertjump(const uint64_t Address, const uint64_t Target);
void Insertcall(const uint64_t Address, const uint64_t Target);
void Insertmov(const uint64_t Address, const uint64_t Target);
