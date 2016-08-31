/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Adds or removes protection from a range of pages.
*/

#pragma once
#include <Configuration\All.h>
#include <Utility\All.h>

void Protectrange(void *Address, const size_t Length, unsigned long Oldprotect);
unsigned long Unprotectrange(void *Address, const size_t Length);
