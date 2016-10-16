/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        This class is based on code by someone I can't remember.
*/

#pragma once

#ifndef _WIN32
    // TODO(Convery): Implement this when needed.
#else
#include <Windows.h>
#include <stdint.h>
#undef min
#undef max

namespace Debug
{
    enum HWBRK_TYPE
    {
        HWBRK_TYPE_CODE,
        HWBRK_TYPE_READWRITE,
        HWBRK_TYPE_WRITE,
    };
    enum HWBRK_SIZE
    {
        HWBRK_SIZE_1,
        HWBRK_SIZE_2,
        HWBRK_SIZE_4,
        HWBRK_SIZE_8,
    };
    class HWBRK
    {
    public:
        void* a;
        HANDLE hT;
        HWBRK_TYPE Type;
        HWBRK_SIZE Size;
        HANDLE hEv;
        int iReg;
        int Opr;
        bool SUCC;

        HWBRK()
        {
            Opr = 0;
            a = 0;
            hT = 0;
            hEv = 0;
            iReg = 0;
            SUCC = false;
        }
    };

    void SetBits(DWORD_PTR &DW, uint32_t LowBit, uint32_t Bits, uint32_t NewValue);
    DWORD WINAPI th(LPVOID lpParameter);
    void SetManualHardwareBreakpoint(CONTEXT& ct, LPVOID at);
    void RemoveManualHardwareBreakpoint(CONTEXT& ct);
    HANDLE SetHardwareBreakpoint(HANDLE hThread, HWBRK_TYPE Type, HWBRK_SIZE Size, void* s);
    bool RemoveHardwareBreakpoint(HANDLE hBrk);
}
#endif
