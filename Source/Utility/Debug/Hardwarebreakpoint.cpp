/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        This class is based on code by someone I can't remember.
*/

#include "Hardwarebreakpoint.h"

#ifndef _WIN32
    // TODO(Convery): Implement this when needed.
#else

void Debug::SetBits(DWORD_PTR &DW, uint32_t LowBit, uint32_t Bits, uint32_t NewValue)
{
    DWORD_PTR mask = (1 << Bits) - 1; 
    DW = (DW & ~(mask << LowBit)) | (NewValue << LowBit);
}
DWORD WINAPI Debug::th(LPVOID lpParameter)
{
    HWBRK* h = (HWBRK*)lpParameter;
    int j = 0;
    int y = 0;

    j = SuspendThread(h->hT);
    y = GetLastError();

    CONTEXT ct = {0};
    ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    j = GetThreadContext(h->hT,&ct);
    y = GetLastError();

    int FlagBit = 0;

    bool Dr0Busy = false;
    bool Dr1Busy = false;
    bool Dr2Busy = false;
    bool Dr3Busy = false;
    if (ct.Dr7 & 1)
        Dr0Busy = true;
    if (ct.Dr7 & 4)
        Dr1Busy = true;
    if (ct.Dr7 & 16)
        Dr2Busy = true;
    if (ct.Dr7 & 64)
        Dr3Busy = true;

    if (h->Opr == 1)
    {
        // Remove
        if (h->iReg == 0)
        {
            FlagBit = 0;
            ct.Dr0 = 0;
            Dr0Busy = false;
        }
        if (h->iReg == 1)
        {
            FlagBit = 2;
            ct.Dr1 = 0;
            Dr1Busy = false;
        }
        if (h->iReg == 2)
        {
            FlagBit = 4;
            ct.Dr2 = 0;
            Dr2Busy = false;
        }
        if (h->iReg == 3)
        {
            FlagBit = 6;
            ct.Dr3 = 0;
            Dr3Busy = false;
        }

        ct.Dr7 &= ~(1 << FlagBit);
    }
    else
    {
        if (!Dr0Busy)
        {
            h->iReg = 0;
            ct.Dr0 = (DWORD_PTR)h->a;
            Dr0Busy = true;
        }
        else
            if (!Dr1Busy)
            {
                h->iReg = 1;
                ct.Dr1 = (DWORD_PTR)h->a;
                Dr1Busy = true;
            }
            else
                if (!Dr2Busy)
                {
                    h->iReg = 2;
                    ct.Dr2 = (DWORD_PTR)h->a;
                    Dr2Busy = true;
                }
                else
                    if (!Dr3Busy)
                    {
                        h->iReg = 3;
                        ct.Dr3 = (DWORD_PTR)h->a;
                        Dr3Busy = true;
                    }
                    else
                    {
                        h->SUCC = false;
                        j = ResumeThread(h->hT);
                        y = GetLastError();
                        SetEvent(h->hEv);
                        return 0;
                    }
        ct.Dr6 = 0;
        int st = 0;
        if (h->Type == HWBRK_TYPE_CODE)
            st = 0;
        if (h->Type == HWBRK_TYPE_READWRITE)
            st = 3;
        if (h->Type == HWBRK_TYPE_WRITE)
            st = 1;
        int le = 0;
        if (h->Size == HWBRK_SIZE_1)
            le = 0;
        if (h->Size == HWBRK_SIZE_2)
            le = 1;
        if (h->Size == HWBRK_SIZE_4)
            le = 3;
        if (h->Size == HWBRK_SIZE_8)
            le = 2;

        SetBits(ct.Dr7, 16 + h->iReg*4, 2, st);
        SetBits(ct.Dr7, 18 + h->iReg*4, 2, le);
        SetBits(ct.Dr7, h->iReg*2,1,1);
    }

    ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    j = SetThreadContext(h->hT,&ct);
    y = GetLastError();

    ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    j = GetThreadContext(h->hT,&ct);
    y = GetLastError();

    j = ResumeThread(h->hT);
    y = GetLastError();

    h->SUCC = true;

    SetEvent(h->hEv);
    return 0;
}
void Debug::SetManualHardwareBreakpoint(CONTEXT& ct, LPVOID at)
{
    bool Dr0Busy = false;
    bool Dr1Busy = false;
    bool Dr2Busy = false;
    bool Dr3Busy = false;
    if (ct.Dr7 & 1)
        Dr0Busy = true;
    if (ct.Dr7 & 4)
        Dr1Busy = true;
    if (ct.Dr7 & 16)
        Dr2Busy = true;
    if (ct.Dr7 & 64)
        Dr3Busy = true;

    int iReg;

    if (!Dr0Busy)
    {
        ct.Dr0 = (DWORD_PTR)at;
        Dr0Busy = true;

        iReg = 0;
    }
    else
        if (!Dr1Busy)
        {
            ct.Dr1 = (DWORD_PTR)at;
            Dr1Busy = true;

            iReg = 1;
        }
        else
            if (!Dr2Busy)
            {
                ct.Dr2 = (DWORD_PTR)at;
                Dr2Busy = true;

                iReg = 2;
            }
            else
                if (!Dr3Busy)
                {
                    ct.Dr3 = (DWORD_PTR)at;
                    Dr3Busy = true;

                    iReg = 3;
                }
                else
                {
                    return;
                }
    ct.Dr6 = 0;
    int st = 0;
    st = 0;
    int le = 0;
    le = 0;

    SetBits(ct.Dr7, 16 + iReg*4, 2, st);
    SetBits(ct.Dr7, 18 + iReg*4, 2, le);
    SetBits(ct.Dr7, iReg*2,1,1);
}
void Debug::RemoveManualHardwareBreakpoint(CONTEXT& ct)
{
    ct.Dr0 = 0;
    ct.Dr1 = 0;
    ct.Dr2 = 0;
    ct.Dr3 = 0;

    ct.Dr7 &= ~(1 | 4 | 16 | 64);
}
HANDLE Debug::SetHardwareBreakpoint(HANDLE hThread, HWBRK_TYPE Type, HWBRK_SIZE Size, void* s)
{
    HWBRK* h = new HWBRK;
    h->a = s;
    h->Size = Size;
    h->Type = Type;
    h->hT = hThread;


    if (hThread == GetCurrentThread())
    {
        DWORD pid = GetCurrentThreadId();
        h->hT = OpenThread(THREAD_ALL_ACCESS,0,pid);
    }

    h->hEv = CreateEvent(0,0,0,0);
    h->Opr = 0; // Set Break
    CreateThread(0,0,th,(LPVOID)h,0,0);
    WaitForSingleObject(h->hEv,INFINITE);
    CloseHandle(h->hEv);
    h->hEv = 0;

    if (hThread == GetCurrentThread())
    {
        CloseHandle(h->hT);
    }
    h->hT = hThread;

    if (!h->SUCC)
    {
        delete h;
        return 0;
    }

    return (HANDLE)h;
}
bool Debug::RemoveHardwareBreakpoint(HANDLE hBrk)
{
    HWBRK* h = (HWBRK*)hBrk;
    if (!h)
        return false;

    bool C = false;
    if (h->hT == GetCurrentThread())
    {
        DWORD pid = GetCurrentThreadId();
        h->hT = OpenThread(THREAD_ALL_ACCESS,0,pid);
        C = true;
    }

    h->hEv = CreateEvent(0,0,0,0);
    h->Opr = 1; // Remove Break
    CreateThread(0,0,th,(LPVOID)h,0,0);
    WaitForSingleObject(h->hEv,INFINITE);
    CloseHandle(h->hEv);
    h->hEv = 0;

    if (C)
    {
        CloseHandle(h->hT);
    }

    delete h;
    return true;
}

#endif
