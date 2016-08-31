/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Some CEG calls are hooked through throwing exceptions.
        We also skip the slow anti-debug so the game works faster.
*/

#include <Configuration\All.h>
#include <Utility\All.h>
#include "SteamCEG.h"
#include <mutex>

size_t Trapcall;
size_t Trapreturn;
std::mutex Traplock;

#ifdef _WIN32
#include <Windows.h>

#ifdef ENVIRONMENT64
LONG CALLBACK Traphandler(PEXCEPTION_POINTERS Exceptioninfo)
{
    // If our breakpoint was hit.
    if (Exceptioninfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        uint8_t *Caller = (uint8_t *)Exceptioninfo->ContextRecord->Rip;

        if (Exceptioninfo->ContextRecord->Rip == Trapreturn)
        {
            // Set the return address.
            Exceptioninfo->ContextRecord->Rsp -= 8;
            *(uint64_t *)(Exceptioninfo->ContextRecord->Rsp) = Exceptioninfo->ContextRecord->Rip;

            // Jump to our decrypted function.
            Exceptioninfo->ContextRecord->Rip = Trapcall;
            Debug::RemoveManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord));

            // Cleanup.
            Trapreturn = 0;
            Traplock.unlock();
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            // TODO(Convery): x64 caller verification.
            if (Caller[0] == 0x83 && Caller[1] == 0xC4)
            {
                Trapreturn = *(uint64_t*)(Exceptioninfo->ContextRecord->Rbp + 8);

                Debug::RemoveManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord));
                Debug::SetManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord), (LPVOID)Trapreturn);

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
    else
    {
        // CEGs exceptioncode.
        if(Exceptioninfo->ExceptionRecord->ExceptionCode == 0x40101010)
        {
            LPVOID bpLoc = (LPVOID)Exceptioninfo->ExceptionRecord->ExceptionInformation[0];

            Debug::SetManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord), bpLoc);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
void InstallTraphandler()
{
    AddVectoredExceptionHandler(1, Traphandler);
}
#else

LONG CALLBACK Traphandler(PEXCEPTION_POINTERS Exceptioninfo)
{
    // If our breakpoint was hit.
    if (Exceptioninfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        uint8_t *Caller = (uint8_t *)Exceptioninfo->ContextRecord->Eip;

        if (Exceptioninfo->ContextRecord->Eip == Trapreturn)
        {
            // Set the return address.
            Exceptioninfo->ContextRecord->Esp -= 4;
            *(uint32_t *)(Exceptioninfo->ContextRecord->Esp) = Exceptioninfo->ContextRecord->Eip;

            // Jump to our decrypted function.
            Exceptioninfo->ContextRecord->Eip = Trapcall;
            Debug::RemoveManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord));

            // Cleanup.
            Trapreturn = 0;
            Traplock.unlock();
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            if (Caller[0] == 0x83 && Caller[1] == 0xC4)
            {
                Trapreturn = *(uint32_t*)(Exceptioninfo->ContextRecord->Ebp + 4);

                Debug::RemoveManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord));
                Debug::SetManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord), (LPVOID)Trapreturn);

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
    else
    {
        // CEGs exceptioncode.
        if(Exceptioninfo->ExceptionRecord->ExceptionCode == 0x40101010)
        {
            LPVOID bpLoc = (LPVOID)Exceptioninfo->ExceptionRecord->ExceptionInformation[0];

            Debug::SetManualHardwareBreakpoint(*(Exceptioninfo->ContextRecord), bpLoc);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
void InstallTraphandler()
{
    AddVectoredExceptionHandler(1, Traphandler);
}
#endif

#else

void InstallTraphandler()
{
    /*
        TODO(Convery):
        While I think that CEG is exclusive to Windows, this
        function remains here in case it gets ported to Nix.
    */
}
#endif
