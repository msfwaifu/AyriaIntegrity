/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        CEG creates some encrypted functions and store them in the
        .conceal segment. We replace them with blocks that we know
        the key to, thus bypassing the key-generation requirement.
*/

#include <Configuration\All.h>
#include <Utility\All.h>
#include "SteamCEG.h"
#include <json.hpp>
#include <base64.h>
#include <mutex>

// Concealed datablock.
struct Concealdata
{
    bool Parsed{ false };
    uint64_t Returnaddress;
    uint64_t Functionaddress;
    std::string Encryptionkey;
    std::string Encryptedblock;

    void Deserialize(std::string &JSON)
    {
        nlohmann::json Reader;
        try
        {
            Reader = nlohmann::json::parse(JSON);
            Returnaddress = Reader["Returnaddress"];
            Functionaddress = Reader["Functionaddress"];
            Base64::Decode(Reader["Encryptionkey"], &Encryptionkey);
            Base64::Decode(Reader["Encryptedblock"], &Encryptedblock);

            Parsed = true;
        }
        catch (...) {};
    }
};

// Global variables that can be accessed from assembly.
size_t Revealmemcpy;
size_t Revealaddress;
uint8_t Revealkey[16];
size_t Revealdecryptor;
extern size_t Trapcall;
extern size_t Trapreturn;
extern std::mutex Traplock;

// Find the block for the caller.
void __stdcall FetchCEG(size_t Caller)
{
    Concealdata *Block;
    Traplock.lock();

    if (GetEncryptedblock(Caller + 3, &Block) || GetEncryptedblock(Caller, &Block))
    {
        Revealaddress = size_t(Block->Functionaddress);
        std::memcpy(Revealkey, Block->Encryptionkey.data(), 16);
        std::memcpy((void *)Revealaddress, Block->Encryptedblock.data(), Block->Encryptedblock.size());
        return;
    }
    else
    {
        DebugPrint(va_small("%s found no datablock for 0x%X!", __func__, Caller));
        Traplock.unlock();
        std::exit(0xDEADC0DE);
    }
}

// Notify the trap that we need to jump.
void __stdcall NotifyTrap(void *Address)
{
    LPVOID Arguments[1];
    Arguments[0] = Address;
    RaiseException(0x40101010, 0, 1, (ULONG_PTR*)Arguments);
}

// Verify that the range is writable before copying.
void Revealmemcpyhook(void *Destination, void *Source, size_t Length)
{
    auto Protection = Unprotectrange(Destination, Length);
    {
        std::memcpy(Destination, Source, Length);
    }
    Protectrange(Destination, Length, Protection);
}

// Replace the encryption block with our own.
#ifdef ENVIRONMENT64

void Revealhook() 
{
    /*
        TODO(Convery):
        There appears to be no CEG on x64, maybe in the future.
    */
};
#else

void __declspec(naked) Revealhook()
{
    __asm
    {
        // Push the return address and read
        // the concealed datablock by it.
        mov eax, [ebp + 04h];
        push eax;
        call FetchCEG;

        // Copy the Encryptionkey.
        mov eax, offset Revealkey;
        push 10h;
        push eax;
        mov eax, [esp + 10h];
        push eax;
        call Revealmemcpyhook;
        add esp, 0Ch;

        // Call the decryptionroutine.
        mov eax, offset Revealkey;
        push eax;
        mov eax, Revealaddress;
        push eax;
        call Revealdecryptor;
        add esp, 08h;

        // Continue execution in the new function.
        mov Trapcall, eax;

        // Raise an exception to notify the trap.
        mov eax, [ebp + 04h];
        push eax;
        call NotifyTrap;
        retn;
    }
}
#endif

// Place the hook on a decryption routine.
void SetRevealhook(const size_t Address)
{
    static bool InitializedTrap = false;
    if (!InitializedTrap)
    {
        InitializedTrap = true;
        InstallTraphandler();

        // Find the decryptor and memcpy.
        Revealmemcpy = FindpatternText("\xE8????\x8B\x56\x08\x8B\x46\x0C\x8B\x4E\x04", std::string("\x01\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01", 14));
        if (Revealmemcpy)
        {
            Insertcall(Revealmemcpy, uint64_t(Revealmemcpyhook));
            Revealdecryptor = Revealmemcpy - 0x2E;
        }
    }

    if(Address)
        Insertcall(Address, size_t(Revealhook));
}
