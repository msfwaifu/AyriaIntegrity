/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Writes an opcode (and args) to the specified address.
*/

#include "Insetopcode.h"
#include "Memoryprotection.h"

#ifdef ENVIRONMENT64

void Insertjump(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 12);
    {
        // movabs rax, Target
        // jmp eax
        *(uint8_t *)(Address + 0) = 0x48;
        *(uint8_t *)(Address + 1) = 0xB8;
        *(uint64_t *)(Address + 2) = Target;
        *(uint8_t *)(Address + 10) = 0xFF;
        *(uint8_t *)(Address + 11) = 0xE0;
    }
    Protectrange((void *)Address, 12, Protection);
}
void Insertcall(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 12);
    {
        // movabs rax, Target
        // call eax
        *(uint8_t *)(Address + 0) = 0x48;
        *(uint8_t *)(Address + 1) = 0xB8;
        *(uint64_t *)(Address + 2) = Target;
        *(uint8_t *)(Address + 10) = 0xFF;
        *(uint8_t *)(Address + 11) = 0xD0;
    }
    Protectrange((void *)Address, 12, Protection);
}
void Insertmov(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 10);
    {
        // movabs rax, Target
        *(uint8_t *)(Address + 0) = 0x48;
        *(uint8_t *)(Address + 1) = 0xB8;
        *(uint64_t *)(Address + 2) = Target;  
    }
    Protectrange((void *)Address, 10, Protection);
}
#else

void Insertjump(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 5);
    {
        // jmp rel Target
        *(uint8_t *)(Address + 0) = 0xE9;
        *(uint32_t *)(Address + 1) = uint32_t(Target) - uint32_t(Address) - 5;  
    }
    Protectrange((void *)Address, 5, Protection);
}
void Insertcall(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 5);
    {
        // call rel Target
        *(uint8_t *)(Address + 0) = 0xE8;
        *(uint32_t *)(Address + 1) = uint32_t(Target) - uint32_t(Address) - 5;  
    }
    Protectrange((void *)Address, 5, Protection);
}
void Insertmov(const uint64_t Address, const uint64_t Target)
{
    auto Protection = Unprotectrange((void *)Address, 5);
    {
        // mov eax, Target
        *(uint8_t *)(Address + 0) = 0xB8;
        *(uint32_t *)(Address + 1) = uint32_t(Target);  
    }
    Protectrange((void *)Address, 5, Protection);
}
#endif
