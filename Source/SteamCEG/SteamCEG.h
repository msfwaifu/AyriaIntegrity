/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        The "Custom Executable Generation" system is sort of a DRM.
        It prevents you from copying your exe to another computer.
        As well as some anti-tampering and anti-debug.
        Modders need to be able to use the same version of an exe.
*/

#pragma once

// Set the hook for decrypting the .conceal segment.
void SetRevealhook(const size_t Address);

// Load an encrypted block to make the binary ignore the hardware.
bool GetEncryptedblock(const size_t Caller, struct Concealdata **Block);

// Handle the anti-debug and handle message exceptions from CEG.
void InstallTraphandler();
