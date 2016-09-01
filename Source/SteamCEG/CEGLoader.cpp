/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: LGPL 3.0
    Started: 2016-8-31
    Notes:
        Loads all configuration-files from ./Plugins/Integrity/
*/

#include <Configuration\All.h>
#include <Utility\All.h>
#include "SteamCEG.h"
#include <json.hpp>
#include <base64.h>
#include <memory>

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

// Block storage with global access.
std::vector<Concealdata> Concealedblocks;
bool GetEncryptedblock(const size_t Caller, struct Concealdata **Block)
{
    for (auto Iterator = Concealedblocks.begin(); Iterator != Concealedblocks.end(); ++Iterator)
    {
        // Identify by the return address.
        if (Iterator->Returnaddress == Caller)
        {
            *Block = &(*Iterator);
            return true;
        }
    }

    return false;
}

// Load all files on initialization.
struct CEGLoader
{
    CEGLoader()
    {
        std::vector<std::string> CEGPatches;
        Filesystem::Searchdir("./Plugins/Integrity/", &CEGPatches, "CEG");

        for each (auto Config in CEGPatches)
        {
            std::string Configurationfile;
            if (Filesystem::Readfile((std::string("./Plugins/Integrity/" + Config).c_str()), &Configurationfile))
            {
                try
                {
                    nlohmann::json Reader;
                    Reader = nlohmann::json::parse(Configurationfile);

                    // Verify that this is the correct exe-version.
                    std::vector<uint64_t> Signature = Reader["Signature"];
                    if (*(uint64_t *)Signature[0] != Signature[1]) continue;

                    // Get the revealhook.
                    SetRevealhook(Reader["Revealhookaddress"]);

                    // Get jump patches.
                    std::vector<nlohmann::json> Jumps = Reader["Jumps"];
                    for each (auto Jump in Jumps)
                    {
                        std::vector<uint64_t> Addresses = Jump;
                        Insertjump(Addresses[0], Addresses[1]);
                    }

                    // Get call patches.
                    std::vector<nlohmann::json> Calls = Reader["Calls"];
                    for each (auto Call in Calls)
                    {
                        std::vector<uint64_t> Addresses = Call;
                        Insertcall(Addresses[0], Addresses[1]);
                    }

                    // Get 'mov eax' patches.
                    std::vector<nlohmann::json> Moves = Reader["Moves"];
                    for each (auto Mov in Moves)
                    {
                        std::vector<uint64_t> Addresses = Mov;
                        Insertmov(Addresses[0], Addresses[1]);
                    }

                    // Get the replacement patterns.
                    std::vector<nlohmann::json> Patternreplace = Reader["Patternreplace"];
                    for each (auto Pattern in Patternreplace)
                    {
                        int64_t Offset = Pattern["Offset"];
                        std::string Data;  Base64::Decode(Pattern["Data"], &Data);
                        auto Results = FindpatternFormatMultiple(Pattern["Pattern"]);

                        for each (auto Result in Results)
                        {
                            auto Protection = Unprotectrange((void *)Result, Data.size());
                            {
                                std::memcpy((void *)(Result + Offset), Data.data(), Data.size());
                            }
                            Protectrange((void *)Result, Data.size(), Protection);
                        }
                    }

                    // Get the encrypted blocks.
                    std::vector<nlohmann::json> Blocks = Reader["Concealblocks"];
                    for each (auto Block in Blocks)
                    {
                        Concealdata Data;
                        std::string JSONString;
                        JSONString = Block.dump();
                        Data.Deserialize(JSONString);
                        if (Data.Parsed)
                            Concealedblocks.push_back(Data);
                    }
                }
                catch (std::exception &e)
                {
                    DebugPrint(va("%s failed to parse \"%s\" for reason: %s", __func__, Config.c_str(), e.what()));
                };
            }
        }
    }
};
static CEGLoader Loader;
