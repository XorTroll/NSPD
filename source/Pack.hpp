
/*

    Goldleaf - Nintendo Switch title manager homebrew

    Copyright © 2018 - Goldleaf project, developed by XorTroll
    This project is under the terms of GPLv3 license: https://github.com/XorTroll/Goldleaf/blob/master/LICENSE

    Code ported from SciresM's source

*/

#pragma once
#include <string>
#include <switch.h>
using namespace std;

namespace hacpack
{
    extern "C"
    {
        #include <pack/nca.h>
        #include <pack/utils.h>
        #include <pack/settings.h>
        #include <pack/pki.h>
        #include <pack/extkeys.h>
        #include <pack/version.h>
        #include <pack/nacp.h>
        #include <pack/npdm.h>
        #include <pack/pfs0.h>
    }

    enum class PackageFormat
    {
        NCA,
        NSP,
    };

    enum class NCAType
    {
        Program,
        Meta,
        Control,
        Manual,
        Data,
        AOCData,
    };

    struct Build
    {
        NCAType NCA;
        bool NSP;
        u64 ApplicationId;

        string ExeFs;
        string RomFs;
        string Logo;

        string MProgramNCA;
        string MControlNCA;
        string MLegalInfoNCA;
        string MOfflineHtmlNCA;

        string NCADir;

        static Build MakeProgramNCA(u64 ApplicationId, string ExeFs, string RomFs, string Logo);
        static Build MakeControlNCA(u64 ApplicationId, string ControlFs);
        static Build MakeManualNCA(u64 ApplicationId, string HtmlFs);
        static Build MakeMetaNCA(u64 ApplicationId, string Program, string Control, string LegalInfo, string OfflineHtml);
        static Build MakeNSP(u64 ApplicationId, string NCADir);
    };

    bool Process(std::string Output, Build Mode, PackageFormat Format, std::string KeyFile);
}