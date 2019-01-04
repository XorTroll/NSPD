#include <iostream>
#include <switch.h>
#include <cstdio>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <functional>
#include <sys/stat.h>
#include <dirent.h>
#include "Process.hpp"
#include "Pack.hpp"
#include <unistd.h>
#include <cstdlib>
using namespace std;

FsStorage storage;

// Thanks Atmosphere

struct StackFrame {
    u64 fp;
    u64 lr;
};

struct AttachProcessInfo {
    u64 title_id;
    u64 process_id;
    char name[0xC];
    u32 flags;
    u64 user_exception_context_address;
};

struct AttachThreadInfo {
    u64 thread_id;
    u64 tls_address;
    u64 entrypoint;
};

enum class DebugExceptionType : u32 {
    UndefinedInstruction = 0,
    InstructionAbort = 1,
    DataAbort = 2,
    AlignmentFault = 3,
    DebuggerAttached = 4,
    BreakPoint = 5,
    UserBreak = 6,
    DebuggerBreak = 7,
    BadSvc = 8,
    UnknownNine = 9,
};

struct UndefinedInstructionInfo {
    u32 insn;
};

struct DataAbortInfo {
    u64 address;
};

struct AlignmentFaultInfo {
    u64 address;
};

struct UserBreakInfo {
    u64 break_reason;
    u64 address;
    u64 size;
};

struct BadSvcInfo {
    u32 id;
};

union SpecificExceptionInfo {
    UndefinedInstructionInfo undefined_instruction;
    DataAbortInfo data_abort;
    AlignmentFaultInfo alignment_fault;
    UserBreakInfo user_break;
    BadSvcInfo bad_svc;
    u64 raw;
};

struct ExceptionInfo {
    DebugExceptionType type;
    u64 address;
    SpecificExceptionInfo specific;
};


enum class DebugEventType : u32 {
    AttachProcess = 0,
    AttachThread = 1,
    ExitProcess = 2,
    ExitThread = 3,
    Exception = 4
};

union DebugInfo {
    AttachProcessInfo attach_process;
    AttachThreadInfo attach_thread;
    ExceptionInfo exception;
};

struct DebugEventInfo {
    DebugEventType type;
    u32 flags;
    u64 thread_id;
    union {
        DebugInfo info;
        u64 _[0x40/sizeof(u64)];
    };
};

namespace nspd
{
    enum class NCAType
    {
        Program,
        Meta,
        Control,
        LegalInfo,
        OfflineHtml,
        Data,
    };

    void Assert(string msg)
    {
        cout << msg << endl << "Press any key to exit.";
        while(true)
        {
            hidScanInput();
            u64 k = hidKeysDown(CONTROLLER_P1_AUTO);
            if(k) break;
            consoleUpdate(NULL);
        }
        consoleExit(NULL);
        ncmExit();
        nsExit();
        exit(0);
    }

    bool IsFile(string Path)
    {
        bool is = false;
        struct stat st;
        if(stat(Path.c_str(), &st) == 0) if(st.st_mode & S_IFREG) is = true;
        return is;
    }

    bool IsDirectory(string Path)
    {
        bool is = false;
        struct stat st;
        if(stat(Path.c_str(), &st) == 0) if(st.st_mode & S_IFDIR) is = true;
        return is;
    }

    void DeleteFile(std::string Path)
    {
        remove(Path.c_str());
    }

    void DeleteDirectory(std::string Path)
    {
        DIR *d = opendir(Path.c_str());
        if(d)
        {
            struct dirent *dent;
            while(true)
            {
                dent = readdir(d);
                if(dent == NULL) break;
                std::string nd = dent->d_name;
                std::string pd = Path + "/" + nd;
                if(IsFile(pd)) DeleteFile(pd);
                else DeleteDirectory(pd);
            }
        }
        closedir(d);
        rmdir(Path.c_str());
    }

    string GetExtension(string Path)
    {
        return Path.substr(Path.find_last_of(".") + 1);
    }

    std::string FormatApplicationId(u64 ApplicationId)
    {
        std::stringstream strm;
        strm << std::uppercase << std::setfill('0') << std::setw(16) << std::hex << ApplicationId;
        return strm.str();
    }

    NcmNcaId GetNCAIdFromString(std::string NCAId)
    {
        NcmNcaId nid = { 0 };
        char lower[17] = { 0 };
        char upper[17] = { 0 };
        memcpy(lower, NCAId.c_str(), 16);
        memcpy(upper, NCAId.c_str() + 16, 16);
        *(u64*)nid.c = __bswap64(strtoul(lower, NULL, 16));
        *(u64*)(nid.c + 0x8) = __bswap64(strtoul(upper, NULL, 16));
        return nid;
    }

    void ExportSDNCAToSdCard(NcmContentStorage *ncst, NcmNcaId NCAId, string Path, std::function<void(u8 P)> Cb)
    {
        u64 ncasize = 0;
        ncmContentStorageGetSize(ncst, &NCAId, &ncasize);
        u64 szrem = ncasize;
        FILE *f = fopen(Path.c_str(), "wb");
        u64 off = 0;
        while(szrem)
        {
            u64 rsize = std::min((u64)1048576, szrem);
            u8 *data = (u8*)malloc(sizeof(u8) * rsize);
            if(ncmContentStorageReadContentIdFile(ncst, &NCAId, off, data, rsize) != 0) break;
            fwrite(data, 1, rsize, f);
            szrem -= rsize;
            off += rsize;
            u8 perc = ((double)((double)off / (double)ncasize) * 100.0);
            Cb(perc);
            free(data);
        }
        fclose(f);
    }

    void CopyFileProgress(string Path, string To, std::function<void(u8 P)> Cb)
    {
        FILE *f = fopen(Path.c_str(), "rb");
        FILE *of = fopen(To.c_str(), "wb");
        fseek(f, 0, SEEK_END);
        u64 fsize = ftell(f);
        rewind(f);
        u64 szrem = fsize;
        u64 read = 0;
        while(szrem)
        {
            u64 rsize = std::min((u64)1048576, szrem);
            u8 *data = (u8*)malloc(sizeof(u8) * rsize);
            fread(data, 1, rsize, f);
            fwrite(data, 1, rsize, of);
            szrem -= rsize;
            read += rsize;
            u8 perc = ((double)((double)read / (double)fsize) * 100.0);
            Cb(perc);
            free(data);
        }
        fclose(of);
        fclose(f);
    }

    bool GetMetaRecord(NcmContentMetaDatabase *metadb, u64 ApplicationId, NcmMetaRecord *out)
    {
        size_t size = sizeof(NcmApplicationContentMetaKey) * 128;
        NcmApplicationContentMetaKey *metas = (NcmApplicationContentMetaKey*)malloc(size);
        u32 total = 0;
        u32 written = 0;
        bool got = false;
        Result rc = ncmContentMetaDatabaseListApplication(metadb, 0x80, metas, size, &written, &total);
        if(rc == 0) if(total > 0) for(u32 i = 0; i < total; i++) if(metas[i].metaRecord.titleId == ApplicationId)
        {
            *out = metas[i].metaRecord;
            got = true;
            break;
        }
        return got;
    }

    FsStorageId GetApplicationLocation(u64 ApplicationId)
    {
        FsStorageId stid = FsStorageId_None;
        NcmContentMetaDatabase cmdb;
        ncmOpenContentMetaDatabase(FsStorageId_SdCard, &cmdb);
        NcmMetaRecord rec;
        bool ok = GetMetaRecord(&cmdb, ApplicationId, &rec);
        if(ok) stid = FsStorageId_SdCard;
        else
        {
            serviceClose(&cmdb.s);
            ncmOpenContentMetaDatabase(FsStorageId_NandUser, &cmdb);
            NcmMetaRecord rec;
            bool ok = GetMetaRecord(&cmdb, ApplicationId, &rec);
            if(ok) stid = FsStorageId_NandUser;
        }
        serviceClose(&cmdb.s);
        return stid;
    }

    // Freezes and closes ES process to access its data. Returns it's launch flags to be used later.
    u32 FreezeES()
    {
        pmdmntInitialize();
        pmshellInitialize();
        u64 espid = 0;
        pmdmntGetTitlePid(&espid, 0x0100000000000033);
        Handle eshandle;
        svcDebugActiveProcess(&eshandle, espid);
        DebugEventInfo dev;
        svcGetDebugEvent((u8*)&dev, eshandle);
        svcCloseHandle(eshandle);
        u32 flags = dev.info.attach_process.flags & 0x1dd;
        pmshellTerminateProcessByTitleId(0x0100000000000033);
        return flags;
    }

    void ContinueES(u32 Flags)
    {
        u64 espid = 0;
        pmshellLaunchProcess(Flags, 0x0100000000000033, FsStorageId_NandSystem, &espid);
        if(espid == 0) Assert("Bad launch!");
        pmdmntExit();
        pmshellExit();
    }

    string GetTitleKeyAndExportTicket(u64 ApplicationId)
    {
        string tkey = "";
        string orid = "";
        string fappid = FormatApplicationId(ApplicationId);
        string outdir = "sdmc:/switch/nspd/" + fappid;
        FsFileSystem ess;
        Result rc = 0;
        do
        {
            rc = fsMount_SystemSaveData(&ess, 0x80000000000000e1);
        } while(rc != 0);
        fsdevMountDevice("escommon", ess);
        FILE *f = fopen("escommon:/ticket.bin", "rb");
        if(!f) Assert("Error opening ticket data in ES savedata.");
        fseek(f, 0, SEEK_END);
        u64 fsize = ftell(f);
        rewind(f);
        u64 szrem = fsize;
        u64 tmp = 0;
        while(szrem)
        {
            u8 *ticket = (u8*)malloc(0x400 * sizeof(u8));
            tmp = fread(ticket, 1, 0x400, f);
            szrem -= 0x400;
            stringstream stid;
            stringstream srid;
            for(u32 i = 0; i < 0x10; i++)
            {
                u32 off = 0x2a0 + i;
                srid << setw(2) << setfill('0') << hex << (int)ticket[off];
            }
            for(u32 i = 0; i < 0x8; i++)
            {
                u32 off = 0x2a0 + i;
                stid << setw(2) << setfill('0') << uppercase << hex << (int)ticket[off];
            }
            stringstream stkey;
            for(u32 i = 0; i < 0x10; i++)
            {
                u32 off = 0x180 + i;
                stkey << setw(2) << setfill('0') << uppercase << hex << (int)ticket[off];
            }
            string tid = stid.str();
            string rid = srid.str();
            string etkey = stkey.str();
            // We found the ticket, return the tkey and export the ticket
            if(fappid == tid)
            {
                orid = rid;
                FILE *tikf = fopen((outdir + "/" + rid + ".tik").c_str(), "wb");
                fwrite(ticket, 1, 0x400, tikf);
                fclose(tikf);
                tkey = etkey;
                free(ticket);
                break;
            }
            free(ticket);
        }
        fclose(f);
        fsdevUnmountDevice("escommon");
        // If we found a tkey export the cert too!
        if(tkey != "")
        {
            FsFileSystem css;
            rc = fsMount_SystemSaveData(&css, 0x80000000000000e0);
            if(rc != 0) Assert("Error mounting ES certificate savedata.");
            fsdevMountDevice("escert", css);
            FILE *c1 = fopen("escert:/certificate/CA00000003", "rb");
            if(!c1) Assert("Error opening first cert file.");
            FILE *ceout = fopen((outdir + "/" + orid + ".cert").c_str(), "wb");
            fseek(c1, 0, SEEK_END);
            u64 c1size = ftell(c1);
            rewind(c1);
            u8 *bc1 = (u8*)malloc(c1size * sizeof(u8));
            fread(bc1, 1, c1size, c1);
            fwrite(bc1, 1, c1size, ceout);
            fclose(c1);
            FILE *c2 = fopen("escert:/certificate/XS00000020", "rb");
            if(!c2) Assert("Error opening second cert file.");
            fseek(c2, 0, SEEK_END);
            u64 c2size = ftell(c2);
            rewind(c2);
            u8 *bc2 = (u8*)malloc(c2size * sizeof(u8));
            fread(bc2, 1, c2size, c2);
            fwrite(bc2, 1, c2size, ceout);
            fclose(c2);
            fclose(ceout);
            fsdevUnmountDevice("escert");
        }
        return tkey;
    }

    std::string GetStringFromNCAId(const NcmNcaId &NCAId)
    {
        char idstr[FS_MAX_PATH] = { 0 };
        u64 lower = __bswap64(*(u64*)NCAId.c);
        u64 upper = __bswap64(*(u64*)(NCAId.c + 0x8));
        snprintf(idstr, FS_MAX_PATH, "%016lx%016lx", lower, upper);
        return std::string(idstr);
    }

    std::string GetNCAIdPath(NcmContentStorage *st, NcmNcaId *Id)
    {
        char out[FS_MAX_PATH] = { 0 };
        Result rc = ncmContentStorageGetPath(st, Id, out, FS_MAX_PATH);
        string sst = "";
        if(rc == 0) sst = string(out);
        return sst;
    }

    bool GetNCAId(NcmContentMetaDatabase *cmdb, NcmMetaRecord *rec, u64 ApplicationId, NCAType Type, NcmNcaId *out)
    {
        NcmContentType ctype = NcmContentType_Program;
        switch(Type)
        {
            case NCAType::Program:
                ctype = NcmContentType_Program;
                break;
            case NCAType::Control:
                ctype = NcmContentType_Icon;
                break;
            case NCAType::Meta:
                ctype = NcmContentType_CNMT;
                break;
            case NCAType::LegalInfo:
                ctype = NcmContentType_Info;
                break;
            case NCAType::OfflineHtml:
                ctype = NcmContentType_Doc;
                break;
            case NCAType::Data:
                ctype = NcmContentType_Data;
                break;
        }
        Result rc = ncmContentMetaDatabaseGetContentIdByType(cmdb, ctype, rec, out);
        return (rc == 0);
    }

    bool IsTitleKeyEncrypted(string NCAPath)
    {
        int outfd = dup(STDOUT_FILENO);
        int errfd = dup(STDERR_FILENO);
        freopen("sdmc:/switch/nspd/temp/hactool_stdout.log", "w", stdout);
        freopen("sdmc:/switch/nspd/temp/hactool_stderr.log", "w", stderr);
        hactool::ProcessResult pr = hactool::Process(NCAPath, hactool::Extraction::MakeExeFs("sdmc:/switch/nspd/temp/tfs"), hactool::ExtractionFormat::NCA, "sdmc:/switch/nspd/prod.keys");
        fclose(stdout);
        fclose(stderr);
        dup2(outfd, STDOUT_FILENO);
        dup2(errfd, STDERR_FILENO);
        stdout = fdopen(STDOUT_FILENO, "w");
        stderr = fdopen(STDERR_FILENO, "w");
        close(outfd);
        close(errfd);
        if(!pr.Ok) return true;
        bool ex = IsDirectory("sdmc:/switch/nspd/temp/tfs");
        if(ex) DeleteDirectory("sdmc:/switch/nspd/temp/tfs");
        return !ex;
    }

    // Gets NACP data via ns commands and returns a name for a NSP: "<name> [<applicationid>][v<version>].nsp" (the version number is got from the meta record)
    string GetFormattedNSPName(NcmMetaRecord *Rec)
    {
        string name;
        NsApplicationControlData* cdata = (NsApplicationControlData*)malloc(sizeof(NsApplicationControlData));
        size_t csize = 0;
        Result rc = nsGetApplicationControlData(1, Rec->titleId, cdata, sizeof(NsApplicationControlData), &csize);
        if((rc == 0) && !(csize < sizeof(cdata->nacp)))
        {
            NacpLanguageEntry *lent;
            nacpGetLanguageEntry(&cdata->nacp, &lent);
            name = std::string(lent->name);
            name += " [";
            name += FormatApplicationId(Rec->titleId);
            name += "][v";
            name += to_string(Rec->version);
            name += "].nsp";
        }
        return name;
    }

    // The main function of the dump
    void ProcessTitle(u64 ApplicationId, FsStorageId Id)
    {
        // Create variables and directories
        string fappid = FormatApplicationId(ApplicationId);
        string outdir = "sdmc:/switch/nspd/" + fappid;
        DeleteDirectory(outdir);
        mkdir("sdmc:/switch", 777);
        mkdir("sdmc:/switch/nspd", 777);
        mkdir("sdmc:/switch/nspd/temp", 777);
        mkdir(outdir.c_str(), 777);

        // We will copy the NCAs, so we mount user NAND to later copy them
        if(Id == FsStorageId_NandUser)
        {
            FsFileSystem bisfs;
            Result rc = fsOpenBisFileSystem(&bisfs, 30, "");
            if(rc != 0) Assert("Error mounting NAND filesystem.");
            fsdevMountDevice("nspduser", bisfs);
        }

        // Check if there's a titlekey for the title, to later reencrypt it to stdcrypto if needed.
        u32 esflags = FreezeES();
        cout << "Checking for titlekeys..." << endl;
        consoleUpdate(NULL);
        string tkey = GetTitleKeyAndExportTicket(ApplicationId);
        bool istkey = (tkey != "");
        if(tkey == "") cout << "Unable to find a titlekey. The title could be stdcrypto (not using a titlekey)" << endl;
        else cout << "Titlekey found: '" << tkey << "'" << endl;
        cout << endl;
        consoleUpdate(NULL);
        ContinueES(esflags);

        // Initialize NCM content services
        NcmContentStorage cst;
        Result rc = ncmOpenContentStorage(Id, &cst);
        if(rc != 0) Assert("Error opening NCM content storage.");
        NcmContentMetaDatabase cmdb;
        rc = ncmOpenContentMetaDatabase(Id, &cmdb);
        if(rc != 0) Assert("Error opening NCM content meta database.");

        // Get the meta record of the title, to later retrieve all the NCAIds we can.
        NcmMetaRecord mrec;
        bool ok = GetMetaRecord(&cmdb, ApplicationId, &mrec);
        if(!ok) Assert("Error trying to get the meta record of the title.");
        cout << "Got meta record of the title." << endl;
        consoleUpdate(NULL);
        string nspn = GetFormattedNSPName(&mrec);
        cout << "Starting to search through system/SD contents..." << endl << endl;
        consoleUpdate(NULL);

        // We start getting the NCAIds: program, control and meta are required, the other two html NCAs are not always there
        NcmNcaId program;
        ok = GetNCAId(&cmdb, &mrec, ApplicationId, NCAType::Program, &program);
        if(!ok) Assert("Unable to get Program NCA. It's an essential part so the dump cannot continue.");
        string sprogram = GetNCAIdPath(&cst, &program);
        cout << "Program NCA:" << endl << "'" << sprogram << "'" << endl << endl;

        NcmNcaId meta;
        ok = GetNCAId(&cmdb, &mrec, ApplicationId, NCAType::Meta, &meta);
        if(!ok) Assert("Unable to get Meta CNMT NCA. It's an essential part so the dump cannot continue.");
        string smeta = GetNCAIdPath(&cst, &meta);
        cout << "Meta CNMT NCA:" << endl << "'" << smeta << "'" << endl << endl;

        NcmNcaId control;
        ok = GetNCAId(&cmdb, &mrec, ApplicationId, NCAType::Control, &control);
        if(!ok) Assert("Unable to get Control NCA. It's an essential part so the dump cannot continue.");
        string scontrol = GetNCAIdPath(&cst, &control);
        cout << "Control NCA:" << endl << "'" << scontrol << "'" << endl << endl;

        NcmNcaId linfo;
        ok = GetNCAId(&cmdb, &mrec, ApplicationId, NCAType::LegalInfo, &linfo);
        bool haslinfo = ok;
        string slinfo;
        if(!ok) cout << "Unable to get LegalInfo NCA. (this could not be present, so not an error)" << endl << endl;
        else
        {
            slinfo = GetNCAIdPath(&cst, &linfo);
            cout << "LegalInfo NCA:" << endl << "'" << slinfo << "'" << endl << endl;
        }

        NcmNcaId hoff;
        ok = GetNCAId(&cmdb, &mrec, ApplicationId, NCAType::OfflineHtml, &hoff);
        bool hashoff = ok;
        string shoff;
        if(!ok) cout << "Unable to get Offline Html NCA. (this could not be present, so not an error)" << endl << endl;
        else
        {
            shoff = GetNCAIdPath(&cst, &hoff);
            cout << "Offline Html NCA:" << endl << "'" << shoff << "'" << endl << endl;
        }
        string xprogram = sprogram;
        string xmeta = smeta;
        string xcontrol = scontrol;
        string xlinfo = slinfo;
        string xhoff = shoff;

        // If SD card, the NCAs are encrypted as NAX0 with the SD seed, but luckily we have NCM commands to read NCA data decrypted from that format (thank god)
        if(Id == FsStorageId_SdCard)
        {
            cout << "This is an SD card title, so the NCAs need to be decrypted from NAX0 format." << endl << "Exporting them..." << endl << endl;
            consoleUpdate(NULL);
            xprogram = outdir + "/" + GetStringFromNCAId(program) + ".nca";
            ExportSDNCAToSdCard(&cst, program, xprogram, [&](u8 p)
            {
                cout << "Decrypting and exporting Program NCA... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            cout << endl << endl;
            xmeta = outdir + "/" + GetStringFromNCAId(meta) + ".cnmt.nca";
            ExportSDNCAToSdCard(&cst, meta, xmeta, [&](u8 p)
            {
                cout << "Decrypting and exporting Meta CNMT NCA... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            cout << endl << endl;
            xcontrol = outdir + "/" + GetStringFromNCAId(control) + ".nca";
            ExportSDNCAToSdCard(&cst, control, xcontrol, [&](u8 p)
            {
                cout << "Decrypting and exporting Control NCA... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            cout << endl << endl;
            if(haslinfo)
            {
                xlinfo = outdir + "/" + GetStringFromNCAId(linfo) + ".nca";
                ExportSDNCAToSdCard(&cst, linfo, xlinfo, [&](u8 p)
                {
                    cout << "Decrypting and exporting LegalInfo NCA... (" << to_string(p) << "%)\r";
                    consoleUpdate(NULL);
                });
                cout << endl << endl;
            }
            else cout << "LegalInfo NCA is not present..." << endl << endl;
            if(hashoff)
            {
                xhoff = outdir + "/" + GetStringFromNCAId(hoff) + ".nca";
                ExportSDNCAToSdCard(&cst, hoff, xhoff, [&](u8 p)
                {
                    cout << "Decrypting and exporting Offline Html NCA... (" << to_string(p) << "%)\r";
                    consoleUpdate(NULL);
                });
                cout << endl << endl;
            }
            else cout << "Offline Html NCA is not present..." << endl << endl;
        }
        // If NAND, we simply copy the NCAs to the SD card.
        if(Id == FsStorageId_NandUser)
        {
            xprogram = "nspduser:/Contents/" + xprogram.substr(15);
            string txprogram = outdir + "/" + GetStringFromNCAId(program) + ".nca";
            CopyFileProgress(xprogram, txprogram, [&](u8 p)
            {
                cout << "Copying Program NCA from NAND memory... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            xprogram = txprogram;
            cout << endl << endl;
            xmeta = "nspduser:/Contents/" + xmeta.substr(15);
            string txmeta = outdir + "/" + GetStringFromNCAId(meta) + ".cnmt.nca";
            CopyFileProgress(xmeta, txmeta, [&](u8 p)
            {
                cout << "Copying Meta CNMT NCA from NAND memory... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            xmeta = txmeta;
            cout << endl << endl;
            xcontrol = "nspduser:/Contents/" + xcontrol.substr(15);
            string txcontrol = outdir + "/" + GetStringFromNCAId(control) + ".nca";
            CopyFileProgress(xcontrol, txcontrol, [&](u8 p)
            {
                cout << "Copying Control NCA from NAND memory... (" << to_string(p) << "%)\r";
                consoleUpdate(NULL);
            });
            xcontrol = txcontrol;
            cout << endl << endl;
            if(haslinfo)
            {
                xlinfo = "nspduser:/Contents/" + xlinfo.substr(15);
                string txlinfo = outdir + "/" + GetStringFromNCAId(linfo) + ".nca";
                CopyFileProgress(xlinfo, txlinfo, [&](u8 p)
                {
                    cout << "Copying LegalInfo NCA from NAND memory... (" << to_string(p) << "%)\r";
                    consoleUpdate(NULL);
                });
                xlinfo = txlinfo;
                cout << endl << endl;
            }
            else cout << "LegalInfo NCA is not present..." << endl << endl;
            if(hashoff)
            {
                xhoff = "nspduser:/Contents/" + xhoff.substr(15);
                string txhoff = outdir + "/" + GetStringFromNCAId(hoff) + ".nca";
                CopyFileProgress(xhoff, txhoff, [&](u8 p)
                {
                    cout << "Copying Offline Html NCA from NAND memory... (" << to_string(p) << "%)\r";
                    consoleUpdate(NULL);
                });
                xhoff = txhoff;
                cout << endl << endl;
            }
            else cout << "Offline Html NCA is not present..." << endl << endl;
        }
        // Over here, we could assume that if we didn't find a titlekey, the title isn't titlekey encrypted.
        // Anyway, to ensure a good extraction is done, we perform a test with hactool to see if the NCA could be "decryptable" without the titlekey.
        bool istkey2 = IsTitleKeyEncrypted(xprogram);
        if(istkey)
        {
            // We found a titlekey...
            if(istkey2)
            {
                // ...and the title cannot be decrypted, so it probably needs the tkey.
                // Previously (when we got the tkey) we also dumped the tik and cert files, so it should be buildable.
                cout << "The title is titlekey encrypted. The NSP will contain a ticket and a cert." << endl << endl;
            }
            else
            {
                // ...and the NCA is decryptable, maybe the titlekey is just leftovers from a past install. Anyway, we don't need it anymore.
                cout << "The title doesn't seem to require a titlekey, but the ticket and the cert will be included anyway." << endl << endl;
            }
        }
        else
        {
            // We didn't find a titlekey...
            if(istkey2)
            {
                // ...but the title doesn't seem decryptable without it. The export can be continued, but won't work without the ticket on other consoles.
                cout << "The title requires a titlekey but it was not found." << endl << "The NSP will be created, but it won't be playable without the required ticket." << endl << endl;
            }
            else
            {
                // ...and the NCA is decryptable, so it must be stdcrypto.
                cout << "The title doesn't need a titlekey, so the rest will be really easy." << endl << endl;
            }
        }
        consoleUpdate(NULL);
        cout << "Building the final NSP..." << endl;
        consoleUpdate(NULL);
        int outfd = dup(STDOUT_FILENO);
        int errfd = dup(STDERR_FILENO);
        freopen("sdmc:/switch/nspd/temp/hacpack_stdout.log", "w", stdout);
        freopen("sdmc:/switch/nspd/temp/hacpack_stderr.log", "w", stderr);
        ok = hacpack::Process("sdmc:/switch/nspd/out", hacpack::Build::MakeNSP(ApplicationId, outdir), hacpack::PackageFormat::NSP, "sdmc:/switch/nspd/prod.keys");
        if(!ok) Assert("Error building the final NSP.");
        fclose(stdout);
        fclose(stderr);
        dup2(outfd, STDOUT_FILENO);
        dup2(errfd, STDERR_FILENO);
        stdout = fdopen(STDOUT_FILENO, "w");
        stderr = fdopen(STDERR_FILENO, "w");
        close(outfd);
        close(errfd);
        cout << "You can find the NSP at:" << endl << "'";
        int ren = rename(("sdmc:/switch/nspd/out/" + fappid + ".nsp").c_str(), (outdir + "/" + nspn).c_str());
        if(ren != 0) cout << "sdmc:/switch/nspd/out/" << fappid << ".nsp";
        else cout << outdir << "/" << nspn;
        cout << "'" << endl << endl;
        cout << "The dump has finished! Doing a quick cleanup..." << endl << endl;
        if(ren == 0) DeleteDirectory("sdmc:/switch/nspd/out");
        DeleteDirectory("sdmc:/switch/nspd/temp");
        serviceClose(&cst.s);
        serviceClose(&cmdb.s);
    }
}

int main()
{
    // Manually change heap to use swkbd correctly
    void *haddr;
    svcSetHeapSize(&haddr, 0x10000000);

    // Initialize services
    consoleInit(NULL);
    ncmInitialize();
    nsInitialize();

    // Check for required keys
    if(!nspd::IsFile("sdmc:/switch/nspd/prod.keys")) nspd::Assert("Key file was not found.\nPlace it at 'sdmc:/switch/nspd/prod.keys'.");

    // Load swkbd to choose an application id
    std::string out = "";
    char tmpout[FS_MAX_PATH] = { 0 };
    SwkbdConfig kbd;
    Result rc = swkbdCreate(&kbd, 0);
    if(rc == 0)
    {
        swkbdConfigMakePresetDefault(&kbd);
        swkbdConfigSetGuideText(&kbd, "Application Id (e.g. 0100000000010000 for SMO)");
        rc = swkbdShow(&kbd, tmpout, sizeof(tmpout));
        if(rc == 0) out = std::string(tmpout);
    }
    swkbdClose(&kbd);
    if(out == "") nspd::Assert("");
    u64 appid = strtoull(out.c_str(), NULL, 16);
    if(appid == 0) nspd::Assert("Invalid Application Id.");

    // Get the location of the title
    FsStorageId stid = nspd::GetApplicationLocation(appid);
    cout << "Starting to process title " << out << "... " ;
    if(stid == FsStorageId_SdCard) cout << "(location: SD card)" << endl;
    else if(stid == FsStorageId_NandUser) cout << "(location: NAND)" << endl;
    else nspd::Assert("Title's location was not found. Are you sure this title is installed?");

    // Aaaaaaaaaand... let the dump begin!
    nspd::ProcessTitle(appid, stid);

    // Dump done, wait for input, then finalize services and exit.
    cout << "Title was successfully processed. Press any key to exit." << endl;
    while(true)
    {
        hidScanInput();
        u64 k = hidKeysDown(CONTROLLER_P1_AUTO);
        if(k) break;
        consoleUpdate(NULL);
    }
    nsExit();
    ncmExit();
    consoleExit(NULL);
    return 0;
}