#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

// ─── Device config ────────────────────────────────────────────────
#define NACON_VID 0x3285
#define NACON_PID 0x0644

// ─── UI constants ─────────────────────────────────────────────────
constexpr int   UI_W         = 80;
constexpr int   UI_H         = 24;
constexpr int   HEX_COLS     = 16;
constexpr int   HEX_ROWS     = 3;
constexpr int   SNIFFER_ROWS = 5;
constexpr int   BAR_LEN      = 5;
constexpr DWORD MAX_HID_REQ  = 4096;
constexpr DWORD PKT_MAX      = 256;

// Polling period for GetInputReport (~125 Hz)
constexpr DWORD POLL_MS = 8;

enum CC : WORD {
    CC_BLK=0, CC_DGRN=2, CC_DGRY=8, CC_GRN=10,
    CC_CYN=11, CC_RED=12, CC_YEL=14, CC_WHT=15, CC_GRY=7
};

static HANDLE hCon   = INVALID_HANDLE_VALUE;
static HANDLE hConIn = INVALID_HANDLE_VALUE;
static FILE*  gLog   = nullptr;
static FILE*  gErr   = nullptr;

// ─── Logging ──────────────────────────────────────────────────────
void logOpen(){
    fopen_s(&gLog,"sniffer.log","w");
    fopen_s(&gErr,"error.log","w");
    if(gLog){ fprintf(gLog,"=== sniffer.log ===\n\n"); fflush(gLog); }
    if(gErr){ fprintf(gErr,"=== error.log ===\n\n");   fflush(gErr); }
}
void logLine(const char* fmt,...){
    if(!gLog) return;
    va_list a; va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a);
    fputc('\n',gLog); fflush(gLog);
}
void logErr(const char* fmt,...){
    va_list a;
    if(gErr){ va_start(a,fmt); vfprintf(gErr,fmt,a); va_end(a); fputc('\n',gErr); fflush(gErr); }
    if(gLog){ fprintf(gLog,"[ERR] "); va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a); fputc('\n',gLog); fflush(gLog); }
}
void logClose(){
    if(gLog){ fclose(gLog); gLog=nullptr; }
    if(gErr){ fclose(gErr); gErr=nullptr; }
}

// ─── Shared buffer (read thread → main thread) ────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX] = {};
    DWORD size           = 0;
    bool  ready          = false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console output ───────────────────────────────────────────────
inline void cWrite(const char* s){
    DWORD n=(DWORD)strlen(s); WriteConsoleA(hCon,s,n,&n,NULL);
}
void cXY(int x,int y){ COORD c={(SHORT)x,(SHORT)y}; SetConsoleCursorPosition(hCon,c); }
void cCol(CC f,CC b=CC_BLK){ SetConsoleTextAttribute(hCon,(WORD)((b<<4)|f)); }
void cPr(int x,int y,const char* s,CC f=CC_GRY,CC b=CC_BLK){
    cXY(x,y); cCol(f,b); cWrite(s);
}
void uiInit(){
    hCon  =GetStdHandle(STD_OUTPUT_HANDLE);
    hConIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0; GetConsoleMode(hConIn,&mode);
    mode &= ~ENABLE_QUICK_EDIT_MODE; mode |= ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(hConIn,mode);
    CONSOLE_CURSOR_INFO ci={1,FALSE}; SetConsoleCursorInfo(hCon,&ci);
    COORD sz={(SHORT)UI_W,(SHORT)UI_H}; SetConsoleScreenBufferSize(hCon,sz);
    SMALL_RECT wr={0,0,(SHORT)(UI_W-1),(SHORT)(UI_H-1)};
    SetConsoleWindowInfo(hCon,TRUE,&wr);
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge");
    DWORD w; COORD o={0,0};
    FillConsoleOutputCharacterA(hCon,' ',UI_W*UI_H,o,&w);
    FillConsoleOutputAttribute(hCon,CC_GRY,UI_W*UI_H,o,&w);
}
void uiRestore(){
    CONSOLE_CURSOR_INFO ci={10,TRUE}; SetConsoleCursorInfo(hCon,&ci);
    SetConsoleTextAttribute(hCon,CC_GRY); cXY(0,23); cWrite("\n");
}

static const char* SEP="--------------------------------------------------------------------------------";
void uiFrame(){
    cPr(0,0,"  NACON MG-X",CC_CYN);  cPr(12,0," -> ",CC_DGRY);
    cPr(16,0,"XBOX 360 BRIDGE",CC_GRN);
    cPr(0,1,SEP,CC_DGRY);
    cPr(1,2,"ViGEm:",CC_DGRY); cPr(18,2,"Nacon:",CC_DGRY);
    cPr(35,2,"Xbox:",CC_DGRY); cPr(50,2,"Size:",CC_DGRY); cPr(64,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY);    cPr(11,4,"LB",CC_DGRY);
    cPr(34,4,"BACK",CC_DGRY);   cPr(42,4,"GUIDE",CC_DGRY);
    cPr(51,4,"START",CC_DGRY);  cPr(62,4,"RB",CC_DGRY); cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY);  cPr(24,6,"L-STICK:",CC_DGRY); cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY);  cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY);
    cPr(0,10,"  RAW HID:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY); cPr(0,15,"  SNIFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL);      cPr(4,22," snifer on/off",CC_DGRY);
    cPr(20,22,"[ESC]",CC_YEL);   cPr(25,22," exit",CC_DGRY);
    cPr(38,22,"log->",CC_DGRY);  cPr(43,22,"sniffer.log",CC_YEL);
}
void uiBtn(int x,int y,const char* l,bool on){
    cXY(x,y); cCol(CC_DGRY); cWrite("[");
    cCol(on?CC_GRN:CC_DGRY); cWrite(l); cCol(CC_DGRY); cWrite("]");
}
void uiBar(int x,int y,BYTE v){
    int f=v*BAR_LEN/255; char s[BAR_LEN+3]={}; s[0]='[';
    for(int i=0;i<BAR_LEN;i++) s[i+1]=(i<f)?'#':'.';
    s[BAR_LEN+1]=']'; s[BAR_LEN+2]='\0';
    cXY(x,y); cCol(v>10?CC_GRN:CC_DGRY); cWrite(s);
}
void uiAxis(int x,int y,SHORT v){
    char b[7]; snprintf(b,sizeof(b),"%+05d",(int)v);
    cPr(x,y,b,v!=0?CC_YEL:CC_DGRY);
}
void uiMsg(const char* s,CC fg=CC_YEL){
    char pad[82]={}; snprintf(pad,81,"  %-76s",s); cPr(0,23,pad,fg);
}
void uiClearMsg(){
    char pad[82]; memset(pad,' ',80); pad[80]='\0'; cPr(0,23,pad,CC_BLK);
}
void uiStatus(bool vig,bool nac,bool xbx,DWORD sz,DWORD pkts){
    cPr(7,2,  vig?"[ON] ":"[--] ", vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ", nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ", xbx?CC_GRN:CC_RED);
    char tmp[20];
    snprintf(tmp,sizeof(tmp),"%-4lu",sz);   cPr(55,2,tmp,CC_YEL);
    snprintf(tmp,sizeof(tmp),"%-9lu",pkts); cPr(69,2,tmp,CC_DGRY);
}
void uiGamepad(const XUSB_REPORT& r){
    uiBar(4,4, r.bLeftTrigger); uiBar(70,4, r.bRightTrigger);
    uiBtn(13,4,"LB",(r.wButtons&XUSB_GAMEPAD_LEFT_SHOULDER)!=0);
    uiBtn(64,4,"RB",(r.wButtons&XUSB_GAMEPAD_RIGHT_SHOULDER)!=0);
    uiBtn(38,4,"<<",(r.wButtons&XUSB_GAMEPAD_BACK)!=0);
    uiBtn(47,4,"()",(r.wButtons&XUSB_GAMEPAD_GUIDE)!=0);
    uiBtn(56,4,">>",(r.wButtons&XUSB_GAMEPAD_START)!=0);
    uiBtn(7,6,"^",(r.wButtons&XUSB_GAMEPAD_DPAD_UP)!=0);
    uiBtn(10,6,"v",(r.wButtons&XUSB_GAMEPAD_DPAD_DOWN)!=0);
    uiBtn(13,6,"<",(r.wButtons&XUSB_GAMEPAD_DPAD_LEFT)!=0);
    uiBtn(16,6,">",(r.wButtons&XUSB_GAMEPAD_DPAD_RIGHT)!=0);
    uiAxis(32,6,r.sThumbLX); uiAxis(38,6,r.sThumbLY);
    uiAxis(54,6,r.sThumbRX); uiAxis(60,6,r.sThumbRY);
    uiBtn(7,8,"Y",(r.wButtons&XUSB_GAMEPAD_Y)!=0);
    uiBtn(11,8,"X",(r.wButtons&XUSB_GAMEPAD_X)!=0);
    uiBtn(15,8,"B",(r.wButtons&XUSB_GAMEPAD_B)!=0);
    uiBtn(19,8,"A",(r.wButtons&XUSB_GAMEPAD_A)!=0);
    uiBtn(49,8,"L3",(r.wButtons&XUSB_GAMEPAD_LEFT_THUMB)!=0);
    uiBtn(55,8,"R3",(r.wButtons&XUSB_GAMEPAD_RIGHT_THUMB)!=0);
}
void uiRawBytes(const BYTE* buf,DWORD sz){
    char tmp[4];
    for(int row=0;row<HEX_ROWS;row++){
        cXY(0,11+row);
        DWORD start=(DWORD)(row*HEX_COLS), drawn=0;
        for(DWORD col=0; col<(DWORD)HEX_COLS && start+col<sz; col++,drawn++){
            BYTE b=buf[start+col]; cCol(b?CC_YEL:CC_DGRY);
            snprintf(tmp,sizeof(tmp),"%02X ",b); cWrite(tmp);
        }
        cCol(CC_DGRY);
        for(DWORD i=drawn; i<(DWORD)HEX_COLS; i++) cWrite("   ");
    }
}
static char snLines[SNIFFER_ROWS][UI_W+2] = {};
static int  snHead = 0;
void uiSnifferAdd(const char* line){
    strncpy_s(snLines[snHead],UI_W+1,line,UI_W);
    snHead=(snHead+1)%SNIFFER_ROWS;
    char pad[UI_W+2];
    for(int i=0;i<SNIFFER_ROWS;i++){
        int idx=(snHead+i)%SNIFFER_ROWS;
        snprintf(pad,sizeof(pad),"%-*s",UI_W,snLines[idx]);
        cPr(0,16+i,pad,snLines[idx][0]?CC_YEL:CC_DGRY);
    }
}
void uiSnifferState(bool on){
    cPr(9,15,on?"[ON] ":"[OFF]",on?CC_GRN:CC_RED);
}

// ─── Delta sniffer ────────────────────────────────────────────────
void SnifferDelta(const std::vector<BYTE>& cur, std::vector<BYTE>& prev,
                  DWORD sz, DWORD pktNum, bool show){
    DWORD m=(DWORD)min((size_t)sz, min(cur.size(), prev.size()));
    char line[UI_W+2]={}; int pos=0;
    for(DWORD i=0; i<m && pos<UI_W-12; i++){
        if(cur[i]!=prev[i]){
            int n=snprintf(line+pos, UI_W-pos, "B%lu:%02X->%02X  ", i, prev[i], cur[i]);
            if(n>0) pos+=n;
        }
    }
    if(pos>0){
        if(show) uiSnifferAdd(line);
        logLine("PKT%-6lu  %s", pktNum, line);
    }
    prev=cur;
}

// ─── RAII handle ─────────────────────────────────────────────────
struct HG {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE) : h(h_) {}
    ~HG(){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
    HG(const HG&)=delete; HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){
        if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); h=nh;
    }
    operator HANDLE() const { return h; }
    bool valid() const { return h!=INVALID_HANDLE_VALUE; }
};

// ─────────────────────────────────────────────────────────────────
//  FindBestNaconInterface
//
//  Перебирает ВСЕ HID-интерфейсы (логирует каждый).
//  Приоритет: UsagePage=0x01 Usage=0x04/0x05 (стандартный геймпад).
//  Fallback:  наибольший InputReportByteLength среди VID/PID-совпадений.
//
//  Возвращает путь устройства и размер пакета.
// ─────────────────────────────────────────────────────────────────
bool FindBestNaconInterface(char* outPath, size_t pathMax, DWORD* outSize){
    GUID hidGuid; HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi = SetupDiGetClassDevs(&hidGuid,NULL,NULL,
                                        DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
    if(hdi==INVALID_HANDLE_VALUE){
        logErr("SetupDiGetClassDevs failed: %lu", GetLastError());
        return false;
    }

    SP_DEVICE_INTERFACE_DATA did={}; did.cbSize=sizeof(did);
    bool  foundGP  = false;
    DWORD bestSize = 0;
    bool  found    = false;

    logLine("--- HID interface scan ---");
    for(int i=0; SetupDiEnumDeviceInterfaces(hdi,NULL,&hidGuid,i,&did); i++){
        DWORD req=0;
        SetupDiGetDeviceInterfaceDetail(hdi,&did,NULL,0,&req,NULL);
        if(req==0||req>MAX_HID_REQ) continue;

        std::vector<BYTE> buf(req);
        auto* det=reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if(!SetupDiGetDeviceInterfaceDetail(hdi,&did,det,req,NULL,NULL)) continue;

        // access=0: атрибуты без захвата устройства
        HANDLE ht=CreateFile(det->DevicePath,0,
                             FILE_SHARE_READ|FILE_SHARE_WRITE,
                             NULL,OPEN_EXISTING,0,NULL);
        if(ht==INVALID_HANDLE_VALUE) continue;

        HIDD_ATTRIBUTES attr={sizeof(attr)};
        if(!HidD_GetAttributes(ht,&attr)){ CloseHandle(ht); continue; }

        WORD  usagePage=0, usage=0;
        DWORD inLen=0;
        PHIDP_PREPARSED_DATA ppd=nullptr;
        if(HidD_GetPreparsedData(ht,&ppd)){
            HIDP_CAPS caps={};
            if(HidP_GetCaps(ppd,&caps)==HIDP_STATUS_SUCCESS){
                usagePage=caps.UsagePage; usage=caps.Usage;
                inLen=caps.InputReportByteLength;
            }
            HidD_FreePreparsedData(ppd);
        }

        // Логируем все устройства — помогает при отладке
        logLine("  [%d] VID=%04X PID=%04X Page=%02X Use=%02X InLen=%u",
                i, attr.VendorID, attr.ProductID, usagePage, usage, inLen);

        bool match=(attr.VendorID==NACON_VID && attr.ProductID==NACON_PID);
        if(match){
            bool isGP=(usagePage==0x01 && (usage==0x04 || usage==0x05));
            if(isGP && !foundGP){
                logLine("  ^-- GAMEPAD interface selected");
                strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);
                bestSize=inLen; foundGP=true; found=true;
            } else if(!foundGP && inLen>bestSize){
                logLine("  ^-- fallback (InLen=%u Usage=0x%02X)", inLen, usage);
                strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);
                bestSize=inLen; found=true;
            }
        }
        CloseHandle(ht);
        if(foundGP) break; // лучшего не найти
    }
    SetupDiDestroyDeviceInfoList(hdi);
    logLine("--- scan done: found=%d size=%lu ---", (int)found, bestSize);
    if(outSize) *outSize=bestSize;
    return found;
}

// ─────────────────────────────────────────────────────────────────
//  OpenNacon
//
//  Открывает СИНХРОННЫЙ хэндл (без FILE_FLAG_OVERLAPPED).
//  Это принципиально: HidD_GetInputReport работает только
//  на синхронных хэндлах. Usage=0x00 устройства (как Nacon MG-X
//  в Android-режиме) не шлют interrupt-reports сами по себе —
//  они отвечают только на явный GET_INPUT_REPORT запрос.
//  ReadFile на таком хэндле блокируется навечно.
// ─────────────────────────────────────────────────────────────────
HANDLE OpenNacon(const char* path){
    // Пробуем READ+WRITE сначала (нужно для SetOutputReport wake-up)
    HANDLE h=CreateFile(path,
                        GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE){
        logErr("CreateFile RW sync failed (%lu), trying READ-only", GetLastError());
        h=CreateFile(path,
                     GENERIC_READ,
                     FILE_SHARE_READ|FILE_SHARE_WRITE,
                     NULL,OPEN_EXISTING,0,NULL);
        if(h==INVALID_HANDLE_VALUE){
            logErr("CreateFile READ sync failed: %lu", GetLastError());
            return INVALID_HANDLE_VALUE;
        }
        logLine("Opened READ-only sync");
    } else {
        logLine("Opened READ+WRITE sync");
    }
    HidD_SetNumInputBuffers(h,64);
    return h;
}

// ─────────────────────────────────────────────────────────────────
//  TrySendWakeup
//
//  Android/MFi контроллеры часто молчат до получения
//  инициализирующего output/feature report.
//  Пробуем 4 варианта — результат идёт в лог.
// ─────────────────────────────────────────────────────────────────
void TrySendWakeup(HANDLE hDev, DWORD pktSize){
    logLine("-- Wake-up sequence --");
    std::vector<BYTE> w(pktSize,0);

    w[0]=0x00;
    BOOL ok=HidD_SetOutputReport(hDev,w.data(),pktSize);
    logLine("  SetOutputReport ID=0x00: %s err=%lu", ok?"OK":"fail", ok?0:GetLastError());

    memset(w.data(),0,pktSize); w[0]=0x00;
    ok=HidD_SetFeature(hDev,w.data(),pktSize);
    logLine("  SetFeature      ID=0x00: %s err=%lu", ok?"OK":"fail", ok?0:GetLastError());

    memset(w.data(),0,pktSize); w[0]=0x01;
    ok=HidD_SetOutputReport(hDev,w.data(),pktSize);
    logLine("  SetOutputReport ID=0x01: %s err=%lu", ok?"OK":"fail", ok?0:GetLastError());

    memset(w.data(),0,pktSize); w[0]=0x02;
    ok=HidD_SetFeature(hDev,w.data(),pktSize);
    logLine("  SetFeature      ID=0x02: %s err=%lu", ok?"OK":"fail", ok?0:GetLastError());

    Sleep(50); // устройству нужно время отреагировать
}

// ─────────────────────────────────────────────────────────────────
//  ProbeReportID
//
//  Перебирает Report ID для HidD_GetInputReport.
//  Usage=0x00 устройства часто используют ID=0x00 или 0x01.
//  Возвращает первый ID который дал непустой ответ.
//  Возвращает 0xFF если ни один не сработал.
// ─────────────────────────────────────────────────────────────────
BYTE ProbeReportID(HANDLE hDev, DWORD pktSize){
    logLine("-- Probing Report IDs --");
    static const BYTE ids[] = {0x00, 0x01, 0x02, 0x03, 0x10, 0x20};
    std::vector<BYTE> buf(pktSize,0);

    for(BYTE id : ids){
        memset(buf.data(),0,pktSize);
        buf[0]=id;
        BOOL ok=HidD_GetInputReport(hDev,buf.data(),pktSize);
        DWORD err=GetLastError();
        logLine("  ID=0x%02X: ok=%d err=%lu", id, (int)ok, ok?0:err);

        if(ok){
            bool nonZero=false;
            for(DWORD j=1; j<pktSize; j++)
                if(buf[j]){ nonZero=true; break; }
            if(nonZero){
                logLine("  ^-- ID 0x%02X WORKS (has data)", id);
                return id;
            }
            logLine("  ^-- ID 0x%02X returned all-zeros (skipped)", id);
        }
    }
    logLine("  No working Report ID found");
    return 0xFF;
}

// ─────────────────────────────────────────────────────────────────
//  ReadThread
//
//  Шаги при старте:
//    1. Wake-up (SetOutputReport/SetFeature)
//    2. Probe Report IDs для GetInputReport
//    3a. GetInputReport polling @ ~125 Hz  — если нашли рабочий ID
//    3b. ReadFile + OVERLAPPED fallback    — если ни один ID не сработал
//
//  Остановка: ctx->stop = true,
//  затем главный поток делает hNacon.reset() чтобы разблокировать
//  GetInputReport если он завис внутри.
// ─────────────────────────────────────────────────────────────────
struct ReadCtx {
    HANDLE        hDev;
    char          devPath[512]; // для fallback overlapped хэндла
    DWORD         pktSize;
    HANDLE        hNewPkt;      // auto-reset event: новый пакет готов
    volatile bool stop;
};

static void PushPacket(const BYTE* data, DWORD sz, HANDLE hNewPkt){
    EnterCriticalSection(&gPkt.cs);
    DWORD safe=min(sz,(DWORD)PKT_MAX);
    memcpy(gPkt.data,data,safe);
    gPkt.size=safe; gPkt.ready=true;
    LeaveCriticalSection(&gPkt.cs);
    SetEvent(hNewPkt);
}

DWORD WINAPI ReadThread(LPVOID param){
    ReadCtx* ctx=reinterpret_cast<ReadCtx*>(param);
    std::vector<BYTE> buf(ctx->pktSize,0);
    logLine("ReadThread started pktSize=%lu", ctx->pktSize);

    // ── 1. Wake-up ───────────────────────────────────────────────
    TrySendWakeup(ctx->hDev, ctx->pktSize);

    // ── 2. Probe Report IDs ──────────────────────────────────────
    BYTE reportID=ProbeReportID(ctx->hDev, ctx->pktSize);

    // ── 3a. GetInputReport polling ───────────────────────────────
    if(reportID!=0xFF){
        logLine("METHOD: GetInputReport polling ID=0x%02X", reportID);
        bool firstPkt=true;
        while(!ctx->stop){
            memset(buf.data(),0,ctx->pktSize);
            buf[0]=reportID;
            BOOL ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);
            if(!ok){
                DWORD e=GetLastError();
                if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED) break;
                logErr("GetInputReport loop err=%lu", e);
                Sleep(50); continue;
            }
            if(firstPkt){
                char raw[512]={}; int pos=0;
                for(DWORD j=0; j<ctx->pktSize&&j<64&&pos<500; j++){
                    int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",buf[j]);
                    if(n>0) pos+=n;
                }
                logLine("FIRST_PKT(GetInputReport) size=%lu RAW: %s",ctx->pktSize,raw);
                firstPkt=false;
            }
            PushPacket(buf.data(),ctx->pktSize,ctx->hNewPkt);
            Sleep(POLL_MS);
        }
        logLine("ReadThread (GetInputReport) done");
        return 0;
    }

    // ── 3b. ReadFile fallback (OVERLAPPED) ───────────────────────
    logLine("METHOD: ReadFile OVERLAPPED fallback");

    HANDLE hOv=CreateFile(ctx->devPath,
                          GENERIC_READ,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL,OPEN_EXISTING,
                          FILE_FLAG_OVERLAPPED,NULL);
    if(hOv==INVALID_HANDLE_VALUE){
        hOv=CreateFile(ctx->devPath,
                       GENERIC_READ|GENERIC_WRITE,
                       FILE_SHARE_READ|FILE_SHARE_WRITE,
                       NULL,OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED,NULL);
    }
    if(hOv==INVALID_HANDLE_VALUE){
        logErr("ReadFile fallback: open failed: %lu", GetLastError());
        return 1;
    }

    HANDLE hEv=CreateEvent(NULL,TRUE,FALSE,NULL);
    if(!hEv){ CloseHandle(hOv); logErr("CreateEvent failed"); return 1; }

    bool firstPkt=true;
    constexpr DWORD TO_MS=100;

    while(!ctx->stop){
        OVERLAPPED ov={}; ov.hEvent=hEv;
        ResetEvent(hEv);
        DWORD br=0;
        BOOL ok=ReadFile(hOv,buf.data(),ctx->pktSize,&br,&ov);
        DWORD err=GetLastError();
        if(!ok){
            if(err==ERROR_IO_PENDING){
                DWORD wt=WaitForSingleObject(hEv,TO_MS);
                if(wt==WAIT_TIMEOUT){
                    if(ctx->stop){ CancelIo(hOv); GetOverlappedResult(hOv,&ov,&br,TRUE); break; }
                    continue;
                }
                if(wt!=WAIT_OBJECT_0) break;
                if(!GetOverlappedResult(hOv,&ov,&br,FALSE)){
                    err=GetLastError();
                    if(err==ERROR_INVALID_HANDLE||err==ERROR_DEVICE_NOT_CONNECTED||
                       err==ERROR_OPERATION_ABORTED) break;
                    logErr("GOR err=%lu", err); Sleep(50); continue;
                }
            } else {
                if(err==ERROR_INVALID_HANDLE||err==ERROR_DEVICE_NOT_CONNECTED||
                   err==ERROR_OPERATION_ABORTED) break;
                logErr("ReadFile err=%lu", err); Sleep(50); continue;
            }
        }
        if(br==0) continue;
        if(firstPkt){
            char raw[512]={}; int pos=0;
            for(DWORD j=0; j<br&&j<64&&pos<500; j++){
                int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",buf[j]);
                if(n>0) pos+=n;
            }
            logLine("FIRST_PKT(ReadFile) size=%lu RAW: %s",br,raw);
            firstPkt=false;
        }
        PushPacket(buf.data(),br,ctx->hNewPkt);
    }

    CloseHandle(hEv);
    CloseHandle(hOv);
    logLine("ReadThread (ReadFile) done");
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox
//
//  Заполни после получения данных в sniffer.log.
//
//  Как читать лог:
//    PKT000042  B5:00->10
//    → нажал кнопку → байт[5] изменился 0x00→0x10, маска = 0x10
//
//  Стики: байт 0x00..0xFF, центр ≈ 0x80.
//  Ось Y обычно инвертирована → inv=true.
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf){
    XUSB_REPORT r={};
    if(buf.size()<12) return r;

    auto toAxis=[](BYTE b,bool inv)->SHORT{
        int v=inv?(128-(int)b):((int)b-128);
        v*=256;
        if(v>32767)v=32767; if(v<-32768)v=-32768;
        return (SHORT)v;
    };

    // ── Кнопки ─────────────────────────────────────────────────
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_A;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_B;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_X;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_Y;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_LEFT_SHOULDER;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_RIGHT_SHOULDER;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_START;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_BACK;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_LEFT_THUMB;
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_RIGHT_THUMB;

    // ── D-Pad hat-switch (0-7, нейтраль=0x0F или 0x08) ─────────
    // switch(buf[?]&0x0F){
    //   case 0: r.wButtons|=XUSB_GAMEPAD_DPAD_UP;                            break;
    //   case 1: r.wButtons|=XUSB_GAMEPAD_DPAD_UP  |XUSB_GAMEPAD_DPAD_RIGHT; break;
    //   case 2: r.wButtons|=XUSB_GAMEPAD_DPAD_RIGHT;                         break;
    //   case 3: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_RIGHT; break;
    //   case 4: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN;                          break;
    //   case 5: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_LEFT;  break;
    //   case 6: r.wButtons|=XUSB_GAMEPAD_DPAD_LEFT;                          break;
    //   case 7: r.wButtons|=XUSB_GAMEPAD_DPAD_UP  |XUSB_GAMEPAD_DPAD_LEFT;  break;
    // }

    // ── Стики ───────────────────────────────────────────────────
    // r.sThumbLX = toAxis(buf[?], false);
    // r.sThumbLY = toAxis(buf[?], true);
    // r.sThumbRX = toAxis(buf[?], false);
    // r.sThumbRY = toAxis(buf[?], true);

    // ── Триггеры ────────────────────────────────────────────────
    // r.bLeftTrigger  = buf[?];
    // r.bRightTrigger = buf[?];

    (void)toAxis;
    return r;
}

// ─── Key edge detection ───────────────────────────────────────────
static bool prevS=false, prevEsc=false;
inline bool keyDown(int vk){ return (GetAsyncKeyState(vk)&0x8000)!=0; }

// ─────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────
static ReadCtx rtCtx;   // static: devPath должен жить пока работает поток

int main(){
    logOpen();
    InitializeCriticalSection(&gPkt.cs);
    memset(&rtCtx,0,sizeof(rtCtx));

    uiInit();
    uiFrame();
    uiStatus(false,false,false,0,0);
    uiSnifferState(false);

    // 1. ViGEm ────────────────────────────────────────────────────
    const auto client=vigem_alloc();
    if(!client){
        uiMsg("FATAL: vigem_alloc failed.",CC_RED);
        logErr("vigem_alloc"); Sleep(3000); logClose(); return -1;
    }
    if(!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found. Install the driver.",CC_RED);
        logErr("vigem_connect");
        Sleep(3000); vigem_free(client); logClose(); return -1;
    }
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: could not create virtual Xbox pad.",CC_RED);
        logErr("vigem_target_add");
        Sleep(3000);
        vigem_target_free(pad); vigem_disconnect(client);
        vigem_free(client); logClose(); return -1;
    }
    uiStatus(true,false,true,0,0);
    logLine("ViGEm OK");

    // 2. Nacon ────────────────────────────────────────────────────
    DWORD devSize=0;
    HG hNacon;

    while(!hNacon.valid()){
        char devPath[512]={};
        if(FindBestNaconInterface(devPath,sizeof(devPath),&devSize)){
            strncpy_s(rtCtx.devPath,sizeof(rtCtx.devPath),devPath,sizeof(devPath)-1);
            hNacon.reset(OpenNacon(devPath));
        }
        if(!hNacon.valid()){
            uiMsg("Waiting for Nacon MG-X — plug in the gamepad...",CC_YEL);
            Sleep(1500);
        }
    }
    uiClearMsg();

    // Уточняем размер пакета через PreparsedData
    DWORD rSz=devSize;
    {
        PHIDP_PREPARSED_DATA ppd;
        if(HidD_GetPreparsedData(hNacon,&ppd)){
            HIDP_CAPS c2; HidP_GetCaps(ppd,&c2);
            if(c2.InputReportByteLength>rSz) rSz=c2.InputReportByteLength;
            HidD_FreePreparsedData(ppd);
        }
    }
    if(rSz<8)       rSz=8;
    if(rSz>PKT_MAX) rSz=PKT_MAX;

    uiStatus(true,true,true,rSz,0);
    logLine("Nacon OK, packet size: %lu", rSz);

    // 3. Read thread ───────────────────────────────────────────────
    HG hNewPkt(CreateEvent(NULL,FALSE,FALSE,NULL));
    if(!hNewPkt.valid()){
        uiMsg("FATAL: CreateEvent failed.",CC_RED);
        logErr("CreateEvent"); Sleep(3000); logClose(); return -1;
    }

    rtCtx.hDev    = hNacon;
    rtCtx.pktSize = rSz;
    rtCtx.hNewPkt = hNewPkt;
    rtCtx.stop    = false;

    HANDLE hThread=CreateThread(NULL,0,ReadThread,&rtCtx,0,NULL);
    if(!hThread){
        uiMsg("FATAL: CreateThread failed.",CC_RED);
        logErr("CreateThread: %lu", GetLastError());
        Sleep(3000); logClose(); return -1;
    }
    logLine("Read thread started");

    std::vector<BYTE> rbuf(rSz,0), pbuf(rSz,0);
    bool  running=true, snifOn=false;
    DWORD pkts=0;

    // 4. Main loop ─────────────────────────────────────────────────
    while(running){
        bool curS  =keyDown('S');
        bool curEsc=keyDown(VK_ESCAPE);
        if(curEsc&&!prevEsc){ running=false; break; }
        if(curS  &&!prevS  ){
            snifOn=!snifOn;
            uiSnifferState(snifOn);
            logLine("--- Sniffer %s at PKT %lu ---", snifOn?"ON":"OFF", pkts);
        }
        prevS=curS; prevEsc=curEsc;

        DWORD wt=WaitForSingleObject(hNewPkt,10);
        if(wt!=WAIT_OBJECT_0) continue;

        DWORD sz=0;
        EnterCriticalSection(&gPkt.cs);
        if(gPkt.ready){
            sz=min(gPkt.size,(DWORD)rSz);
            memcpy(rbuf.data(),gPkt.data,sz);
            gPkt.ready=false;
        }
        LeaveCriticalSection(&gPkt.cs);
        if(sz==0) continue;

        ++pkts;
        uiRawBytes(rbuf.data(),min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
        SnifferDelta(rbuf,pbuf,sz,pkts,snifOn);

        XUSB_REPORT xr=MapNaconToXbox(rbuf);
        if(!VIGEM_SUCCESS(vigem_target_x360_update(client,pad,xr))){
            uiMsg("vigem update error",CC_RED);
            logErr("vigem_target_x360_update at PKT %lu", pkts);
        }
        uiGamepad(xr);
        uiStatus(true,true,true,rSz,pkts);
    }

    // 5. Cleanup ───────────────────────────────────────────────────
    // Сначала stop=true, потом закрываем хэндл —
    // это разблокирует GetInputReport внутри потока
    rtCtx.stop=true;
    hNacon.reset();

    if(WaitForSingleObject(hThread,3000)==WAIT_TIMEOUT){
        logErr("ReadThread timeout — terminating");
        TerminateThread(hThread,0);
    }
    CloseHandle(hThread);

    vigem_target_remove(client,pad);
    vigem_target_free(pad);
    vigem_disconnect(client);
    vigem_free(client);

    DeleteCriticalSection(&gPkt.cs);
    logLine("\nSession ended. Total packets: %lu", pkts);
    logClose();
    uiRestore();
    return 0;
}
