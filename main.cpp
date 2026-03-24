#include <windows.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <setupapi.h>
#include <winusb.h>
#include <usb100.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winusb.lib")

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

enum CC : WORD {
    CC_BLK=0, CC_DGRN=2, CC_DGRY=8, CC_GRN=10,
    CC_CYN=11, CC_RED=12, CC_YEL=14, CC_WHT=15, CC_GRY=7
};

static HANDLE hCon   = INVALID_HANDLE_VALUE;
static HANDLE hConIn = INVALID_HANDLE_VALUE;
static FILE*  gLog   = nullptr;

// ─── Log ──────────────────────────────────────────────────────────
void logOpen() {
    fopen_s(&gLog, "sniffer.log", "w");
    if (gLog) { fprintf(gLog, "=== sniffer.log ===\n\n"); fflush(gLog); }
}
void logLine(const char* fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt); vfprintf(gLog, fmt, a); va_end(a);
    fputc('\n', gLog); fflush(gLog);
}
void logErr(const char* fmt, ...) {
    if (!gLog) return;
    fprintf(gLog, "[ERR] ");
    va_list a; va_start(a, fmt); vfprintf(gLog, fmt, a); va_end(a);
    fputc('\n', gLog); fflush(gLog);
}
void logClose() { if (gLog) { fclose(gLog); gLog = nullptr; } }

// ─── Shared buffer ────────────────────────────────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX] = {};
    DWORD size  = 0;
    bool  ready = false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console ──────────────────────────────────────────────────────
inline void cWrite(const char* s) { DWORD n=(DWORD)strlen(s); WriteConsoleA(hCon,s,n,&n,NULL); }
void cXY(int x,int y) { COORD c={(SHORT)x,(SHORT)y}; SetConsoleCursorPosition(hCon,c); }
void cCol(CC f,CC b=CC_BLK) { SetConsoleTextAttribute(hCon,(WORD)((b<<4)|f)); }
void cPr(int x,int y,const char* s,CC f=CC_GRY,CC b=CC_BLK) { cXY(x,y);cCol(f,b);cWrite(s); }

void uiInit() {
    hCon=GetStdHandle(STD_OUTPUT_HANDLE); hConIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0; GetConsoleMode(hConIn,&mode);
    mode&=~ENABLE_QUICK_EDIT_MODE; mode|=ENABLE_EXTENDED_FLAGS;
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
void uiRestore() {
    CONSOLE_CURSOR_INFO ci={10,TRUE}; SetConsoleCursorInfo(hCon,&ci);
    SetConsoleTextAttribute(hCon,CC_GRY); cXY(0,23); cWrite("\n");
}
static const char* SEP="--------------------------------------------------------------------------------";
void uiFrame() {
    cPr(0,0,"  NACON MG-X",CC_CYN); cPr(12,0," -> ",CC_DGRY); cPr(16,0,"XBOX 360 BRIDGE",CC_GRN);
    cPr(0,1,SEP,CC_DGRY);
    cPr(1,2,"ViGEm:",CC_DGRY); cPr(18,2,"Nacon:",CC_DGRY); cPr(35,2,"Xbox:",CC_DGRY);
    cPr(50,2,"Size:",CC_DGRY); cPr(64,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY); cPr(11,4,"LB",CC_DGRY); cPr(34,4,"BACK",CC_DGRY);
    cPr(42,4,"GUIDE",CC_DGRY); cPr(51,4,"START",CC_DGRY); cPr(62,4,"RB",CC_DGRY); cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY); cPr(24,6,"L-STICK:",CC_DGRY); cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY); cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY); cPr(0,10,"  RAW HID:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY); cPr(0,15,"  SNIFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL); cPr(4,22," snifer on/off",CC_DGRY);
    cPr(20,22,"[ESC]",CC_YEL); cPr(25,22," exit",CC_DGRY);
    cPr(38,22,"log->",CC_DGRY); cPr(43,22,"sniffer.log",CC_YEL);
}
void uiBtn(int x,int y,const char* l,bool on) {
    cXY(x,y);cCol(CC_DGRY);cWrite("[");cCol(on?CC_GRN:CC_DGRY);cWrite(l);cCol(CC_DGRY);cWrite("]");
}
void uiBar(int x,int y,BYTE v) {
    int f=v*BAR_LEN/255; char s[BAR_LEN+3]={}; s[0]='[';
    for(int i=0;i<BAR_LEN;i++) s[i+1]=(i<f)?'#':'.';
    s[BAR_LEN+1]=']'; s[BAR_LEN+2]='\0';
    cXY(x,y); cCol(v>10?CC_GRN:CC_DGRY); cWrite(s);
}
void uiAxis(int x,int y,SHORT v) {
    char b[7]; snprintf(b,sizeof(b),"%+05d",(int)v);
    cPr(x,y,b,v!=0?CC_YEL:CC_DGRY);
}
void uiMsg(const char* s,CC fg=CC_YEL) {
    char pad[82]={}; snprintf(pad,81,"  %-76s",s); cPr(0,23,pad,fg);
}
void uiClearMsg() { char pad[82]; memset(pad,' ',80); pad[80]='\0'; cPr(0,23,pad,CC_BLK); }
void uiStatus(bool vig,bool nac,bool xbx,DWORD sz,DWORD pkts) {
    cPr(7,2,  vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    char tmp[20];
    snprintf(tmp,sizeof(tmp),"%-4lu",sz);   cPr(55,2,tmp,CC_YEL);
    snprintf(tmp,sizeof(tmp),"%-9lu",pkts); cPr(69,2,tmp,CC_DGRY);
}
void uiGamepad(const XUSB_REPORT& r) {
    uiBar(4,4,r.bLeftTrigger); uiBar(70,4,r.bRightTrigger);
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
void uiRawBytes(const BYTE* buf,DWORD sz) {
    char tmp[4];
    for(int row=0;row<HEX_ROWS;row++) {
        cXY(0,11+row);
        DWORD start=(DWORD)(row*HEX_COLS),drawn=0;
        for(DWORD col=0;col<(DWORD)HEX_COLS&&start+col<sz;col++,drawn++) {
            BYTE b=buf[start+col]; cCol(b?CC_YEL:CC_DGRY);
            snprintf(tmp,sizeof(tmp),"%02X ",b); cWrite(tmp);
        }
        cCol(CC_DGRY);
        for(DWORD i=drawn;i<(DWORD)HEX_COLS;i++) cWrite("   ");
    }
}
static char snLines[SNIFFER_ROWS][UI_W+2]={}; static int snHead=0;
void uiSnifferAdd(const char* line) {
    strncpy_s(snLines[snHead],UI_W+1,line,UI_W);
    snHead=(snHead+1)%SNIFFER_ROWS;
    char pad[UI_W+2];
    for(int i=0;i<SNIFFER_ROWS;i++) {
        int idx=(snHead+i)%SNIFFER_ROWS;
        snprintf(pad,sizeof(pad),"%-*s",UI_W,snLines[idx]);
        cPr(0,16+i,pad,snLines[idx][0]?CC_YEL:CC_DGRY);
    }
}
void uiSnifferState(bool on) { cPr(9,15,on?"[ON] ":"[OFF]",on?CC_GRN:CC_RED); }
void SnifferDelta(const std::vector<BYTE>& cur,std::vector<BYTE>& prev,
                  DWORD sz,DWORD pktNum,bool show) {
    DWORD m=(DWORD)min((size_t)sz,min(cur.size(),prev.size()));
    char line[UI_W+2]={}; int pos=0;
    for(DWORD i=0;i<m&&pos<UI_W-12;i++) {
        if(cur[i]!=prev[i]) {
            int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",i,prev[i],cur[i]);
            if(n>0) pos+=n;
        }
    }
    if(pos>0) { if(show) uiSnifferAdd(line); logLine("PKT%-6lu  %s",pktNum,line); }
    prev=cur;
}

struct HG {
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE):h(h_){}
    ~HG(){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
    HG(const HG&)=delete; HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); h=nh; }
    operator HANDLE()const{ return h; }
    bool valid()const{ return h!=INVALID_HANDLE_VALUE; }
};

// ─────────────────────────────────────────────────────────────────
//  DumpHidDescriptor
//
//  Читает полный HID Report Descriptor через IOCTL_HID_GET_REPORT_DESCRIPTOR.
//  Это сырые байты описания — из них видно:
//    • какие Report ID существуют
//    • какие поля (кнопки, оси) в каждом репорте
//    • размеры полей
//
//  Также логирует все Button и Value capabilities через HidP_Get*Caps.
//  Это ключевые данные для понимания структуры устройства.
// ─────────────────────────────────────────────────────────────────
void DumpHidDescriptor(HANDLE hDev) {
    logLine("=== HID REPORT DESCRIPTOR DUMP ===");

    // Метод 1: IOCTL_HID_GET_REPORT_DESCRIPTOR
    // CTL_CODE(FILE_DEVICE_KEYBOARD, 0x100, METHOD_NEITHER, FILE_ANY_ACCESS)
    constexpr DWORD IOCTL_DESC = CTL_CODE(0x0000000b, 0x100, 3, 0);
    BYTE   descBuf[4096] = {};
    DWORD  descLen = 0;
    BOOL   ok = DeviceIoControl(hDev, IOCTL_DESC,
                                NULL, 0,
                                descBuf, sizeof(descBuf),
                                &descLen, NULL);
    if (ok && descLen > 0) {
        logLine("Raw descriptor (%lu bytes):", descLen);
        char hex[512]={};
        int pos=0;
        for(DWORD i=0;i<descLen&&pos<500;i++) {
            int n=snprintf(hex+pos,sizeof(hex)-pos,"%02X ",descBuf[i]);
            if(n>0) pos+=n;
            // Новая строка каждые 16 байт
            if((i+1)%16==0) {
                logLine("  %s", hex);
                pos=0; memset(hex,0,sizeof(hex));
            }
        }
        if(pos>0) logLine("  %s",hex);
    } else {
        logErr("IOCTL_HID_GET_REPORT_DESCRIPTOR failed: err=%lu", GetLastError());
    }

    // Метод 2: HidP capabilities — детальный разбор через preparsed data
    PHIDP_PREPARSED_DATA ppd = nullptr;
    if (!HidD_GetPreparsedData(hDev, &ppd)) {
        logErr("HidD_GetPreparsedData failed: %lu", GetLastError());
        return;
    }

    HIDP_CAPS caps = {};
    if (HidP_GetCaps(ppd, &caps) != HIDP_STATUS_SUCCESS) {
        logErr("HidP_GetCaps failed");
        HidD_FreePreparsedData(ppd);
        return;
    }

    logLine("HIDP_CAPS:");
    logLine("  UsagePage=%04X  Usage=%04X", caps.UsagePage, caps.Usage);
    logLine("  InputReportByteLength=%u", caps.InputReportByteLength);
    logLine("  OutputReportByteLength=%u", caps.OutputReportByteLength);
    logLine("  FeatureReportByteLength=%u", caps.FeatureReportByteLength);
    logLine("  NumberInputButtonCaps=%u", caps.NumberInputButtonCaps);
    logLine("  NumberInputValueCaps=%u", caps.NumberInputValueCaps);
    logLine("  NumberOutputButtonCaps=%u", caps.NumberOutputButtonCaps);
    logLine("  NumberOutputValueCaps=%u", caps.NumberOutputValueCaps);
    logLine("  NumberFeatureButtonCaps=%u", caps.NumberFeatureButtonCaps);
    logLine("  NumberFeatureValueCaps=%u", caps.NumberFeatureValueCaps);

    // Input Button caps
    if (caps.NumberInputButtonCaps > 0) {
        std::vector<HIDP_BUTTON_CAPS> bCaps(caps.NumberInputButtonCaps);
        USHORT bCount = caps.NumberInputButtonCaps;
        if (HidP_GetButtonCaps(HidP_Input, bCaps.data(), &bCount, ppd) == HIDP_STATUS_SUCCESS) {
            logLine("Input Button caps:");
            for (USHORT i = 0; i < bCount; i++) {
                auto& bc = bCaps[i];
                logLine("  [%u] Page=%04X  ReportID=%02X  IsRange=%d",
                        i, bc.UsagePage, bc.ReportID, bc.IsRange);
                if (bc.IsRange)
                    logLine("       UsageMin=%04X  UsageMax=%04X", bc.Range.UsageMin, bc.Range.UsageMax);
                else
                    logLine("       Usage=%04X", bc.NotRange.Usage);
            }
        }
    }

    // Input Value caps (оси, триггеры, D-pad)
    if (caps.NumberInputValueCaps > 0) {
        std::vector<HIDP_VALUE_CAPS> vCaps(caps.NumberInputValueCaps);
        USHORT vCount = caps.NumberInputValueCaps;
        if (HidP_GetValueCaps(HidP_Input, vCaps.data(), &vCount, ppd) == HIDP_STATUS_SUCCESS) {
            logLine("Input Value caps:");
            for (USHORT i = 0; i < vCount; i++) {
                auto& vc = vCaps[i];
                logLine("  [%u] Page=%04X  Usage=%04X  ReportID=%02X  Bits=%u  Min=%ld  Max=%ld",
                        i, vc.UsagePage,
                        vc.IsRange ? vc.Range.UsageMin : vc.NotRange.Usage,
                        vc.ReportID, vc.BitSize,
                        vc.LogicalMin, vc.LogicalMax);
            }
        }
    }

    // Feature caps — важно для MFi
    if (caps.NumberFeatureValueCaps > 0 || caps.NumberFeatureButtonCaps > 0) {
        logLine("Feature caps exist! FeatureReportLen=%u", caps.FeatureReportByteLength);
        if (caps.NumberFeatureValueCaps > 0) {
            std::vector<HIDP_VALUE_CAPS> fvCaps(caps.NumberFeatureValueCaps);
            USHORT fvCount = caps.NumberFeatureValueCaps;
            if (HidP_GetValueCaps(HidP_Feature, fvCaps.data(), &fvCount, ppd) == HIDP_STATUS_SUCCESS) {
                logLine("Feature Value caps:");
                for (USHORT i = 0; i < fvCount; i++) {
                    auto& vc = fvCaps[i];
                    logLine("  [%u] Page=%04X  Usage=%04X  ReportID=%02X  Bits=%u",
                            i, vc.UsagePage,
                            vc.IsRange ? vc.Range.UsageMin : vc.NotRange.Usage,
                            vc.ReportID, vc.BitSize);
                }
            }
        }
    }

    HidD_FreePreparsedData(ppd);
    logLine("=== DESCRIPTOR DUMP END ===");
}

// ─────────────────────────────────────────────────────────────────
//  AggressiveWakeUp
//
//  Пробует ВСЕ известные способы разбудить MFi-контроллер:
//
//  1. SetOutputReport с разными ID и паттернами байт
//  2. SetFeature с разными ID
//  3. DeviceIoControl — прямые HID IOCTL
//  4. iAP2-подобная инициализация (vendor-specific)
//
//  Результат каждой попытки идёт в лог.
//  После каждой попытки — пробуем ReadFile 200мс.
// ─────────────────────────────────────────────────────────────────
static bool TryReadAfterWake(HANDLE hDev, DWORD pktSize, const char* label) {
    // Пробуем прочитать 200мс после wake-up
    std::vector<BYTE> buf(pktSize, 0);
    HANDLE hEv = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEv) return false;

    // Открываем overlapped хэндл для теста
    // (используем тот же sync-хэндл с OVERLAPPED)
    OVERLAPPED ov = {}; ov.hEvent = hEv;
    DWORD br = 0;
    BOOL ok = ReadFile(hDev, buf.data(), pktSize, &br, &ov);
    DWORD err = GetLastError();
    bool got = false;

    if (!ok && err == ERROR_IO_PENDING) {
        if (WaitForSingleObject(hEv, 200) == WAIT_OBJECT_0 &&
            GetOverlappedResult(hDev, &ov, &br, FALSE) && br > 0)
            got = true;
        else
            CancelIo(hDev);
    } else if (ok && br > 0) {
        got = true;
    }
    CloseHandle(hEv);

    if (got) {
        char raw[256]={}; int pos=0;
        for(DWORD j=0;j<br&&j<24&&pos<240;j++){
            int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",buf[j]);if(n>0)pos+=n;
        }
        logLine("  ** DATA after [%s]: %lu bytes: %s", label, br, raw);
    }
    return got;
}

bool AggressiveWakeUp(HANDLE hDev, DWORD pktSize) {
    logLine("=== AGGRESSIVE WAKE-UP SEQUENCE ===");

    std::vector<BYTE> w(max(pktSize, (DWORD)64), 0);

    // ── 1. SetOutputReport — расширенный список ───────────────────
    struct OutCmd { BYTE id; BYTE b1; BYTE b2; BYTE b3; BYTE b4; const char* note; };
    static const OutCmd outCmds[] = {
        {0x00,0x00,0x00,0x00,0x00,"zero"},
        {0x01,0x00,0x00,0x00,0x00,"out id1"},
        {0x02,0x00,0x00,0x00,0x00,"out id2"},
        {0x05,0x01,0x00,0x00,0x00,"id5 mode1"},
        {0x05,0x09,0x00,0x00,0x00,"id5 mode9"},
        {0x0B,0x01,0x00,0x00,0x00,"id0B"},
        {0xF0,0x55,0xAA,0x00,0x00,"vendor magic"},
        {0x01,0x13,0x00,0x00,0x00,"id1 cmd13"},
        {0x01,0x01,0x00,0x00,0x00,"id1 cmd01"},
        {0x03,0x00,0x00,0x00,0x00,"id3"},
        {0x04,0x00,0x00,0x00,0x00,"id4"},
    };
    logLine("-- SetOutputReport --");
    for (auto& c : outCmds) {
        memset(w.data(), 0, w.size());
        w[0]=c.id; w[1]=c.b1; w[2]=c.b2; w[3]=c.b3; w[4]=c.b4;
        BOOL ok = HidD_SetOutputReport(hDev, w.data(), (ULONG)min((DWORD)w.size(), pktSize));
        DWORD err = GetLastError();
        logLine("  OutRpt id=0x%02X [%s]: %s err=%lu", c.id, c.note, ok?"OK":"fail", ok?0:err);
        if (ok) {
            Sleep(50);
            if (TryReadAfterWake(hDev, pktSize, c.note)) return true;
        }
    }

    // ── 2. SetFeature — расширенный список ───────────────────────
    static const OutCmd featCmds[] = {
        {0x00,0x00,0x00,0x00,0x00,"feat zero"},
        {0x01,0x00,0x00,0x00,0x00,"feat id1"},
        {0x02,0x00,0x00,0x00,0x00,"feat id2"},
        {0x03,0x00,0x00,0x00,0x00,"feat id3"},
        {0x10,0x00,0x00,0x00,0x00,"feat id10"},
        {0x20,0x00,0x00,0x00,0x00,"feat id20"},
        {0x40,0x00,0x00,0x00,0x00,"feat id40"},
        {0xF0,0x55,0xAA,0xFF,0x00,"feat vendor"},
        {0x01,0x42,0x03,0x00,0x00,"feat iap2-like"},
    };
    logLine("-- SetFeature --");
    for (auto& c : featCmds) {
        memset(w.data(), 0, w.size());
        w[0]=c.id; w[1]=c.b1; w[2]=c.b2; w[3]=c.b3; w[4]=c.b4;
        BOOL ok = HidD_SetFeature(hDev, w.data(), (ULONG)min((DWORD)w.size(), pktSize));
        DWORD err = GetLastError();
        logLine("  Feature id=0x%02X [%s]: %s err=%lu", c.id, c.note, ok?"OK":"fail", ok?0:err);
        if (ok) {
            Sleep(50);
            if (TryReadAfterWake(hDev, pktSize, c.note)) return true;
        }
    }

    // ── 3. DeviceIoControl — прямые HID IOCTL ────────────────────
    // IOCTL_HID_SET_OUTPUT_REPORT = CTL_CODE(0xb, 0x101, 0, 0)
    // IOCTL_HID_ACTIVATE_DEVICE   = CTL_CODE(0xb, 0x107, 0, 0)
    logLine("-- DeviceIoControl IOCTLs --");
    struct IoCmd { DWORD code; const char* name; };
    static const IoCmd ioCmds[] = {
        { CTL_CODE(0x0000000b, 0x107, 0, 0), "ACTIVATE_DEVICE" },
        { CTL_CODE(0x0000000b, 0x100, 3, 0), "GET_DESCRIPTOR" },
        { CTL_CODE(0x0000000b, 0x102, 0, 0), "GET_INPUT_REPORT" },
        { CTL_CODE(0x0000000b, 0x103, 0, 0), "SET_OUTPUT_REPORT" },
    };
    for (auto& io : ioCmds) {
        BYTE outBuf[256]={};
        DWORD ret=0;
        BOOL ok = DeviceIoControl(hDev, io.code,
                                  NULL, 0,
                                  outBuf, sizeof(outBuf),
                                  &ret, NULL);
        DWORD err = GetLastError();
        logLine("  IOCTL %s (0x%08X): %s err=%lu ret=%lu",
                io.name, io.code, ok?"OK":"fail", ok?0:err, ret);
        if (ok && ret > 0) {
            char hex[256]={}; int pos=0;
            for(DWORD j=0;j<ret&&j<16&&pos<240;j++){
                int n=snprintf(hex+pos,sizeof(hex)-pos,"%02X ",outBuf[j]);if(n>0)pos+=n;
            }
            logLine("    data: %s", hex);
        }
    }

    logLine("=== WAKE-UP DONE (no data triggered) ===");
    return false;
}

// ─────────────────────────────────────────────────────────────────
//  FindBestNaconInterface
// ─────────────────────────────────────────────────────────────────
bool FindBestNaconInterface(char* outPath, size_t pathMax, DWORD* outSize) {
    GUID hidGuid; HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi = SetupDiGetClassDevs(&hidGuid, NULL, NULL,
                                        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdi == INVALID_HANDLE_VALUE) { logErr("SetupDiGetClassDevs: %lu",GetLastError()); return false; }

    SP_DEVICE_INTERFACE_DATA did={}; did.cbSize=sizeof(did);
    char  p1[512]={},p2[512]={},p3[512]={};
    DWORD s1=0,s2=0,s3=0;
    bool  f1=false,f2=false,f3=false;

    logLine("=== HID DEVICE SCAN ===");
    for(int i=0;SetupDiEnumDeviceInterfaces(hdi,NULL,&hidGuid,i,&did);i++) {
        DWORD req=0;
        SetupDiGetDeviceInterfaceDetail(hdi,&did,NULL,0,&req,NULL);
        if(req==0||req>MAX_HID_REQ) continue;

        std::vector<BYTE> buf(req);
        auto* det=reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if(!SetupDiGetDeviceInterfaceDetail(hdi,&did,det,req,NULL,NULL)) continue;

        HANDLE ht=CreateFileA(det->DevicePath,0,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
        if(ht==INVALID_HANDLE_VALUE) continue;

        HIDD_ATTRIBUTES attr={sizeof(attr)};
        if(!HidD_GetAttributes(ht,&attr)){CloseHandle(ht);continue;}

        wchar_t wname[128]={}; char name[128]="(unknown)";
        if(HidD_GetProductString(ht,wname,sizeof(wname)))
            WideCharToMultiByte(CP_ACP,0,wname,-1,name,sizeof(name),NULL,NULL);

        WORD up=0,use=0; DWORD inLen=0;
        PHIDP_PREPARSED_DATA ppd=nullptr;
        if(HidD_GetPreparsedData(ht,&ppd)){
            HIDP_CAPS caps={};
            if(HidP_GetCaps(ppd,&caps)==HIDP_STATUS_SUCCESS){up=caps.UsagePage;use=caps.Usage;inLen=caps.InputReportByteLength;}
            HidD_FreePreparsedData(ppd);
        }

        bool isNacon=(attr.VendorID==NACON_VID&&attr.ProductID==NACON_PID);
        bool isGP=(up==0x01&&(use==0x04||use==0x05));
        const char* mark=isNacon?(isGP?"[NACON+GAMEPAD]":"[NACON]"):(isGP?"[GAMEPAD]":"");
        logLine("  [%d] VID=%04X PID=%04X Page=%02X Use=%02X InLen=%u  %s  \"%s\"",
                i,attr.VendorID,attr.ProductID,up,use,inLen,mark,name);

        if(isNacon&&isGP&&!f1){ logLine("    ^-- P1: Nacon PC mode!"); strncpy_s(p1,sizeof(p1),det->DevicePath,sizeof(p1)-1); s1=inLen;f1=true; }
        if(isGP&&!isNacon&&!f2){ logLine("    ^-- P2: generic gamepad"); strncpy_s(p2,sizeof(p2),det->DevicePath,sizeof(p2)-1); s2=inLen;f2=true; }
        if(isNacon&&!isGP&&!f3){ logLine("    ^-- P3: Nacon fallback"); strncpy_s(p3,sizeof(p3),det->DevicePath,sizeof(p3)-1); s3=inLen;f3=true; }
        CloseHandle(ht);
        if(f1) break;
    }
    SetupDiDestroyDeviceInfoList(hdi);
    logLine("=== SCAN END ===");

    if(f1){strncpy_s(outPath,pathMax,p1,pathMax-1);if(outSize)*outSize=s1;return true;}
    if(f2){strncpy_s(outPath,pathMax,p2,pathMax-1);if(outSize)*outSize=s2;return true;}
    if(f3){strncpy_s(outPath,pathMax,p3,pathMax-1);if(outSize)*outSize=s3;return true;}
    logErr("No device found");
    return false;
}

// ─────────────────────────────────────────────────────────────────
//  ReadCtx
// ─────────────────────────────────────────────────────────────────
struct ReadCtx {
    HANDLE        hDev;
    char          devPath[512];
    DWORD         pktSize;
    HANDLE        hNewPkt;
    volatile bool stop;
};

static void PushPacket(const BYTE* d, DWORD sz, HANDLE ev) {
    EnterCriticalSection(&gPkt.cs);
    DWORD s=min(sz,(DWORD)PKT_MAX);
    memcpy(gPkt.data,d,s); gPkt.size=s; gPkt.ready=true;
    LeaveCriticalSection(&gPkt.cs);
    SetEvent(ev);
}
static void LogFirstPkt(const char* m, const BYTE* d, DWORD sz) {
    char raw[512]={}; int pos=0;
    for(DWORD j=0;j<sz&&j<48&&pos<490;j++){int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",d[j]);if(n>0)pos+=n;}
    logLine("FIRST_PKT [%s] size=%lu  RAW: %s",m,sz,raw);
}
static HANDLE OpenOv(const char* path) {
    HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(h==INVALID_HANDLE_VALUE)
        h=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    return h;
}

// ─────────────────────────────────────────────────────────────────
//  ReadThread
//  Методы A(GetFeature) → B(GetInputReport) → C(ReadFile OV) → D(Blocking)
// ─────────────────────────────────────────────────────────────────
DWORD WINAPI ReadThread(LPVOID param) {
    ReadCtx* ctx=reinterpret_cast<ReadCtx*>(param);
    logLine("ReadThread started  pktSize=%lu", ctx->pktSize);
    std::vector<BYTE> buf(max(ctx->pktSize,(DWORD)128),0);

    // [A] GetFeature
    {static const BYTE ids[]={0x00,0x01,0x02,0x03,0x10,0x20,0x40};BYTE wid=0xFF;
     logLine("-- [A] GetFeature --");
     for(BYTE id:ids){memset(buf.data(),0,ctx->pktSize);buf[0]=id;
       BOOL ok=HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize);DWORD err=GetLastError();
       logLine("  ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
       if(ok){bool nz=false;for(DWORD j=0;j<ctx->pktSize;j++)if(buf[j]){nz=true;break;}
         if(nz){logLine("  ^-- WORKS!");wid=id;break;}logLine("  ^-- zeros");}}
     if(wid!=0xFF){logLine("METHOD:GetFeature ID=0x%02X",wid);bool first=true;
       while(!ctx->stop){memset(buf.data(),0,ctx->pktSize);buf[0]=wid;
         if(!HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize)){
           DWORD e=GetLastError();if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED)break;
           Sleep(50);continue;}
         if(first){LogFirstPkt("GetFeature",buf.data(),ctx->pktSize);first=false;}
         PushPacket(buf.data(),ctx->pktSize,ctx->hNewPkt);Sleep(8);}
       logLine("ReadThread[GetFeature]done");return 0;}}

    // [B] GetInputReport
    {static const BYTE ids[]={0x00,0x01,0x02,0x03,0x10,0x20};BYTE wid=0xFF;
     logLine("-- [B] GetInputReport --");
     for(BYTE id:ids){memset(buf.data(),0,ctx->pktSize);buf[0]=id;
       BOOL ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);DWORD err=GetLastError();
       logLine("  ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
       if(ok){bool nz=false;for(DWORD j=1;j<ctx->pktSize;j++)if(buf[j]){nz=true;break;}
         if(nz){logLine("  ^-- WORKS!");wid=id;break;}logLine("  ^-- zeros");}}
     if(wid!=0xFF){logLine("METHOD:GetInputReport ID=0x%02X",wid);bool first=true;
       while(!ctx->stop){memset(buf.data(),0,ctx->pktSize);buf[0]=wid;
         if(!HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize)){
           DWORD e=GetLastError();if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED)break;
           Sleep(50);continue;}
         if(first){LogFirstPkt("GetInputReport",buf.data(),ctx->pktSize);first=false;}
         PushPacket(buf.data(),ctx->pktSize,ctx->hNewPkt);Sleep(8);}
       logLine("ReadThread[GetInputReport]done");return 0;}}

    // [C] ReadFile overlapped
    {static const DWORD sizes[]={64,65,32,16,128,8};
     logLine("-- [C] ReadFile overlapped --");
     for(DWORD ps:sizes){
       if(ctx->stop)break;logLine("  size=%lu ...",ps);
       HANDLE hp=OpenOv(ctx->devPath);
       if(hp==INVALID_HANDLE_VALUE){logErr("  open failed %lu",GetLastError());break;}
       HANDLE hev=CreateEvent(NULL,TRUE,FALSE,NULL);
       std::vector<BYTE> pb(ps,0);OVERLAPPED pov={};pov.hEvent=hev;DWORD br=0;
       BOOL ok=ReadFile(hp,pb.data(),ps,&br,&pov);DWORD err=GetLastError();bool got=false;
       if(!ok&&err==ERROR_IO_PENDING){
         if(WaitForSingleObject(hev,2000)==WAIT_OBJECT_0&&GetOverlappedResult(hp,&pov,&br,FALSE)&&br>0)got=true;
         else CancelIo(hp);}
       else if(ok&&br>0)got=true;
       CloseHandle(hev);CloseHandle(hp);
       if(got){logLine("  ReadFile WORKS! size=%lu",ps);
         HANDLE hf=OpenOv(ctx->devPath);
         if(hf==INVALID_HANDLE_VALUE){logErr("  final open failed");break;}
         HANDLE hem=CreateEvent(NULL,TRUE,FALSE,NULL);
         std::vector<BYTE> mb(ps,0);bool first=true;
         logLine("METHOD:ReadFile OV size=%lu",ps);
         while(!ctx->stop){
           OVERLAPPED mov={};mov.hEvent=hem;ResetEvent(hem);DWORD mbr=0;
           BOOL mok=ReadFile(hf,mb.data(),ps,&mbr,&mov);DWORD merr=GetLastError();
           if(!mok){if(merr==ERROR_IO_PENDING){
             DWORD mwt=WaitForSingleObject(hem,500);
             if(mwt==WAIT_TIMEOUT){if(ctx->stop){CancelIo(hf);GetOverlappedResult(hf,&mov,&mbr,TRUE);break;}continue;}
             if(mwt!=WAIT_OBJECT_0)break;
             if(!GetOverlappedResult(hf,&mov,&mbr,FALSE)){
               merr=GetLastError();
               if(merr==ERROR_INVALID_HANDLE||merr==ERROR_DEVICE_NOT_CONNECTED||merr==ERROR_OPERATION_ABORTED)break;
               Sleep(50);continue;}}
           else{if(merr==ERROR_INVALID_HANDLE||merr==ERROR_DEVICE_NOT_CONNECTED||merr==ERROR_OPERATION_ABORTED)break;
             Sleep(50);continue;}}
           if(mbr==0)continue;
           if(first){LogFirstPkt("ReadFile",mb.data(),mbr);first=false;}
           PushPacket(mb.data(),mbr,ctx->hNewPkt);}
         CloseHandle(hem);CloseHandle(hf);
         logLine("ReadThread[ReadFile OV]done");return 0;}
       logLine("  size=%lu: no data",ps);}}

    // [D] Blocking
    {logLine("METHOD:Blocking ReadFile");bool first=true;
     while(!ctx->stop){
       DWORD br=0;
       BOOL ok=ReadFile(ctx->hDev,buf.data(),ctx->pktSize,&br,NULL);
       if(!ok){DWORD e=GetLastError();
         if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED||
            e==ERROR_OPERATION_ABORTED||e==ERROR_BROKEN_PIPE)break;
         Sleep(50);continue;}
       if(br==0)continue;
       if(first){LogFirstPkt("Blocking",buf.data(),br);first=false;}
       PushPacket(buf.data(),br,ctx->hNewPkt);}}

    logLine("ReadThread done");
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox — заполни после получения данных
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r={};
    if(buf.size()<12) return r;
    auto toAxis=[](BYTE b,bool inv)->SHORT{
        int v=inv?(128-(int)b):((int)b-128);v*=256;
        if(v>32767)v=32767;if(v<-32768)v=-32768;return (SHORT)v;};
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_A;
    // ...
    (void)toAxis;
    return r;
}

static bool prevS=false,prevEsc=false;
inline bool keyDown(int vk){ return (GetAsyncKeyState(vk)&0x8000)!=0; }
static ReadCtx rtCtx;

int main() {
    logOpen();
    InitializeCriticalSection(&gPkt.cs);
    memset(&rtCtx,0,sizeof(rtCtx));
    SetPriorityClass(GetCurrentProcess(),HIGH_PRIORITY_CLASS);

    uiInit(); uiFrame();
    uiStatus(false,false,false,0,0);
    uiSnifferState(false);

    // 1. ViGEm
    const auto client=vigem_alloc();
    if(!client){uiMsg("FATAL: vigem_alloc",CC_RED);logErr("vigem_alloc");Sleep(3000);logClose();return -1;}
    if(!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found.",CC_RED);logErr("vigem_connect");
        Sleep(3000);vigem_free(client);logClose();return -1;}
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: vigem_target_add",CC_RED);logErr("vigem_target_add");
        Sleep(3000);vigem_target_free(pad);vigem_disconnect(client);vigem_free(client);logClose();return -1;}
    uiStatus(true,false,true,0,0);
    logLine("ViGEm OK");

    // 2. Поиск устройства
    DWORD devSize=0; HG hNacon;
    while(!hNacon.valid()){
        char devPath[512]={};
        if(FindBestNaconInterface(devPath,sizeof(devPath),&devSize)){
            strncpy_s(rtCtx.devPath,sizeof(rtCtx.devPath),devPath,sizeof(devPath)-1);
            HANDLE h=CreateFileA(devPath,GENERIC_READ|GENERIC_WRITE,
                                  FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
            if(h==INVALID_HANDLE_VALUE){
                logErr("CreateFile RW (%lu), READ-only",GetLastError());
                h=CreateFileA(devPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);}
            if(h!=INVALID_HANDLE_VALUE){
                logLine("Sync handle OK");
                HidD_SetNumInputBuffers(h,64);
                hNacon.reset(h);}
        }
        if(!hNacon.valid()){uiMsg("Waiting for Nacon MG-X...",CC_YEL);Sleep(1500);}
    }
    uiClearMsg();

    DWORD rSz=devSize;
    {PHIDP_PREPARSED_DATA ppd;
     if(HidD_GetPreparsedData(hNacon,&ppd)){
         HIDP_CAPS c2;HidP_GetCaps(ppd,&c2);
         if(c2.InputReportByteLength>rSz)rSz=c2.InputReportByteLength;
         HidD_FreePreparsedData(ppd);}}
    if(rSz<8)rSz=8; if(rSz>PKT_MAX)rSz=PKT_MAX;

    uiStatus(true,true,true,rSz,0);
    logLine("Nacon OK  pktSize=%lu  path=%s",rSz,rtCtx.devPath);

    // 3. Дамп дескриптора — ключевые данные для диагностики
    uiMsg("Dumping HID descriptor...",CC_YEL);
    DumpHidDescriptor(hNacon);

    // 4. Агрессивный wake-up перед запуском потока
    uiMsg("Trying wake-up sequences...",CC_YEL);
    bool wokeUp = AggressiveWakeUp(hNacon, rSz);
    if(wokeUp) logLine("*** WAKE-UP SUCCEEDED! ***");
    else        logLine("Wake-up: no data triggered, starting read thread anyway");

    // 5. Read thread
    HG hNewPkt(CreateEvent(NULL,FALSE,FALSE,NULL));
    if(!hNewPkt.valid()){uiMsg("FATAL: CreateEvent",CC_RED);logErr("CreateEvent");Sleep(3000);logClose();return -1;}

    rtCtx.hDev    =hNacon;
    rtCtx.pktSize =rSz;
    rtCtx.hNewPkt =hNewPkt;
    rtCtx.stop    =false;

    HANDLE hThread=CreateThread(NULL,0,ReadThread,&rtCtx,0,NULL);
    if(!hThread){uiMsg("FATAL: CreateThread",CC_RED);logErr("CreateThread: %lu",GetLastError());Sleep(3000);logClose();return -1;}
    logLine("Read thread started");
    uiClearMsg();

    std::vector<BYTE> rbuf(rSz,0),pbuf(rSz,0);
    bool running=true,snifOn=false;
    DWORD pkts=0;

    // 6. Main loop
    while(running){
        bool curS=keyDown('S'),curEsc=keyDown(VK_ESCAPE);
        if(curEsc&&!prevEsc){running=false;break;}
        if(curS&&!prevS){
            snifOn=!snifOn;uiSnifferState(snifOn);
            logLine("--- Sniffer %s PKT %lu ---",snifOn?"ON":"OFF",pkts);}
        prevS=curS;prevEsc=curEsc;

        if(WaitForSingleObject(hNewPkt,10)!=WAIT_OBJECT_0) continue;

        DWORD sz=0;
        EnterCriticalSection(&gPkt.cs);
        if(gPkt.ready){sz=min(gPkt.size,(DWORD)rSz);memcpy(rbuf.data(),gPkt.data,sz);gPkt.ready=false;}
        LeaveCriticalSection(&gPkt.cs);
        if(sz==0) continue;

        ++pkts;
        uiRawBytes(rbuf.data(),min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
        SnifferDelta(rbuf,pbuf,sz,pkts,snifOn);
        XUSB_REPORT xr=MapNaconToXbox(rbuf);
        if(!VIGEM_SUCCESS(vigem_target_x360_update(client,pad,xr)))
            logErr("vigem update PKT %lu",pkts);
        uiGamepad(xr);
        uiStatus(true,true,true,rSz,pkts);
    }

    // 7. Cleanup
    rtCtx.stop=true;
    hNacon.reset();
    if(WaitForSingleObject(hThread,3000)==WAIT_TIMEOUT){
        logErr("ReadThread timeout");TerminateThread(hThread,0);}
    CloseHandle(hThread);
    vigem_target_remove(client,pad);vigem_target_free(pad);
    vigem_disconnect(client);vigem_free(client);
    DeleteCriticalSection(&gPkt.cs);
    logLine("\nDone. Packets: %lu",pkts);
    logClose();uiRestore();
    return 0;
}
