#include <windows.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <setupapi.h>
#include <bluetoothapis.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <atomic>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Bthprops.lib") // Библиотека для работы с Bluetooth

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

enum WorkMode {
    MODE_UNKNOWN  = 0,
    MODE_HID      = 1
};

static HANDLE hCon   = INVALID_HANDLE_VALUE;
static HANDLE hConIn = INVALID_HANDLE_VALUE;
static FILE*  gLog   = nullptr;

static char g_MgxMac[32] = {0}; // Здесь будем хранить MAC-адрес геймпада
static int  g_LastDevCount = -1; // Для умного логирования

// ─── Log ──────────────────────────────────────────────────────────
void logOpen() {
    fopen_s(&gLog, "sniffer.log", "w");
    if (gLog) { fprintf(gLog, "=== sniffer.log ===\n\n"); fflush(gLog); }
}
void logLine(const char* fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a);
    fputc('\n',gLog); fflush(gLog);
}
void logErr(const char* fmt, ...) {
    if (!gLog) return;
    fprintf(gLog,"[ERR] ");
    va_list a; va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a);
    fputc('\n',gLog); fflush(gLog);
}
void logClose() { if(gLog){fclose(gLog);gLog=nullptr;} }

// ─── Shared buffer ────────────────────────────────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX] = {};
    DWORD size  = 0;
    bool  ready = false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console UI ───────────────────────────────────────────────────
inline void cWrite(const char* s){ DWORD n=(DWORD)strlen(s);WriteConsoleA(hCon,s,n,&n,NULL); }
void cXY(int x,int y){ COORD c={(SHORT)x,(SHORT)y};SetConsoleCursorPosition(hCon,c); }
void cCol(CC f,CC b=CC_BLK){ SetConsoleTextAttribute(hCon,(WORD)((b<<4)|f)); }
void cPr(int x,int y,const char* s,CC f=CC_GRY,CC b=CC_BLK){ cXY(x,y);cCol(f,b);cWrite(s); }

void uiInit(){
    hCon=GetStdHandle(STD_OUTPUT_HANDLE); hConIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0;GetConsoleMode(hConIn,&mode);
    mode&=~ENABLE_QUICK_EDIT_MODE;mode|=ENABLE_EXTENDED_FLAGS;SetConsoleMode(hConIn,mode);
    CONSOLE_CURSOR_INFO ci={1,FALSE};SetConsoleCursorInfo(hCon,&ci);
    COORD sz={(SHORT)UI_W,(SHORT)UI_H};SetConsoleScreenBufferSize(hCon,sz);
    SMALL_RECT wr={0,0,(SHORT)(UI_W-1),(SHORT)(UI_H-1)};SetConsoleWindowInfo(hCon,TRUE,&wr);
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge (Bluetooth)");
    DWORD w;COORD o={0,0};
    FillConsoleOutputCharacterA(hCon,' ',UI_W*UI_H,o,&w);
    FillConsoleOutputAttribute(hCon,CC_GRY,UI_W*UI_H,o,&w);
}
void uiRestore(){
    CONSOLE_CURSOR_INFO ci={10,TRUE};SetConsoleCursorInfo(hCon,&ci);
    SetConsoleTextAttribute(hCon,CC_GRY);cXY(0,23);cWrite("\n");
}
static const char* SEP="--------------------------------------------------------------------------------";
void uiFrame(){
    cPr(0,0,"  NACON MG-X",CC_CYN);cPr(12,0," -> ",CC_DGRY);cPr(16,0,"XBOX 360 BRIDGE",CC_GRN);
    cPr(0,1,SEP,CC_DGRY);
    cPr(1,2,"ViGEm:",CC_DGRY);cPr(18,2,"Nacon:",CC_DGRY);cPr(35,2,"Xbox:",CC_DGRY);
    cPr(50,2,"Mode:",CC_DGRY);cPr(62,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY);cPr(11,4,"LB",CC_DGRY);cPr(34,4,"BACK",CC_DGRY);
    cPr(42,4,"GUIDE",CC_DGRY);cPr(51,4,"START",CC_DGRY);cPr(62,4,"RB",CC_DGRY);cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY);cPr(24,6,"L-STICK:",CC_DGRY);cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY);cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY);cPr(0,10,"  RAW DATA:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY);cPr(0,15,"  SNIFFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL);cPr(4,22," sniffer on/off",CC_DGRY);
    cPr(20,22,"[ESC]",CC_YEL);cPr(25,22," exit",CC_DGRY);
    cPr(38,22,"log->",CC_DGRY);cPr(43,22,"sniffer.log",CC_YEL);
}
void uiBtn(int x,int y,const char* l,bool on){ cXY(x,y);cCol(CC_DGRY);cWrite("[");cCol(on?CC_GRN:CC_DGRY);cWrite(l);cCol(CC_DGRY);cWrite("]"); }
void uiBar(int x,int y,BYTE v){
    int f=v*BAR_LEN/255;char s[BAR_LEN+3]={};s[0]='[';
    for(int i=0;i<BAR_LEN;i++)s[i+1]=(i<f)?'#':'.';s[BAR_LEN+1]=']';s[BAR_LEN+2]='\0';
    cXY(x,y);cCol(v>10?CC_GRN:CC_DGRY);cWrite(s);
}
void uiAxis(int x,int y,SHORT v){ char b[7];snprintf(b,sizeof(b),"%+05d",(int)v);cPr(x,y,b,v!=0?CC_YEL:CC_DGRY); }
void uiMsg(const char* s,CC fg=CC_YEL){ char pad[82]={};snprintf(pad,81,"  %-76s",s);cPr(0,23,pad,fg); }
void uiClearMsg(){char pad[82];memset(pad,' ',80);pad[80]='\0';cPr(0,23,pad,CC_BLK);}
void uiStatus(bool vig,bool nac,bool xbx,WorkMode mode,DWORD pkts){
    cPr(7,2,  vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    const char* ms; CC mc;
    switch(mode){
        case MODE_HID:    ms="[BT ] "; mc=CC_GRN; break;
        default:          ms="[---] "; mc=CC_DGRY; break;
    }
    cPr(55,2,ms,mc);
    char tmp[16];snprintf(tmp,sizeof(tmp),"%-9lu",pkts);cPr(69,2,tmp,CC_DGRY);
}
void uiGamepad(const XUSB_REPORT& r){
    uiBar(4,4,r.bLeftTrigger);uiBar(70,4,r.bRightTrigger);
    uiBtn(13,4,"LB",(r.wButtons&XUSB_GAMEPAD_LEFT_SHOULDER)!=0);
    uiBtn(64,4,"RB",(r.wButtons&XUSB_GAMEPAD_RIGHT_SHOULDER)!=0);
    uiBtn(38,4,"<<",(r.wButtons&XUSB_GAMEPAD_BACK)!=0);
    uiBtn(47,4,"()",(r.wButtons&XUSB_GAMEPAD_GUIDE)!=0);
    uiBtn(56,4,">>",(r.wButtons&XUSB_GAMEPAD_START)!=0);
    uiBtn(7,6,"^",(r.wButtons&XUSB_GAMEPAD_DPAD_UP)!=0);
    uiBtn(10,6,"v",(r.wButtons&XUSB_GAMEPAD_DPAD_DOWN)!=0);
    uiBtn(13,6,"<",(r.wButtons&XUSB_GAMEPAD_DPAD_LEFT)!=0);
    uiBtn(16,6,">",(r.wButtons&XUSB_GAMEPAD_DPAD_RIGHT)!=0);
    uiAxis(32,6,r.sThumbLX);uiAxis(38,6,r.sThumbLY);
    uiAxis(54,6,r.sThumbRX);uiAxis(60,6,r.sThumbRY);
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
        DWORD start=(DWORD)(row*HEX_COLS),drawn=0;
        for(DWORD col=0;col<(DWORD)HEX_COLS&&start+col<sz;col++,drawn++){
            BYTE b=buf[start+col];cCol(b?CC_YEL:CC_DGRY);
            snprintf(tmp,sizeof(tmp),"%02X ",b);cWrite(tmp);
        }
        cCol(CC_DGRY);for(DWORD i=drawn;i<(DWORD)HEX_COLS;i++)cWrite("   ");
    }
}
static char snLines[SNIFFER_ROWS][UI_W+2]={};static int snHead=0;
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
void uiSnifferState(bool on){ cPr(9,15,on?"[ON] ":"[OFF]",on?CC_GRN:CC_RED); }
void SnifferDelta(const std::vector<BYTE>& cur,std::vector<BYTE>& prev,DWORD sz,DWORD pktNum,bool show){
    DWORD m=(DWORD)min((size_t)sz,min(cur.size(),prev.size()));
    char line[UI_W+2]={};int pos=0;
    for(DWORD i=0;i<m&&pos<UI_W-12;i++){
        if(cur[i]!=prev[i]){
            int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",i,prev[i],cur[i]);
            if(n>0)pos+=n;
        }
    }
    if(pos>0){if(show)uiSnifferAdd(line);logLine("PKT%-6lu  %s",pktNum,line);}
    prev=cur;
}

struct HG{
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE):h(h_){}
    ~HG(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
    HG(const HG&)=delete;HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=nh;}
    operator HANDLE()const{return h;}
    bool valid()const{return h!=INVALID_HANDLE_VALUE;}
};

// ─────────────────────────────────────────────────────────────────
//  Bluetooth Force Connect
// ─────────────────────────────────────────────────────────────────
void ForceConnectBluetoothHID() {
    logLine("--- Bluetooth Check & Kick ---");
    
    BLUETOOTH_DEVICE_SEARCH_PARAMS search = {};
    search.dwSize = sizeof(search);
    search.fReturnAuthenticated = TRUE;  // Только сопряжённые
    search.fReturnRemembered = TRUE;     // Запомненные системой
    search.cTimeoutMultiplier = 2;       // Таймаут

    BLUETOOTH_DEVICE_INFO info = {};
    info.dwSize = sizeof(info);

    HANDLE hFind = BluetoothFindFirstDevice(&search, &info);
    if (!hFind) {
        logLine("BluetoothFindFirstDevice failed, error: %lu", GetLastError());
        return;
    }

    bool found = false;
    do {
        // Ищем по имени. info.szName имеет тип WCHAR (широкие символы)
        if (wcsstr(info.szName, L"MG-X") || wcsstr(info.szName, L"Nacon") || wcsstr(info.szName, L"NACON")) {
            found = true;
            
            // Сохраняем физический MAC адрес контроллера (в формате c03900450b33)
            sprintf_s(g_MgxMac, sizeof(g_MgxMac), "%02x%02x%02x%02x%02x%02x", 
                info.Address.rgBytes[5], info.Address.rgBytes[4], info.Address.rgBytes[3], 
                info.Address.rgBytes[2], info.Address.rgBytes[1], info.Address.rgBytes[0]);

            logLine("Found BT Device: %S[MAC: %s]", info.szName, g_MgxMac);
            logLine("Status: %s", info.fConnected ? "CONNECTED" : "DISCONNECTED");

            // Стандартный GUID для HID over Bluetooth
            GUID hidService = { 0x00001124, 0x0000, 0x1000, {0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb} };

            // Принудительно отключаем службу (если "зависла")
            logLine("Disabling HID service to reset state...");
            BluetoothSetServiceState(NULL, &info, &hidService, BLUETOOTH_SERVICE_DISABLE);
            Sleep(500);

            // Включаем её обратно, инициируя новое соединение
            logLine("Enabling HID service...");
            DWORD res = BluetoothSetServiceState(NULL, &info, &hidService, BLUETOOTH_SERVICE_ENABLE);
            
            if (res == ERROR_SUCCESS) {
                logLine("HID service kicked successfully for %S", info.szName);
                uiMsg("Bluetooth HID service kicked!", CC_YEL);
            } else {
                logErr("BluetoothSetServiceState enable failed: %lu", res);
            }
            break; // Нашли устройство, выходим из цикла поиска BT
        }
    } while (BluetoothFindNextDevice(hFind, &info));
    BluetoothFindDeviceClose(hFind);

    if (!found) {
        logLine("No matching Bluetooth device found in Windows history.");
        uiMsg("Bluetooth device not found. Ensure it's paired.", CC_RED);
    }
}

// ─────────────────────────────────────────────────────────────────
//  Поиск Устройств (HID)
// ─────────────────────────────────────────────────────────────────
bool FindHIDPath(char* outPath, size_t pathMax, DWORD* outSize, bool* isGamepad) {
    GUID hidGuid; HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi = SetupDiGetClassDevs(&hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdi == INVALID_HANDLE_VALUE) return false;

    SP_DEVICE_INTERFACE_DATA did = {}; 
    did.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    
    // Считаем общее количество HID устройств
    int devCount = 0;
    while (SetupDiEnumDeviceInterfaces(hdi, NULL, &hidGuid, devCount, &did)) devCount++;
    
    // Будем логировать подробно ТОЛЬКО если кол-во устройств изменилось, чтобы не засорять лог
    bool logDetails = (devCount != g_LastDevCount);
    g_LastDevCount = devCount;

    if (logDetails) logLine("=== HID DEVICE SCAN (%d devices present) ===", devCount);

    char  p1[512]={}, p3[512]={};
    DWORD s1=0, s3=0;
    bool  f1=false, f3=false;
    bool  gp1=false, gp3=false;

    for (int i = 0; SetupDiEnumDeviceInterfaces(hdi, NULL, &hidGuid, i, &did); i++) {
        DWORD req = 0;
        SetupDiGetDeviceInterfaceDetail(hdi, &did, NULL, 0, &req, NULL);
        if (req == 0 || req > MAX_HID_REQ) continue;

        std::vector<BYTE> buf(req);
        auto* det = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (!SetupDiGetDeviceInterfaceDetail(hdi, &did, det, req, NULL, NULL)) continue;

        // Переводим путь в нижний регистр для безопасного поиска MAC-адреса
        char lowerPath[512] = {};
        if (det->DevicePath[0] != '\0') {
            strncpy_s(lowerPath, sizeof(lowerPath), det->DevicePath, _TRUNCATE);
            _strlwr_s(lowerPath);
        }

        // Ключевой хак: ищем физический MAC адрес в PnP пути устройства!
        bool isN_byMac = (g_MgxMac[0] != '\0' && strstr(lowerPath, g_MgxMac) != nullptr);

        HANDLE ht = CreateFileA(det->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (ht == INVALID_HANDLE_VALUE) {
            ht = CreateFileA(det->DevicePath, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        }

        if (ht == INVALID_HANDLE_VALUE) {
            if (isN_byMac && logDetails) logLine("  [%d] FOUND BY MAC, but FAILED to open handle! Err: %lu", i, GetLastError());
            continue;
        }

        HIDD_ATTRIBUTES attr = { sizeof(attr) };
        if (!HidD_GetAttributes(ht, &attr)) { CloseHandle(ht); continue; }

        wchar_t wn[128]={}; char name[128]="(unknown)";
        if (HidD_GetProductString(ht, wn, sizeof(wn))) {
            WideCharToMultiByte(CP_ACP, 0, wn, -1, name, sizeof(name), NULL, NULL);
        }

        WORD up=0, use=0; DWORD inLen=0;
        PHIDP_PREPARSED_DATA ppd = nullptr;
        if (HidD_GetPreparsedData(ht, &ppd)) {
            HIDP_CAPS caps={};
            if (HidP_GetCaps(ppd, &caps) == HIDP_STATUS_SUCCESS) {
                up=caps.UsagePage; use=caps.Usage; inLen=caps.InputReportByteLength;
            }
            HidD_FreePreparsedData(ppd);
        }

        // 1. Проверяем по USB VID/PID 
        bool isN = (attr.VendorID == NACON_VID && attr.ProductID == NACON_PID);

        // 2. Расширенный поиск по имени 
        char lowerName[256] = {};
        if (name[0] != '\0') {
            strncpy_s(lowerName, sizeof(lowerName), name, _TRUNCATE);
            _strlwr_s(lowerName);
        }
        if (!isN && (strstr(lowerName, "mg-x") != nullptr || strstr(lowerName, "nacon") != nullptr)) isN = true;

        // 3. Подтверждение по MAC-адресу (Железобетонный метод для Bluetooth)
        if (!isN && isN_byMac) isN = true;

        if (logDetails) {
            logLine("  [%d] VID=%04X PID=%04X Page=%02X Use=%02X Name=\"%s\"", 
                    i, attr.VendorID, attr.ProductID, up, use, name);
            if (isN_byMac) logLine("      ^-- Identifed by BT MAC address!");
            else if (isN) logLine("      ^-- Identifed by VID/PID/Name");
        }

        bool isGP = (up == 0x01 && (use == 0x04 || use == 0x05));

        if (isN && isGP && !f1) { p1[0]='\0'; strncpy_s(p1, sizeof(p1), det->DevicePath, sizeof(p1)-1); s1=inLen; f1=true; gp1=true; }
        if (isN && !isGP && !f3) { p3[0]='\0'; strncpy_s(p3, sizeof(p3), det->DevicePath, sizeof(p3)-1); s3=inLen; f3=true; gp3=false; }
        
        CloseHandle(ht);
    }
    
    if (logDetails) logLine("=== SCAN END ===");
    SetupDiDestroyDeviceInfoList(hdi);

    if (f1) { strncpy_s(outPath, pathMax, p1, pathMax-1); if(outSize)*outSize=s1; if(isGamepad)*isGamepad=gp1; return true; }
    if (f3) { strncpy_s(outPath, pathMax, p3, pathMax-1); if(outSize)*outSize=s3; if(isGamepad)*isGamepad=gp3; return true; }
    return false;
}

// ─────────────────────────────────────────────────────────────────
//  ReadCtx & Thread
// ─────────────────────────────────────────────────────────────────
struct ReadCtx {
    HANDLE            hDev     = INVALID_HANDLE_VALUE;
    char              devPath[512] = {};
    DWORD             pktSize  = 64;
    WorkMode          mode     = MODE_UNKNOWN;
    HANDLE            hNewPkt  = INVALID_HANDLE_VALUE;
    
    std::atomic<bool> stop{false};
    std::atomic<bool> disconnected{false}; 
};

static void PushPacket(const BYTE* d, DWORD sz, HANDLE ev) {
    EnterCriticalSection(&gPkt.cs);
    DWORD s = min(sz, (DWORD)PKT_MAX);
    memcpy(gPkt.data, d, s); gPkt.size = s; gPkt.ready = true;
    LeaveCriticalSection(&gPkt.cs);
    SetEvent(ev);
}

static void LogFirstPkt(const char* m, const BYTE* d, DWORD sz) {
    char raw[512]={}; int pos=0;
    for (DWORD j=0; j<sz && j<48 && pos<490; j++) {
        int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",d[j]); if(n>0)pos+=n;
    }
    logLine("FIRST_PKT[%s] size=%lu  RAW: %s", m, sz, raw);
}

static HANDLE OpenOv(const char* path) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileA(path, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    }
    return h;
}

DWORD WINAPI ReadThread(LPVOID param) {
    ReadCtx* ctx = reinterpret_cast<ReadCtx*>(param);
    logLine("ReadThread started  mode=HID  pktSize=%lu", ctx->pktSize);

    // ── HID режим (Абсолютно безопасный Overlapped I/O) ────────────
    logLine("METHOD: ReadFile Overlapped");
    HANDLE hf = OpenOv(ctx->devPath);
    if (hf != INVALID_HANDLE_VALUE) {
        HANDLE hem = CreateEvent(NULL, TRUE, FALSE, NULL);
        std::vector<BYTE> mb(ctx->pktSize, 0);
        bool first = true;
        
        OVERLAPPED mov = {};
        mov.hEvent = hem;
        bool pendingRead = false;

        while (!ctx->stop) {
            if (!pendingRead) {
                memset(&mov, 0, sizeof(mov));
                mov.hEvent = hem;
                ResetEvent(hem);
                DWORD mbr0 = 0;
                BOOL imm = ReadFile(hf, mb.data(), ctx->pktSize, &mbr0, &mov);
                DWORD e0 = GetLastError();
                
                if (imm && mbr0 > 0) {
                    if (first) { LogFirstPkt("ReadFile", mb.data(), mbr0); first = false; }
                    PushPacket(mb.data(), mbr0, ctx->hNewPkt);
                    continue;
                }
                if (!imm && e0 != ERROR_IO_PENDING) {
                    logErr("ReadFile fatal error: %lu", e0);
                    if (e0 == ERROR_DEVICE_NOT_CONNECTED || e0 == ERROR_INVALID_HANDLE) break;
                    Sleep(50); continue;
                }
                pendingRead = true;
            }

            DWORD mwt = WaitForSingleObject(hem, 500);
            if (mwt == WAIT_TIMEOUT) {
                if (ctx->stop) {
                    CancelIo(hf);
                    DWORD tmp = 0; GetOverlappedResult(hf, &mov, &tmp, TRUE); 
                    break;
                }
                continue; 
            }
            if (mwt != WAIT_OBJECT_0) break;

            DWORD mbr = 0;
            if (!GetOverlappedResult(hf, &mov, &mbr, FALSE)) {
                DWORD merr = GetLastError();
                if (merr == ERROR_INVALID_HANDLE || merr == ERROR_DEVICE_NOT_CONNECTED || merr == ERROR_OPERATION_ABORTED) {
                    logErr("GetOverlappedResult disconnected! Err: %lu", merr);
                    break;
                }
                pendingRead = false; Sleep(50); continue;
            }
            
            pendingRead = false;
            if (mbr > 0) {
                if (first) { LogFirstPkt("ReadFile", mb.data(), mbr); first = false; }
                PushPacket(mb.data(), mbr, ctx->hNewPkt);
            }
        }
        CloseHandle(hem);
        CloseHandle(hf);
    } else {
        logErr("Failed to open device handle for reading! Err: %lu", GetLastError());
    }

    logLine("ReadThread [HID] exited loop");
    ctx->disconnected = true; SetEvent(ctx->hNewPkt); 
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r={};
    if(buf.size()<8) return r;
    auto toAxis=[](BYTE b,bool inv)->SHORT{
        int v=inv?(128-(int)b):((int)b-128);v*=256;
        if(v>32767)v=32767;if(v<-32768)v=-32768;return (SHORT)v;};

    // Заполни маппинг по необходимости после получения пакетов
    (void)toAxis;
    return r;
}

inline bool keyDown(int vk){ return (GetAsyncKeyState(vk)&0x8000)!=0; }

static ReadCtx rtCtx;

int main() {
    logOpen();
    InitializeCriticalSection(&gPkt.cs);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    uiInit(); uiFrame();
    uiStatus(false,false,false,MODE_UNKNOWN,0);
    uiSnifferState(false);

    // 1. ViGEm
    const auto client=vigem_alloc();
    if(!client){uiMsg("FATAL: vigem_alloc",CC_RED); Sleep(3000); logClose(); return -1;}
    if(!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found.",CC_RED); Sleep(3000); vigem_free(client); logClose(); return -1;}
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: vigem_target_add",CC_RED); Sleep(3000);
        vigem_target_free(pad);vigem_disconnect(client);vigem_free(client); logClose(); return -1;}
    logLine("ViGEm OK");

    HG hNewPkt(CreateEvent(NULL, FALSE, FALSE, NULL));
    rtCtx.hNewPkt = hNewPkt;

    bool globalRunning = true;
    bool prevS=false, prevEsc=false;
    bool snifOn=false;
    DWORD pkts=0;

    int notFoundCount = 0;
    bool firstRun = true;

    // Цикл переподключения
    while (globalRunning) {
        WorkMode mode = MODE_UNKNOWN;
        DWORD rSz = 64;
        bool isGamepad = false;

        uiClearMsg();
        
        // Главный цикл поиска
        while (globalRunning && mode == MODE_UNKNOWN) {
            
            // Если ищем дольше 10 секунд - пытаемся физически пересоздать подключение Bluetooth
            if (firstRun || notFoundCount >= 10) { 
                ForceConnectBluetoothHID();
                notFoundCount = 0;
                firstRun = false;
                Sleep(2500); // Даём Windows время поднять драйверы
            }

            uiMsg("Scanning for Nacon MG-X (HID)...", CC_YEL);
            
            char hidPath[512] = {};
            if (FindHIDPath(hidPath, sizeof(hidPath), &rSz, &isGamepad)) {
                
                // Защита от кривых дескрипторов (0 байт)
                if (rSz < 8) rSz = 64;
                if (rSz > PKT_MAX) rSz = PKT_MAX;

                strncpy_s(rtCtx.devPath, sizeof(rtCtx.devPath), hidPath, sizeof(hidPath)-1);
                mode = MODE_HID;
                rtCtx.mode = MODE_HID;
                logLine("HID mode detected");

                if (!isGamepad) {
                    uiMsg("Warning: Device does not report standard gamepad usage.", CC_YEL);
                } else {
                    uiMsg("Bluetooth HID Connected Successfully", CC_GRN);
                }
                break;
            }

            if (keyDown(VK_ESCAPE)) { globalRunning = false; break; }

            notFoundCount++;
            Sleep(1000); // Сканируем ровно 1 раз в секунду
        }

        if (!globalRunning) break;

        rtCtx.pktSize = rSz;
        rtCtx.stop = false;
        rtCtx.disconnected = false;

        uiStatus(true, true, true, mode, pkts);

        // Старт потока чтения
        HANDLE hThread = CreateThread(NULL, 0, ReadThread, &rtCtx, 0, NULL);
        if (!hThread) {
            uiMsg("FATAL: CreateThread",CC_RED); Sleep(3000); break;
        }

        std::vector<BYTE> rbuf(rSz, 0), pbuf(rSz, 0);

        // Внутренний цикл передачи пакетов
        while (!rtCtx.disconnected && globalRunning) {
            bool curS=keyDown('S'), curEsc=keyDown(VK_ESCAPE);
            if (curEsc && !prevEsc) { globalRunning = false; break; }
            if (curS && !prevS) {
                snifOn=!snifOn; uiSnifferState(snifOn);
            }
            prevS=curS; prevEsc=curEsc;

            if (WaitForSingleObject(hNewPkt, 10) != WAIT_OBJECT_0) continue;

            DWORD sz=0;
            EnterCriticalSection(&gPkt.cs);
            if (gPkt.ready) {
                sz=min(gPkt.size,(DWORD)rSz);
                memcpy(rbuf.data(),gPkt.data,sz);
                gPkt.ready=false;
            }
            LeaveCriticalSection(&gPkt.cs);
            if (sz == 0) continue;

            ++pkts;
            uiRawBytes(rbuf.data(), min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
            SnifferDelta(rbuf, pbuf, sz, pkts, snifOn);

            XUSB_REPORT xr = MapNaconToXbox(rbuf);
            vigem_target_x360_update(client, pad, xr);
            
            uiGamepad(xr);
            uiStatus(true, true, true, mode, pkts);
        }

        // Очистка перед переподключением
        rtCtx.stop = true;
        
        if (WaitForSingleObject(hThread, 3000) == WAIT_TIMEOUT) {
            logErr("Thread stuck! Terminating forcibly.");
            TerminateThread(hThread, 0);
        }
        CloseHandle(hThread);

        uiStatus(true, false, false, MODE_UNKNOWN, pkts);
        if (globalRunning) {
            uiClearMsg();
            uiMsg("Device lost or thread exited. Reconnecting...", CC_RED);
            logLine("Connection dropped. Restarting discovery...");
            
            // Если устройство отвалилось, форсируем пинок на следующем тике
            notFoundCount = 10; 
            Sleep(1000);
        }
    }

    vigem_target_remove(client,pad); vigem_target_free(pad);
    vigem_disconnect(client); vigem_free(client);
    DeleteCriticalSection(&gPkt.cs);
    logLine("\nDone. Packets: %lu", pkts);
    logClose(); uiRestore();
    return 0;
}
