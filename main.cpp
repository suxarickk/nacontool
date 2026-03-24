// Порядок инклюдов критичен:
// winsock2.h и ws2bth.h ОБЯЗАТЕЛЬНО до windows.h
// иначе winsock1/winsock2 конфликт
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2bth.h>
#include <windows.h>
#include <bluetoothapis.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <atomic>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bthprops.lib")

// ─── L2CAP PSM каналы HID ─────────────────────────────────────────
//  0x11 = HID Control   (команды)
//  0x13 = HID Interrupt (входные данные — кнопки, стики)
#define HID_PSM_CONTROL   0x11
#define HID_PSM_INTERRUPT 0x13

// SO_BTH_MTU может отсутствовать в старых SDK — определяем сами
#ifndef SO_BTH_MTU
#define SO_BTH_MTU 0x8007
#endif

// ─── UI constants ─────────────────────────────────────────────────
constexpr int   UI_W         = 80;
constexpr int   UI_H         = 24;
constexpr int   HEX_COLS     = 16;
constexpr int   HEX_ROWS     = 3;
constexpr int   SNIFFER_ROWS = 5;
constexpr int   BAR_LEN      = 5;
constexpr DWORD PKT_MAX      = 256;
constexpr int   BT_BUF       = 128;
constexpr int   RECV_TIMEOUT_MS = 200;

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
void logClose() { if (gLog) { fclose(gLog); gLog = nullptr; } }
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

// ─── Shared buffer ────────────────────────────────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX] = {};
    DWORD size  = 0;
    bool  ready = false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console UI ───────────────────────────────────────────────────
inline void cWrite(const char* s) {
    DWORD n=(DWORD)strlen(s); WriteConsoleA(hCon,s,n,&n,NULL);
}
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
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge (BT L2CAP)");
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
    cPr(32,0,"  BT L2CAP",CC_DGRY);
    cPr(0,1,SEP,CC_DGRY);
    cPr(1,2,"ViGEm:",CC_DGRY); cPr(18,2,"Nacon:",CC_DGRY); cPr(35,2,"Xbox:",CC_DGRY);
    cPr(50,2,"Chan:",CC_DGRY); cPr(62,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY); cPr(11,4,"LB",CC_DGRY); cPr(34,4,"BACK",CC_DGRY);
    cPr(42,4,"GUIDE",CC_DGRY); cPr(51,4,"START",CC_DGRY);
    cPr(62,4,"RB",CC_DGRY); cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY); cPr(24,6,"L-STICK:",CC_DGRY); cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY); cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY); cPr(0,10,"  RAW DATA:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY); cPr(0,15,"  SNIFFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL); cPr(4,22," sniffer on/off",CC_DGRY);
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
void uiStatus(bool vig,bool nac,bool xbx,bool chan,DWORD pkts) {
    cPr(7,2,  vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    cPr(55,2, chan?"[INT]":"[---]",chan?CC_CYN:CC_DGRY);
    char tmp[16]; snprintf(tmp,sizeof(tmp),"%-9lu",pkts); cPr(69,2,tmp,CC_DGRY);
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

void SnifferDelta(const BYTE* cur,BYTE* prev,DWORD sz,DWORD pktNum,bool show) {
    char line[UI_W+2]={}; int pos=0;
    for(DWORD i=0;i<sz&&pos<UI_W-12;i++) {
        if(cur[i]!=prev[i]) {
            int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",i,prev[i],cur[i]);
            if(n>0) pos+=n;
        }
    }
    if(pos>0) { if(show) uiSnifferAdd(line); logLine("PKT%-6lu  %s",pktNum,line); }
    memcpy(prev,cur,sz);
}

// ─────────────────────────────────────────────────────────────────
//  FindNaconBtAddr
//
//  Ищет среди всех известных BT-устройств то, в имени которого
//  есть "MG-X" или "Nacon". Логирует все найденные устройства.
// ─────────────────────────────────────────────────────────────────
BTH_ADDR FindNaconBtAddr() {
    BLUETOOTH_DEVICE_SEARCH_PARAMS sp = {};
    sp.dwSize               = sizeof(sp);
    sp.fReturnAuthenticated = TRUE;
    sp.fReturnRemembered    = TRUE;
    sp.fReturnConnected     = TRUE;
    sp.fReturnUnknown       = FALSE;
    sp.cTimeoutMultiplier   = 2;

    BLUETOOTH_DEVICE_INFO info = {};
    info.dwSize = sizeof(info);

    HANDLE hFind = BluetoothFindFirstDevice(&sp, &info);
    if (!hFind) {
        // Нет ни одного paired устройства — нормально при первом запуске
        logLine("BluetoothFindFirstDevice: no devices (err=%lu)", GetLastError());
        return 0;
    }

    logLine("--- BT device scan ---");
    BTH_ADDR found = 0;
    do {
        const BYTE* b = info.Address.rgBytes;
        logLine("  %S  MAC=%02X:%02X:%02X:%02X:%02X:%02X  conn=%d auth=%d",
                info.szName,
                b[5],b[4],b[3],b[2],b[1],b[0],
                info.fConnected, info.fAuthenticated);

        if (wcsstr(info.szName,L"MG-X") ||
            wcsstr(info.szName,L"Nacon") ||
            wcsstr(info.szName,L"NACON"))
        {
            found = info.Address.ullLong;
            logLine("  ^-- TARGET FOUND");
        }
    } while (BluetoothFindNextDevice(hFind,&info));

    BluetoothFindDeviceClose(hFind);
    logLine("--- BT scan done ---");
    return found;
}

// ─────────────────────────────────────────────────────────────────
//  ConnectL2CAP
//
//  Открывает L2CAP сокет к заданному PSM.
//  recv() таймаут 200мс — чтобы поток мог проверять флаг stop.
// ─────────────────────────────────────────────────────────────────
SOCKET ConnectL2CAP(BTH_ADDR addr, ULONG psm) {
    SOCKET s = socket(AF_BTH, SOCK_SEQPACKET, BTHPROTO_L2CAP);
    if (s == INVALID_SOCKET) {
        logErr("socket() err=%d", WSAGetLastError());
        return INVALID_SOCKET;
    }

    DWORD to = (DWORD)RECV_TIMEOUT_MS;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));

    // MTU — максимальный размер L2CAP пакета
    int mtu = BT_BUF;
    setsockopt(s, SOL_BLUETOOTH, SO_BTH_MTU, (const char*)&mtu, sizeof(mtu));

    SOCKADDR_BTH sa = {};
    sa.addressFamily = AF_BTH;
    sa.btAddr        = addr;
    sa.port          = (ULONG)psm;

    logLine("ConnectL2CAP PSM=0x%02lX ...", psm);
    if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) != 0) {
        logErr("connect() PSM=0x%02lX err=%d", psm, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    logLine("L2CAP PSM=0x%02lX connected", psm);
    return s;
}

// ─── Shared state read thread ─────────────────────────────────────
struct ReadCtx {
    SOCKET            sock    = INVALID_SOCKET;
    HANDLE            hNewPkt = INVALID_HANDLE_VALUE;
    std::atomic<bool> stop    {false};
    std::atomic<bool> disconnected {false};
};

static void PushPacket(const BYTE* d,DWORD sz,HANDLE ev) {
    EnterCriticalSection(&gPkt.cs);
    DWORD s=min(sz,(DWORD)PKT_MAX);
    memcpy(gPkt.data,d,s); gPkt.size=s; gPkt.ready=true;
    LeaveCriticalSection(&gPkt.cs);
    SetEvent(ev);
}

// ─────────────────────────────────────────────────────────────────
//  ReadThread
//
//  Читает L2CAP пакеты через recv().
//  Таймаут 200мс — поток не зависает, проверяет stop каждые 200мс.
//
//  Первый байт BT HID пакета:
//    0xA1 = DATA(A) | INPUT(1) — стандартный входной репорт.
//    После него данные геймпада начинаются с buf[1].
//    Логируем всё для анализа.
// ─────────────────────────────────────────────────────────────────
DWORD WINAPI ReadThread(LPVOID param) {
    ReadCtx* ctx = reinterpret_cast<ReadCtx*>(param);
    logLine("ReadThread started (L2CAP)");

    BYTE  buf[BT_BUF] = {};
    bool  first   = true;
    DWORD pktNum  = 0;

    while (!ctx->stop) {
        int br = recv(ctx->sock, (char*)buf, sizeof(buf), 0);

        if (br > 0) {
            if (first) {
                char raw[512]={}; int pos=0;
                for(int j=0;j<br&&j<48&&pos<490;j++){
                    int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",buf[j]);if(n>0)pos+=n;}
                logLine("FIRST_PKT size=%d  header=0x%02X", br, buf[0]);
                logLine("  RAW: %s", raw);
                if (buf[0] == 0xA1) {
                    logLine("  BT HID header 0xA1 present. Data at buf[1]");
                    if (br > 1) logLine("  buf[1]=0x%02X (Report ID or first data byte)", buf[1]);
                } else {
                    logLine("  No 0xA1 header. Raw data starts at buf[0]");
                }
                first = false;
            }
            pktNum++;
            PushPacket(buf, (DWORD)br, ctx->hNewPkt);

        } else if (br == 0) {
            logErr("recv()=0 — device closed connection");
            break;
        } else {
            int err = WSAGetLastError();
            // WSAETIMEDOUT — нормально, проверяем stop и читаем снова
            if (err == WSAETIMEDOUT) continue;
            // Эти коды = нормальное завершение при stop
            if (err == WSAEINTR || err == WSAENOTSOCK ||
                err == WSAECONNRESET || err == WSAENOTCONN ||
                err == WSAESHUTDOWN) {
                logLine("recv() stopped cleanly (err=%d)", err);
                break;
            }
            logErr("recv() err=%d", err);
            break;
        }
    }

    logLine("ReadThread done. L2CAP packets: %lu", pktNum);
    ctx->disconnected = true;
    SetEvent(ctx->hNewPkt);
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox
//
//  Автоматически пропускает BT HID заголовок 0xA1 если он есть.
//  Заполни маппинг после получения FIRST_PKT в sniffer.log.
//
//  d[] — данные после заголовка (Report ID и далее):
//    d[0] = Report ID (если используется)
//    d[1] = D-pad / hat-switch (0-7, нейтраль обычно 8 или 0x0F)
//    d[2] = кнопки (маски)
//    d[3] = кнопки (маски)
//    d[4] = LX (0-255, центр=128)
//    d[5] = LY (0-255, центр=128, инвертирован)
//    d[6] = RX
//    d[7] = RY
//    d[8] = LT (0-255)
//    d[9] = RT (0-255)
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const BYTE* buf, DWORD sz) {
    XUSB_REPORT r = {};
    if (sz < 2) return r;

    // Пропускаем BT HID заголовок 0xA1
    const BYTE* d   = (buf[0] == 0xA1 && sz > 1) ? buf+1 : buf;
    DWORD       dsz = (buf[0] == 0xA1 && sz > 1) ? sz-1  : sz;

    if (dsz < 2) return r;

    auto toAxis = [](BYTE b, bool inv) -> SHORT {
        int v = inv ? (128-(int)b) : ((int)b-128);
        v *= 256;
        if (v >  32767) v =  32767;
        if (v < -32768) v = -32768;
        return (SHORT)v;
    };

    // ── Раскомментируй после анализа sniffer.log ─────────────────
    //
    // КНОПКИ:
    // if(dsz>2 && d[2]&0x??) r.wButtons|=XUSB_GAMEPAD_A;
    // if(dsz>2 && d[2]&0x??) r.wButtons|=XUSB_GAMEPAD_B;
    // if(dsz>2 && d[2]&0x??) r.wButtons|=XUSB_GAMEPAD_X;
    // if(dsz>2 && d[2]&0x??) r.wButtons|=XUSB_GAMEPAD_Y;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_LEFT_SHOULDER;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_RIGHT_SHOULDER;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_START;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_BACK;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_LEFT_THUMB;
    // if(dsz>3 && d[3]&0x??) r.wButtons|=XUSB_GAMEPAD_RIGHT_THUMB;
    //
    // D-PAD (hat-switch 0-7, нейтраль=8 или 0x0F):
    // if(dsz>1) switch(d[1]&0x0F){
    //   case 0: r.wButtons|=XUSB_GAMEPAD_DPAD_UP;                            break;
    //   case 1: r.wButtons|=XUSB_GAMEPAD_DPAD_UP|XUSB_GAMEPAD_DPAD_RIGHT;   break;
    //   case 2: r.wButtons|=XUSB_GAMEPAD_DPAD_RIGHT;                         break;
    //   case 3: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_RIGHT; break;
    //   case 4: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN;                          break;
    //   case 5: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_LEFT;  break;
    //   case 6: r.wButtons|=XUSB_GAMEPAD_DPAD_LEFT;                          break;
    //   case 7: r.wButtons|=XUSB_GAMEPAD_DPAD_UP|XUSB_GAMEPAD_DPAD_LEFT;    break;
    // }
    //
    // СТИКИ:
    // if(dsz>5){ r.sThumbLX=toAxis(d[4],false); r.sThumbLY=toAxis(d[5],true); }
    // if(dsz>7){ r.sThumbRX=toAxis(d[6],false); r.sThumbRY=toAxis(d[7],true); }
    //
    // ТРИГГЕРЫ:
    // if(dsz>9){ r.bLeftTrigger=d[8]; r.bRightTrigger=d[9]; }

    (void)toAxis;
    return r;
}

inline bool keyDown(int vk) { return (GetAsyncKeyState(vk)&0x8000)!=0; }
static ReadCtx rtCtx;

int main() {
    logOpen();
    InitializeCriticalSection(&gPkt.cs);
    SetPriorityClass(GetCurrentProcess(),HIGH_PRIORITY_CLASS);

    uiInit(); uiFrame();
    uiStatus(false,false,false,false,0);
    uiSnifferState(false);

    // 1. Winsock
    WSADATA wsd={};
    if (WSAStartup(MAKEWORD(2,2),&wsd)!=0) {
        uiMsg("FATAL: WSAStartup failed",CC_RED);
        logErr("WSAStartup: %d",WSAGetLastError());
        Sleep(3000); logClose(); return -1;
    }
    logLine("WinSock OK");

    // 2. ViGEm
    const auto client=vigem_alloc();
    if (!client){uiMsg("FATAL: vigem_alloc",CC_RED);Sleep(3000);WSACleanup();logClose();return -1;}
    if (!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found. Install the driver.",CC_RED);
        Sleep(3000);vigem_free(client);WSACleanup();logClose();return -1;}
    const auto pad=vigem_target_x360_alloc();
    if (!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: vigem_target_add",CC_RED);
        Sleep(3000);vigem_target_free(pad);vigem_disconnect(client);vigem_free(client);WSACleanup();logClose();return -1;}
    logLine("ViGEm OK");
    uiStatus(true,false,true,false,0);

    // 3. Событие
    HANDLE hNewPkt=CreateEvent(NULL,FALSE,FALSE,NULL);
    if (!hNewPkt){uiMsg("FATAL: CreateEvent",CC_RED);Sleep(3000);logClose();return -1;}
    rtCtx.hNewPkt=hNewPkt;

    bool  globalRunning=true;
    bool  prevS=false,prevEsc=false,snifOn=false;
    DWORD pkts=0;
    BYTE  prevBuf[BT_BUF]={};

    // 4. Главный цикл (переподключение)
    while (globalRunning) {

        // Поиск MAC
        BTH_ADDR btAddr=0;
        logLine("--- Searching for Nacon ---");
        while (globalRunning && btAddr==0) {
            if (keyDown(VK_ESCAPE)){globalRunning=false;break;}
            uiMsg("Searching for paired Nacon MG-X...",CC_YEL);
            btAddr=FindNaconBtAddr();
            if (btAddr==0){logLine("Not found, retry in 2s");Sleep(2000);}
        }
        if (!globalRunning) break;

        // Подключение: сначала HID Interrupt (PSM 0x13), потом HID Control (0x11)
        uiMsg("Connecting via BT L2CAP...",CC_YEL);
        SOCKET sock=ConnectL2CAP(btAddr,HID_PSM_INTERRUPT);
        if (sock==INVALID_SOCKET){
            logLine("PSM 0x13 failed, trying PSM 0x11...");
            sock=ConnectL2CAP(btAddr,HID_PSM_CONTROL);
        }
        if (sock==INVALID_SOCKET){
            uiMsg("L2CAP connect failed. Ensure device is paired. Retry in 3s...",CC_RED);
            Sleep(3000); continue;
        }

        uiMsg("Connected! Reading gamepad data...",CC_GRN);
        uiStatus(true,true,true,true,pkts);

        rtCtx.sock=sock;
        rtCtx.stop=false;
        rtCtx.disconnected=false;

        HANDLE hThread=CreateThread(NULL,0,ReadThread,&rtCtx,0,NULL);
        if (!hThread){
            uiMsg("FATAL: CreateThread",CC_RED);
            logErr("CreateThread: %lu",GetLastError());
            closesocket(sock); Sleep(3000); break;
        }

        // Цикл обработки пакетов
        while (!rtCtx.disconnected && globalRunning) {
            bool curS=keyDown('S'), curEsc=keyDown(VK_ESCAPE);
            if (curEsc&&!prevEsc){globalRunning=false;break;}
            if (curS&&!prevS){
                snifOn=!snifOn; uiSnifferState(snifOn);
                logLine("--- Sniffer %s PKT %lu ---",snifOn?"ON":"OFF",pkts);}
            prevS=curS; prevEsc=curEsc;

            if (WaitForSingleObject(hNewPkt,10)!=WAIT_OBJECT_0) continue;

            DWORD sz=0;
            BYTE localBuf[PKT_MAX]={};
            EnterCriticalSection(&gPkt.cs);
            if (gPkt.ready){sz=min(gPkt.size,(DWORD)sizeof(localBuf));memcpy(localBuf,gPkt.data,sz);gPkt.ready=false;}
            LeaveCriticalSection(&gPkt.cs);
            if (sz==0) continue;

            ++pkts;
            uiRawBytes(localBuf,min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
            SnifferDelta(localBuf,prevBuf,min(sz,(DWORD)BT_BUF),pkts,snifOn);
            XUSB_REPORT xr=MapNaconToXbox(localBuf,sz);
            vigem_target_x360_update(client,pad,xr);
            uiGamepad(xr);
            uiStatus(true,true,true,true,pkts);
        }

        // Стоп потока
        rtCtx.stop=true;
        if (rtCtx.sock!=INVALID_SOCKET){
            closesocket(rtCtx.sock);
            rtCtx.sock=INVALID_SOCKET;
        }
        if (WaitForSingleObject(hThread,3000)==WAIT_TIMEOUT){
            logErr("ReadThread stuck — terminating");
            TerminateThread(hThread,0);
        }
        CloseHandle(hThread);

        uiStatus(true,false,false,false,pkts);
        if (globalRunning){uiMsg("Disconnected. Reconnecting in 2s...",CC_RED);Sleep(2000);}
    }

    // 5. Cleanup
    CloseHandle(hNewPkt);
    vigem_target_remove(client,pad); vigem_target_free(pad);
    vigem_disconnect(client); vigem_free(client);
    WSACleanup();
    DeleteCriticalSection(&gPkt.cs);
    logLine("\nDone. Total packets: %lu",pkts);
    logClose(); uiRestore();
    return 0;
}
