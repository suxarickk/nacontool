#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ─── Device config ────────────────────────────────────────────────
#define NACON_VID 0x3285
#define NACON_PID 0x0644

// ─── Network ──────────────────────────────────────────────────────
#define UDP_PORT        7331
#define UDP_PKT_SIZE    16
#define UDP_MAGIC       0x4E41434F  // "NACO"
// Если Android-пакет старше этого — считаем источник мёртвым
#define UDP_TIMEOUT_MS  300

// ─── UI ───────────────────────────────────────────────────────────
constexpr int   UI_W         = 80;
constexpr int   UI_H         = 24;
constexpr int   HEX_COLS     = 16;
constexpr int   HEX_ROWS     = 3;
constexpr int   SNIFFER_ROWS = 5;
constexpr int   BAR_LEN      = 5;
constexpr DWORD MAX_HID_REQ  = 4096;
constexpr DWORD PKT_MAX      = 256;

enum CC : WORD {
    CC_BLK=0,CC_DGRN=2,CC_DGRY=8,CC_GRN=10,
    CC_CYN=11,CC_RED=12,CC_YEL=14,CC_WHT=15,CC_GRY=7
};
enum InputSource { SRC_NONE=0, SRC_ANDROID=1, SRC_HID=2 };

// ─── UDP пакет ────────────────────────────────────────────────────
#pragma pack(push,1)
struct UdpPkt {
    WORD  buttons;
    BYTE  lt, rt;
    SHORT lx, ly, rx, ry;
    DWORD magic;
};
#pragma pack(pop)
static_assert(sizeof(UdpPkt)==UDP_PKT_SIZE,"udp packet size");

// ─── Shared state ─────────────────────────────────────────────────
struct UdpState {
    XUSB_REPORT  report  = {};
    DWORD        lastMs  = 0;
    bool         hasData = false;
    CRITICAL_SECTION cs;
};
static UdpState gUdp;

struct HidPkt {
    BYTE  data[PKT_MAX]={};
    DWORD size=0;
    bool  ready=false;
    CRITICAL_SECTION cs;
};
static HidPkt gHid;

static HANDLE hCon=INVALID_HANDLE_VALUE, hConIn=INVALID_HANDLE_VALUE;
static FILE*  gLog=nullptr;

// ─── Log ──────────────────────────────────────────────────────────
void logOpen(){ fopen_s(&gLog,"sniffer.log","w"); if(gLog){fprintf(gLog,"=== sniffer.log ===\n\n");fflush(gLog);} }
void logLine(const char* fmt,...){ if(!gLog)return; va_list a;va_start(a,fmt);vfprintf(gLog,fmt,a);va_end(a);fputc('\n',gLog);fflush(gLog); }
void logErr (const char* fmt,...){ if(!gLog)return; fprintf(gLog,"[ERR] ");va_list a;va_start(a,fmt);vfprintf(gLog,fmt,a);va_end(a);fputc('\n',gLog);fflush(gLog); }
void logClose(){ if(gLog){fclose(gLog);gLog=nullptr;} }

// ─── Console ──────────────────────────────────────────────────────
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
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge");
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
    cPr(50,2,"Src:",CC_DGRY);cPr(60,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY);cPr(11,4,"LB",CC_DGRY);cPr(34,4,"BACK",CC_DGRY);
    cPr(42,4,"GUIDE",CC_DGRY);cPr(51,4,"START",CC_DGRY);cPr(62,4,"RB",CC_DGRY);cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY);cPr(24,6,"L-STICK:",CC_DGRY);cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY);cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY);cPr(0,10,"  RAW HID:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY);cPr(0,15,"  SNIFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL);cPr(4,22," snifer on/off",CC_DGRY);
    cPr(20,22,"[ESC]",CC_YEL);cPr(25,22," exit",CC_DGRY);
    char portStr[16];snprintf(portStr,sizeof(portStr),"UDP:%d",UDP_PORT);
    cPr(42,22,portStr,CC_CYN);
}
void uiBtn(int x,int y,const char* l,bool on){
    cXY(x,y);cCol(CC_DGRY);cWrite("[");cCol(on?CC_GRN:CC_DGRY);cWrite(l);cCol(CC_DGRY);cWrite("]");
}
void uiBar(int x,int y,BYTE v){
    int f=v*BAR_LEN/255;char s[BAR_LEN+3]={};s[0]='[';
    for(int i=0;i<BAR_LEN;i++)s[i+1]=(i<f)?'#':'.';s[BAR_LEN+1]=']';s[BAR_LEN+2]='\0';
    cXY(x,y);cCol(v>10?CC_GRN:CC_DGRY);cWrite(s);
}
void uiAxis(int x,int y,SHORT v){
    char b[7];snprintf(b,sizeof(b),"%+05d",(int)v);cPr(x,y,b,v!=0?CC_YEL:CC_DGRY);
}
void uiMsg(const char* s,CC fg=CC_YEL){
    char pad[82]={};snprintf(pad,81,"  %-76s",s);cPr(0,23,pad,fg);
}
void uiClearMsg(){ char pad[82];memset(pad,' ',80);pad[80]='\0';cPr(0,23,pad,CC_BLK); }
void uiStatus(bool vig,bool nac,bool xbx,InputSource src,DWORD pkts){
    cPr(7,2,  vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    const char* ss=(src==SRC_ANDROID)?"[BT] ":(src==SRC_HID)?"[HID]":"[---]";
    CC sc=(src==SRC_ANDROID)?CC_CYN:(src==SRC_HID)?CC_GRN:CC_DGRY;
    cPr(54,2,ss,sc);
    char tmp[16];snprintf(tmp,sizeof(tmp),"%-9lu",pkts);cPr(65,2,tmp,CC_DGRY);
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
        cXY(0,11+row);DWORD start=(DWORD)(row*HEX_COLS),drawn=0;
        for(DWORD col=0;col<(DWORD)HEX_COLS&&start+col<sz;col++,drawn++){
            BYTE b=buf[start+col];cCol(b?CC_YEL:CC_DGRY);snprintf(tmp,sizeof(tmp),"%02X ",b);cWrite(tmp);
        }
        cCol(CC_DGRY);for(DWORD i=drawn;i<(DWORD)HEX_COLS;i++)cWrite("   ");
    }
}
static char snLines[SNIFFER_ROWS][UI_W+2]={};static int snHead=0;
void uiSnifferAdd(const char* line){
    strncpy_s(snLines[snHead],UI_W+1,line,UI_W);snHead=(snHead+1)%SNIFFER_ROWS;
    char pad[UI_W+2];
    for(int i=0;i<SNIFFER_ROWS;i++){
        int idx=(snHead+i)%SNIFFER_ROWS;snprintf(pad,sizeof(pad),"%-*s",UI_W,snLines[idx]);
        cPr(0,16+i,pad,snLines[idx][0]?CC_YEL:CC_DGRY);
    }
}
void uiSnifferState(bool on){ cPr(9,15,on?"[ON] ":"[OFF]",on?CC_GRN:CC_RED); }
void SnifferDelta(const std::vector<BYTE>& cur,std::vector<BYTE>& prev,DWORD sz,DWORD pktNum,bool show){
    DWORD m=(DWORD)min((size_t)sz,min(cur.size(),prev.size()));
    char line[UI_W+2]={};int pos=0;
    for(DWORD i=0;i<m&&pos<UI_W-12;i++){
        if(cur[i]!=prev[i]){ int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",i,prev[i],cur[i]);if(n>0)pos+=n; }
    }
    if(pos>0){ if(show)uiSnifferAdd(line); logLine("PKT%-6lu  %s",pktNum,line); }
    prev=cur;
}

// ─── RAII handle ──────────────────────────────────────────────────
struct HG {
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE):h(h_){}
    ~HG(){ if(h!=INVALID_HANDLE_VALUE)CloseHandle(h); }
    HG(const HG&)=delete;HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){ if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=nh; }
    operator HANDLE()const{ return h; }
    bool valid()const{ return h!=INVALID_HANDLE_VALUE; }
};

// ─────────────────────────────────────────────────────────────────
//  UdpThread
//
//  Оптимизации latency на стороне PC:
//    • SO_RCVBUF = 4096 — минимальный буфер приёма
//      (не накапливаем старые пакеты — только свежий)
//    • recvfrom таймаут 100 мс чтобы проверять ctx->stop
//    • Пакет передаётся сразу без очереди
// ─────────────────────────────────────────────────────────────────
struct UdpCtx { volatile bool stop; };

DWORD WINAPI UdpThread(LPVOID param){
    UdpCtx* ctx=reinterpret_cast<UdpCtx*>(param);

    SOCKET sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock==INVALID_SOCKET){ logErr("UDP socket: %d",WSAGetLastError()); return 1; }

    // Минимальный буфер — берём только самый свежий пакет
    int rcvBuf=4096;
    setsockopt(sock,SOL_SOCKET,SO_RCVBUF,(const char*)&rcvBuf,sizeof(rcvBuf));

    // Таймаут recv для проверки ctx->stop
    DWORD tv=100;
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(const char*)&tv,sizeof(tv));

    sockaddr_in addr={};
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(UDP_PORT);
    if(bind(sock,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){
        logErr("UDP bind: %d",WSAGetLastError());closesocket(sock);return 1;
    }
    logLine("UDP listening on port %d",UDP_PORT);

    UdpPkt pkt={};sockaddr_in from={};int fl=sizeof(from);
    bool firstPkt=true;char clientIP[INET_ADDRSTRLEN]={};

    while(!ctx->stop){
        int r=recvfrom(sock,(char*)&pkt,sizeof(pkt),0,(sockaddr*)&from,&fl);
        if(r==SOCKET_ERROR){
            int e=WSAGetLastError();
            if(e==WSAETIMEDOUT||e==WSAEWOULDBLOCK) continue;
            logErr("UDP recvfrom: %d",e); break;
        }
        if(r!=UDP_PKT_SIZE) continue;
        if(pkt.magic!=UDP_MAGIC) continue;

        if(firstPkt){
            inet_ntop(AF_INET,&from.sin_addr,clientIP,sizeof(clientIP));
            logLine("Android connected from %s",clientIP);
            firstPkt=false;
        }

        XUSB_REPORT xr={};
        xr.wButtons=pkt.buttons; xr.bLeftTrigger=pkt.lt; xr.bRightTrigger=pkt.rt;
        xr.sThumbLX=pkt.lx; xr.sThumbLY=pkt.ly; xr.sThumbRX=pkt.rx; xr.sThumbRY=pkt.ry;

        EnterCriticalSection(&gUdp.cs);
        gUdp.report=xr; gUdp.lastMs=GetTickCount(); gUdp.hasData=true;
        LeaveCriticalSection(&gUdp.cs);
    }
    closesocket(sock);
    logLine("UDP thread stopped");
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  FindBestNaconInterface
// ─────────────────────────────────────────────────────────────────
bool FindBestNaconInterface(char* outPath,size_t pathMax,DWORD* outSize){
    GUID hidGuid;HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi=SetupDiGetClassDevs(&hidGuid,NULL,NULL,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
    if(hdi==INVALID_HANDLE_VALUE){logErr("SetupDiGetClassDevs: %lu",GetLastError());return false;}
    SP_DEVICE_INTERFACE_DATA did={};did.cbSize=sizeof(did);
    bool foundGP=false,found=false;DWORD bestSize=0;
    logLine("--- HID scan ---");
    for(int i=0;SetupDiEnumDeviceInterfaces(hdi,NULL,&hidGuid,i,&did);i++){
        DWORD req=0;SetupDiGetDeviceInterfaceDetail(hdi,&did,NULL,0,&req,NULL);
        if(req==0||req>MAX_HID_REQ)continue;
        std::vector<BYTE> buf(req);
        auto* det=reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if(!SetupDiGetDeviceInterfaceDetail(hdi,&did,det,req,NULL,NULL))continue;
        HANDLE ht=CreateFileA(det->DevicePath,0,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
        if(ht==INVALID_HANDLE_VALUE)continue;
        HIDD_ATTRIBUTES attr={sizeof(attr)};
        if(!HidD_GetAttributes(ht,&attr)){CloseHandle(ht);continue;}
        WORD up=0,use=0;DWORD inLen=0;
        PHIDP_PREPARSED_DATA ppd=nullptr;
        if(HidD_GetPreparsedData(ht,&ppd)){
            HIDP_CAPS caps={};if(HidP_GetCaps(ppd,&caps)==HIDP_STATUS_SUCCESS){up=caps.UsagePage;use=caps.Usage;inLen=caps.InputReportByteLength;}
            HidD_FreePreparsedData(ppd);
        }
        logLine("  [%d] VID=%04X PID=%04X Page=%02X Use=%02X InLen=%u",i,attr.VendorID,attr.ProductID,up,use,inLen);
        if(attr.VendorID==NACON_VID&&attr.ProductID==NACON_PID){
            bool isGP=(up==0x01&&(use==0x04||use==0x05));
            if(isGP&&!foundGP){logLine("  ^-- GAMEPAD");strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);bestSize=inLen;foundGP=true;found=true;}
            else if(!foundGP&&inLen>bestSize){logLine("  ^-- fallback InLen=%u",inLen);strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);bestSize=inLen;found=true;}
        }
        CloseHandle(ht);if(foundGP)break;
    }
    SetupDiDestroyDeviceInfoList(hdi);
    logLine("--- scan done found=%d size=%lu ---",(int)found,bestSize);
    if(outSize)*outSize=bestSize;return found;
}

// ─── HID read thread ──────────────────────────────────────────────
struct HidCtx { HANDLE hDev;char devPath[512];DWORD pktSize;HANDLE hEvt;volatile bool stop; };

static void PushHid(const BYTE* d,DWORD sz,HANDLE ev){
    EnterCriticalSection(&gHid.cs);
    DWORD s=min(sz,(DWORD)PKT_MAX);memcpy(gHid.data,d,s);gHid.size=s;gHid.ready=true;
    LeaveCriticalSection(&gHid.cs);SetEvent(ev);
}
static void LogFirst(const char* m,const BYTE* d,DWORD sz){
    char raw[256]={};int pos=0;
    for(DWORD j=0;j<sz&&j<16&&pos<240;j++){int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",d[j]);if(n>0)pos+=n;}
    logLine("FIRST_PKT[%s] RAW: %s",m,raw);
}
static HANDLE OpenOv(const char* path){
    HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(h==INVALID_HANDLE_VALUE)h=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    return h;
}

DWORD WINAPI HidReadThread(LPVOID param){
    HidCtx* ctx=reinterpret_cast<HidCtx*>(param);
    logLine("HidReadThread pktSize=%lu",ctx->pktSize);
    std::vector<BYTE> buf(max(ctx->pktSize,(DWORD)128),0);

    // GetFeature
    { static const BYTE ids[]={0x00,0x01,0x02,0x03,0x10,0x20,0x40};BYTE wid=0xFF;
      logLine("-- GetFeature --");
      for(BYTE id:ids){memset(buf.data(),0,ctx->pktSize);buf[0]=id;BOOL ok=HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize);DWORD err=GetLastError();logLine("  ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
        if(ok){bool nz=false;for(DWORD j=0;j<ctx->pktSize;j++)if(buf[j]){nz=true;break;}if(nz){wid=id;logLine("  ^-- WORKS!");break;}}}
      if(wid!=0xFF){logLine("METHOD:GetFeature ID=0x%02X",wid);bool first=true;
        while(!ctx->stop){memset(buf.data(),0,ctx->pktSize);buf[0]=wid;if(!HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize)){DWORD e=GetLastError();if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED)break;Sleep(50);continue;}
          if(first){LogFirst("GetFeature",buf.data(),ctx->pktSize);first=false;}PushHid(buf.data(),ctx->pktSize,ctx->hEvt);Sleep(8);}return 0;}}

    // GetInputReport
    { static const BYTE ids[]={0x00,0x01,0x02,0x03,0x10,0x20};BYTE wid=0xFF;
      logLine("-- GetInputReport --");
      for(BYTE id:ids){memset(buf.data(),0,ctx->pktSize);buf[0]=id;BOOL ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);DWORD err=GetLastError();logLine("  ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
        if(ok){bool nz=false;for(DWORD j=1;j<ctx->pktSize;j++)if(buf[j]){nz=true;break;}if(nz){wid=id;logLine("  ^-- WORKS!");break;}}}
      if(wid!=0xFF){logLine("METHOD:GetInputReport ID=0x%02X",wid);bool first=true;
        while(!ctx->stop){memset(buf.data(),0,ctx->pktSize);buf[0]=wid;if(!HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize)){DWORD e=GetLastError();if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED)break;Sleep(50);continue;}
          if(first){LogFirst("GetInputReport",buf.data(),ctx->pktSize);first=false;}PushHid(buf.data(),ctx->pktSize,ctx->hEvt);Sleep(8);}return 0;}}

    // ReadFile overlapped
    { static const DWORD sizes[]={64,65,32,16,128,8};logLine("-- ReadFile probe --");
      for(DWORD ps:sizes){
        if(ctx->stop)break;logLine("  size=%lu",ps);
        HANDLE hp=OpenOv(ctx->devPath);if(hp==INVALID_HANDLE_VALUE){logErr("  open failed %lu",GetLastError());break;}
        HANDLE hev=CreateEvent(NULL,TRUE,FALSE,NULL);std::vector<BYTE> pb(ps,0);OVERLAPPED pov={};pov.hEvent=hev;DWORD br=0;
        BOOL ok=ReadFile(hp,pb.data(),ps,&br,&pov);DWORD err=GetLastError();bool got=false;
        if(!ok&&err==ERROR_IO_PENDING){if(WaitForSingleObject(hev,2000)==WAIT_OBJECT_0&&GetOverlappedResult(hp,&pov,&br,FALSE)&&br>0)got=true;else CancelIo(hp);}
        else if(ok&&br>0)got=true;
        CloseHandle(hev);CloseHandle(hp);
        if(got){logLine("  ReadFile works size=%lu!",ps);
          HANDLE hf=OpenOv(ctx->devPath);if(hf==INVALID_HANDLE_VALUE){logErr("  final open failed");break;}
          HANDLE hem=CreateEvent(NULL,TRUE,FALSE,NULL);std::vector<BYTE> mb(ps,0);bool first=true;
          logLine("METHOD:ReadFile OVERLAPPED size=%lu",ps);
          while(!ctx->stop){OVERLAPPED mov={};mov.hEvent=hem;ResetEvent(hem);DWORD mbr=0;
            BOOL mok=ReadFile(hf,mb.data(),ps,&mbr,&mov);DWORD merr=GetLastError();
            if(!mok){if(merr==ERROR_IO_PENDING){DWORD wt=WaitForSingleObject(hem,500);
              if(wt==WAIT_TIMEOUT){if(ctx->stop){CancelIo(hf);GetOverlappedResult(hf,&mov,&mbr,TRUE);break;}continue;}
              if(wt!=WAIT_OBJECT_0)break;if(!GetOverlappedResult(hf,&mov,&mbr,FALSE)){merr=GetLastError();if(merr==ERROR_INVALID_HANDLE||merr==ERROR_DEVICE_NOT_CONNECTED||merr==ERROR_OPERATION_ABORTED)break;Sleep(50);continue;}}
            else{if(merr==ERROR_INVALID_HANDLE||merr==ERROR_DEVICE_NOT_CONNECTED||merr==ERROR_OPERATION_ABORTED)break;Sleep(50);continue;}}
            if(mbr==0)continue;if(first){LogFirst("ReadFile",mb.data(),mbr);first=false;}PushHid(mb.data(),mbr,ctx->hEvt);}
          CloseHandle(hem);CloseHandle(hf);return 0;}
        logLine("  size=%lu: no data",ps);}}

    // Blocking fallback
    { logLine("METHOD:Blocking ReadFile");bool first=true;
      while(!ctx->stop){DWORD br=0;BOOL ok=ReadFile(ctx->hDev,buf.data(),ctx->pktSize,&br,NULL);
        if(!ok){DWORD e=GetLastError();if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED||e==ERROR_OPERATION_ABORTED||e==ERROR_BROKEN_PIPE)break;Sleep(50);continue;}
        if(br==0)continue;if(first){LogFirst("Blocking",buf.data(),br);first=false;}PushHid(buf.data(),br,ctx->hEvt);}}

    logLine("HidReadThread done");return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapHidToXbox — заполни когда HID заработает
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapHidToXbox(const std::vector<BYTE>& buf){
    XUSB_REPORT r={};if(buf.size()<12)return r;
    auto toAxis=[](BYTE b,bool inv)->SHORT{int v=inv?(128-(int)b):((int)b-128);v*=256;if(v>32767)v=32767;if(v<-32768)v=-32768;return (SHORT)v;};
    // if(buf[?]&0x??) r.wButtons|=XUSB_GAMEPAD_A;
    // ...
    (void)toAxis;return r;
}

static bool prevS=false,prevEsc=false;
inline bool keyDown(int vk){ return (GetAsyncKeyState(vk)&0x8000)!=0; }
static UdpCtx udpCtx;
static HidCtx hidCtx;

int main(){
    logOpen();
    InitializeCriticalSection(&gHid.cs);
    InitializeCriticalSection(&gUdp.cs);
    memset(&udpCtx,0,sizeof(udpCtx));
    memset(&hidCtx,0,sizeof(hidCtx));

    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){logErr("WSAStartup");return -1;}

    // Повышаем приоритет процесса — снижает latency ViGEm
    SetPriorityClass(GetCurrentProcess(),HIGH_PRIORITY_CLASS);

    uiInit();uiFrame();
    uiStatus(false,false,false,SRC_NONE,0);
    uiSnifferState(false);

    // 1. ViGEm
    const auto client=vigem_alloc();
    if(!client){uiMsg("FATAL: vigem_alloc",CC_RED);logErr("vigem_alloc");Sleep(3000);logClose();return -1;}
    if(!VIGEM_SUCCESS(vigem_connect(client))){uiMsg("FATAL: ViGEmBus not found.",CC_RED);logErr("vigem_connect");Sleep(3000);vigem_free(client);logClose();return -1;}
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){uiMsg("FATAL: vigem_target_add",CC_RED);logErr("vigem_target_add");Sleep(3000);vigem_target_free(pad);vigem_disconnect(client);vigem_free(client);logClose();return -1;}
    logLine("ViGEm OK");

    // 2. UDP thread (всегда)
    udpCtx.stop=false;
    HANDLE hUdpThr=CreateThread(NULL,0,UdpThread,&udpCtx,0,NULL);
    if(hUdpThr) logLine("UDP thread started");

    // 3. HID (опционально)
    DWORD devSize=0;HG hNacon;bool hidOk=false;
    { char devPath[512]={};
      if(FindBestNaconInterface(devPath,sizeof(devPath),&devSize)){
          strncpy_s(hidCtx.devPath,sizeof(hidCtx.devPath),devPath,sizeof(devPath)-1);
          HANDLE h=CreateFileA(devPath,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
          if(h==INVALID_HANDLE_VALUE)h=CreateFileA(devPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
          if(h!=INVALID_HANDLE_VALUE){HidD_SetNumInputBuffers(h,64);hNacon.reset(h);hidOk=true;logLine("HID handle OK");}
      } else logLine("Nacon USB not found — Android-only mode");
    }
    DWORD rSz=max(devSize,(DWORD)65);
    if(hidOk){PHIDP_PREPARSED_DATA ppd;if(HidD_GetPreparsedData(hNacon,&ppd)){HIDP_CAPS c2;HidP_GetCaps(ppd,&c2);if(c2.InputReportByteLength>rSz)rSz=c2.InputReportByteLength;HidD_FreePreparsedData(ppd);}}
    if(rSz<8)rSz=8;if(rSz>PKT_MAX)rSz=PKT_MAX;

    HG hEvtHid(CreateEvent(NULL,FALSE,FALSE,NULL));
    hidCtx.hDev=hidOk?(HANDLE)hNacon:INVALID_HANDLE_VALUE;
    hidCtx.pktSize=rSz;hidCtx.hEvt=hEvtHid;hidCtx.stop=false;

    HANDLE hHidThr=INVALID_HANDLE_VALUE;
    if(hidOk){ hHidThr=CreateThread(NULL,0,HidReadThread,&hidCtx,0,NULL);logLine("HID thread started"); }

    uiStatus(true,hidOk,true,SRC_NONE,0);
    uiMsg(hidOk?"Waiting for Android app or HID data (port 7331)...":
                "USB HID N/A. Open Android app, enter PC IP, press Start.",CC_YEL);

    std::vector<BYTE> rbuf(rSz,0),pbuf(rSz,0);
    bool running=true,snifOn=false;DWORD pkts=0;
    InputSource lastSrc=SRC_NONE;

    // 4. Main loop
    while(running){
        bool curS=keyDown('S'),curEsc=keyDown(VK_ESCAPE);
        if(curEsc&&!prevEsc){running=false;break;}
        if(curS&&!prevS){snifOn=!snifOn;uiSnifferState(snifOn);logLine("--- Sniffer %s PKT %lu ---",snifOn?"ON":"OFF",pkts);}
        prevS=curS;prevEsc=curEsc;

        // ── Android UDP: высший приоритет ────────────────────────
        {
            EnterCriticalSection(&gUdp.cs);
            bool fresh=gUdp.hasData&&(GetTickCount()-gUdp.lastMs)<UDP_TIMEOUT_MS;
            XUSB_REPORT xr=gUdp.report;
            LeaveCriticalSection(&gUdp.cs);

            if(fresh){
                // Обновляем ViGEm сразу — не ждём событий
                vigem_target_x360_update(client,pad,xr);
                uiGamepad(xr);++pkts;
                if(lastSrc!=SRC_ANDROID){uiClearMsg();lastSrc=SRC_ANDROID;}
                uiStatus(true,hidOk,true,SRC_ANDROID,pkts);
                Sleep(1); // ~1 мс — ждём следующий пакет
                continue;
            }
        }

        // ── HID fallback ─────────────────────────────────────────
        if(WaitForSingleObject(hEvtHid,10)!=WAIT_OBJECT_0) continue;
        DWORD sz=0;
        EnterCriticalSection(&gHid.cs);
        if(gHid.ready){sz=min(gHid.size,(DWORD)rSz);memcpy(rbuf.data(),gHid.data,sz);gHid.ready=false;}
        LeaveCriticalSection(&gHid.cs);
        if(sz==0)continue;++pkts;
        uiRawBytes(rbuf.data(),min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
        SnifferDelta(rbuf,pbuf,sz,pkts,snifOn);
        XUSB_REPORT xr=MapHidToXbox(rbuf);
        vigem_target_x360_update(client,pad,xr);
        uiGamepad(xr);
        if(lastSrc!=SRC_HID){uiClearMsg();lastSrc=SRC_HID;}
        uiStatus(true,hidOk,true,SRC_HID,pkts);
    }

    // 5. Cleanup
    udpCtx.stop=true;hidCtx.stop=true;hNacon.reset();
    if(hHidThr!=INVALID_HANDLE_VALUE){if(WaitForSingleObject(hHidThr,3000)==WAIT_TIMEOUT)TerminateThread(hHidThr,0);CloseHandle(hHidThr);}
    if(hUdpThr){if(WaitForSingleObject(hUdpThr,2000)==WAIT_TIMEOUT)TerminateThread(hUdpThr,0);CloseHandle(hUdpThr);}
    vigem_target_remove(client,pad);vigem_target_free(pad);vigem_disconnect(client);vigem_free(client);
    DeleteCriticalSection(&gHid.cs);DeleteCriticalSection(&gUdp.cs);
    WSACleanup();
    logLine("\nDone. Packets: %lu",pkts);
    logClose();uiRestore();return 0;
}
