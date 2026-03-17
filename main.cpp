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

enum CC : WORD {
    CC_BLK=0,CC_DGRN=2,CC_DGRY=8,CC_GRN=10,
    CC_CYN=11,CC_RED=12,CC_YEL=14,CC_WHT=15,CC_GRY=7
};

static HANDLE hCon   = INVALID_HANDLE_VALUE;
static HANDLE hConIn = INVALID_HANDLE_VALUE;
static FILE*  gLog   = nullptr;

// ─── Logging (один файл) ──────────────────────────────────────────
void logOpen(){
    fopen_s(&gLog,"sniffer.log","w");
    if(gLog){ fprintf(gLog,"=== sniffer.log ===\n\n"); fflush(gLog); }
}
void logLine(const char* fmt,...){
    if(!gLog) return;
    va_list a; va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a);
    fputc('\n',gLog); fflush(gLog);
}
void logErr(const char* fmt,...){
    if(!gLog) return;
    fprintf(gLog,"[ERR] ");
    va_list a; va_start(a,fmt); vfprintf(gLog,fmt,a); va_end(a);
    fputc('\n',gLog); fflush(gLog);
}
void logClose(){ if(gLog){ fclose(gLog); gLog=nullptr; } }

// ─── Shared buffer ────────────────────────────────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX]={};
    DWORD size=0;
    bool  ready=false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console helpers ──────────────────────────────────────────────
inline void cWrite(const char* s){ DWORD n=(DWORD)strlen(s); WriteConsoleA(hCon,s,n,&n,NULL); }
void cXY(int x,int y){ COORD c={(SHORT)x,(SHORT)y}; SetConsoleCursorPosition(hCon,c); }
void cCol(CC f,CC b=CC_BLK){ SetConsoleTextAttribute(hCon,(WORD)((b<<4)|f)); }
void cPr(int x,int y,const char* s,CC f=CC_GRY,CC b=CC_BLK){ cXY(x,y); cCol(f,b); cWrite(s); }

void uiInit(){
    hCon  =GetStdHandle(STD_OUTPUT_HANDLE);
    hConIn=GetStdHandle(STD_INPUT_HANDLE);
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
void uiRestore(){
    CONSOLE_CURSOR_INFO ci={10,TRUE}; SetConsoleCursorInfo(hCon,&ci);
    SetConsoleTextAttribute(hCon,CC_GRY); cXY(0,23); cWrite("\n");
}
static const char* SEP="--------------------------------------------------------------------------------";
void uiFrame(){
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
    cPr(7,2,  vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2, nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2, xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    char tmp[20];
    snprintf(tmp,sizeof(tmp),"%-4lu",sz);   cPr(55,2,tmp,CC_YEL);
    snprintf(tmp,sizeof(tmp),"%-9lu",pkts); cPr(69,2,tmp,CC_DGRY);
}
void uiGamepad(const XUSB_REPORT& r){
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
void uiRawBytes(const BYTE* buf,DWORD sz){
    char tmp[4];
    for(int row=0;row<HEX_ROWS;row++){
        cXY(0,11+row);
        DWORD start=(DWORD)(row*HEX_COLS),drawn=0;
        for(DWORD col=0;col<(DWORD)HEX_COLS&&start+col<sz;col++,drawn++){
            BYTE b=buf[start+col]; cCol(b?CC_YEL:CC_DGRY);
            snprintf(tmp,sizeof(tmp),"%02X ",b); cWrite(tmp);
        }
        cCol(CC_DGRY);
        for(DWORD i=drawn;i<(DWORD)HEX_COLS;i++) cWrite("   ");
    }
}
static char snLines[SNIFFER_ROWS][UI_W+2]={};
static int  snHead=0;
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

// ─── Delta sniffer ────────────────────────────────────────────────
void SnifferDelta(const std::vector<BYTE>& cur,std::vector<BYTE>& prev,
                  DWORD sz,DWORD pktNum,bool show){
    DWORD m=(DWORD)min((size_t)sz,min(cur.size(),prev.size()));
    char line[UI_W+2]={}; int pos=0;
    for(DWORD i=0;i<m&&pos<UI_W-12;i++){
        if(cur[i]!=prev[i]){
            int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",i,prev[i],cur[i]);
            if(n>0) pos+=n;
        }
    }
    if(pos>0){
        if(show) uiSnifferAdd(line);
        logLine("PKT%-6lu  %s",pktNum,line);
    }
    prev=cur;
}

// ─── RAII handle ─────────────────────────────────────────────────
struct HG {
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE):h(h_){}
    ~HG(){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
    HG(const HG&)=delete; HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){
        if(h!=INVALID_HANDLE_VALUE) CloseHandle(h); h=nh;
    }
    operator HANDLE()const{ return h; }
    bool valid()const{ return h!=INVALID_HANDLE_VALUE; }
};

// ─────────────────────────────────────────────────────────────────
//  FindBestNaconInterface
// ─────────────────────────────────────────────────────────────────
bool FindBestNaconInterface(char* outPath,size_t pathMax,DWORD* outSize){
    GUID hidGuid; HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi=SetupDiGetClassDevs(&hidGuid,NULL,NULL,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
    if(hdi==INVALID_HANDLE_VALUE){ logErr("SetupDiGetClassDevs: %lu",GetLastError()); return false; }

    SP_DEVICE_INTERFACE_DATA did={}; did.cbSize=sizeof(did);
    bool foundGP=false,found=false;
    DWORD bestSize=0;

    logLine("--- HID interface scan ---");
    for(int i=0;SetupDiEnumDeviceInterfaces(hdi,NULL,&hidGuid,i,&did);i++){
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
        if(!HidD_GetAttributes(ht,&attr)){ CloseHandle(ht); continue; }

        WORD up=0,use=0; DWORD inLen=0;
        PHIDP_PREPARSED_DATA ppd=nullptr;
        if(HidD_GetPreparsedData(ht,&ppd)){
            HIDP_CAPS caps={};
            if(HidP_GetCaps(ppd,&caps)==HIDP_STATUS_SUCCESS){
                up=caps.UsagePage; use=caps.Usage; inLen=caps.InputReportByteLength;
            }
            HidD_FreePreparsedData(ppd);
        }
        logLine("  [%d] VID=%04X PID=%04X Page=%02X Use=%02X InLen=%u",
                i,attr.VendorID,attr.ProductID,up,use,inLen);

        if(attr.VendorID==NACON_VID&&attr.ProductID==NACON_PID){
            bool isGP=(up==0x01&&(use==0x04||use==0x05));
            if(isGP&&!foundGP){
                logLine("  ^-- GAMEPAD selected");
                strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);
                bestSize=inLen; foundGP=true; found=true;
            } else if(!foundGP&&inLen>bestSize){
                logLine("  ^-- fallback (InLen=%u Usage=0x%02X)",inLen,use);
                strncpy_s(outPath,pathMax,det->DevicePath,pathMax-1);
                bestSize=inLen; found=true;
            }
        }
        CloseHandle(ht);
        if(foundGP) break;
    }
    SetupDiDestroyDeviceInfoList(hdi);
    logLine("--- scan done: found=%d size=%lu ---",(int)found,bestSize);
    if(outSize) *outSize=bestSize;
    return found;
}

// ─────────────────────────────────────────────────────────────────
//  ReadCtx — devPath хранится здесь, передаётся напрямую в поток.
//  Никакого GetFinalPathNameByHandle.
// ─────────────────────────────────────────────────────────────────
struct ReadCtx {
    HANDLE        hDev;
    char          devPath[512]; // путь для overlapped хэндла
    DWORD         pktSize;
    HANDLE        hNewPkt;
    volatile bool stop;
};

static void PushPacket(const BYTE* data,DWORD sz,HANDLE ev){
    EnterCriticalSection(&gPkt.cs);
    DWORD s=min(sz,(DWORD)PKT_MAX);
    memcpy(gPkt.data,data,s);
    gPkt.size=s; gPkt.ready=true;
    LeaveCriticalSection(&gPkt.cs);
    SetEvent(ev);
}

static void LogFirstPkt(const char* method,const BYTE* d,DWORD sz){
    char raw[512]={}; int pos=0;
    for(DWORD j=0;j<sz&&j<48&&pos<490;j++){
        int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",d[j]);
        if(n>0) pos+=n;
    }
    logLine("FIRST_PKT [%s] size=%lu  RAW: %s",method,sz,raw);
}

// ─────────────────────────────────────────────────────────────────
//  OpenOverlapped — открывает overlapped хэндл по пути из ctx.
//  Сначала GENERIC_READ, затем READ|WRITE.
// ─────────────────────────────────────────────────────────────────
static HANDLE OpenOverlapped(const char* path){
    HANDLE h=CreateFileA(path,GENERIC_READ,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(h==INVALID_HANDLE_VALUE){
        h=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,
                       FILE_SHARE_READ|FILE_SHARE_WRITE,
                       NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    }
    return h;
}

// ─────────────────────────────────────────────────────────────────
//  ReadFile loop (overlapped) — основной цикл чтения.
//  Таймаут 500 мс между попытками чтобы реагировать на ctx->stop.
// ─────────────────────────────────────────────────────────────────
static bool RunReadFileLoop(ReadCtx* ctx,HANDLE hOv,DWORD bufSize){
    HANDLE hEv=CreateEvent(NULL,TRUE,FALSE,NULL);
    if(!hEv) return false;

    std::vector<BYTE> buf(bufSize,0);
    bool first=true;
    bool gotAny=false;

    while(!ctx->stop){
        OVERLAPPED ov={}; ov.hEvent=hEv;
        ResetEvent(hEv);
        DWORD br=0;
        BOOL ok=ReadFile(hOv,buf.data(),bufSize,&br,&ov);
        DWORD err=GetLastError();

        if(!ok){
            if(err==ERROR_IO_PENDING){
                DWORD wt=WaitForSingleObject(hEv,500);
                if(wt==WAIT_TIMEOUT){
                    if(ctx->stop){ CancelIo(hOv); GetOverlappedResult(hOv,&ov,&br,TRUE); break; }
                    continue;
                }
                if(wt!=WAIT_OBJECT_0) break;
                if(!GetOverlappedResult(hOv,&ov,&br,FALSE)){
                    err=GetLastError();
                    if(err==ERROR_INVALID_HANDLE||err==ERROR_DEVICE_NOT_CONNECTED||
                       err==ERROR_OPERATION_ABORTED) break;
                    logErr("GOR err=%lu",err); Sleep(50); continue;
                }
            } else {
                if(err==ERROR_INVALID_HANDLE||err==ERROR_DEVICE_NOT_CONNECTED||
                   err==ERROR_OPERATION_ABORTED) break;
                logErr("ReadFile err=%lu",err); Sleep(50); continue;
            }
        }
        if(br==0) continue;
        gotAny=true;
        if(first){ LogFirstPkt("ReadFile",buf.data(),br); first=false; }
        PushPacket(buf.data(),br,ctx->hNewPkt);
    }

    CloseHandle(hEv);
    return gotAny;
}

// ─────────────────────────────────────────────────────────────────
//  ReadThread
//
//  Методы по убыванию приоритета:
//
//  [A] HidD_GetFeature  — для MFi/кастомных HID устройств которые
//      используют Feature-reports для передачи состояния.
//      Многие iOS-ориентированные контроллеры идут именно этим путём.
//      Перебираем ID: 0x00..0x03, 0x10, 0x20, 0x40.
//
//  [B] HidD_GetInputReport — стандартный poll.
//      На Usage=0x00 обычно err=31, но пробуем.
//
//  [C] ReadFile overlapped с перебором размеров буфера.
//      FIX: используем ctx->devPath напрямую (не GetFinalPathNameByHandle).
//      Пробуем: 64, 65, 32, 16, 128, 8 байт, по 2 секунды каждый.
//
//  [D] Блокирующий ReadFile на sync-хэндле (последний шанс).
//      Закрытие hDev из main() разблокирует вызов.
// ─────────────────────────────────────────────────────────────────
DWORD WINAPI ReadThread(LPVOID param){
    ReadCtx* ctx=reinterpret_cast<ReadCtx*>(param);
    logLine("ReadThread started pktSize=%lu  path=%s",ctx->pktSize,ctx->devPath);

    std::vector<BYTE> buf(max(ctx->pktSize,(DWORD)128),0);

    // ── [A] HidD_GetFeature ───────────────────────────────────────
    // MFi контроллеры часто передают данные через Feature reports,
    // а не через Input reports. Это главное отличие от стандартных HID.
    {
        static const BYTE fids[]={0x00,0x01,0x02,0x03,0x10,0x20,0x40,0x11,0x12};
        logLine("-- Probing HidD_GetFeature IDs --");
        BYTE workID=0xFF;

        for(BYTE id:fids){
            memset(buf.data(),0,ctx->pktSize); buf[0]=id;
            BOOL ok=HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize);
            DWORD err=GetLastError();
            logLine("  GetFeature ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
            if(ok){
                bool nz=false;
                for(DWORD j=0;j<ctx->pktSize;j++) if(buf[j]){nz=true;break;}
                if(nz){
                    char raw[256]={}; int pos=0;
                    for(DWORD j=0;j<ctx->pktSize&&j<16&&pos<240;j++){
                        int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",buf[j]);
                        if(n>0) pos+=n;
                    }
                    logLine("  ^-- GetFeature ID=0x%02X WORKS! RAW: %s",id,raw);
                    workID=id; break;
                }
                logLine("  ^-- all-zeros, skip");
            }
        }

        if(workID!=0xFF){
            logLine("METHOD: GetFeature polling ID=0x%02X",workID);
            bool first=true;
            while(!ctx->stop){
                memset(buf.data(),0,ctx->pktSize); buf[0]=workID;
                BOOL ok=HidD_GetFeature(ctx->hDev,buf.data(),ctx->pktSize);
                if(!ok){
                    DWORD e=GetLastError();
                    if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED) break;
                    logErr("GetFeature loop err=%lu",e); Sleep(50); continue;
                }
                if(first){ LogFirstPkt("GetFeature",buf.data(),ctx->pktSize); first=false; }
                PushPacket(buf.data(),ctx->pktSize,ctx->hNewPkt);
                Sleep(8); // ~125 Hz
            }
            logLine("ReadThread [GetFeature] done");
            return 0;
        }
    }

    // ── [B] HidD_GetInputReport ───────────────────────────────────
    {
        static const BYTE iids[]={0x00,0x01,0x02,0x03,0x10,0x20};
        logLine("-- Probing HidD_GetInputReport IDs --");
        BYTE workID=0xFF;

        for(BYTE id:iids){
            memset(buf.data(),0,ctx->pktSize); buf[0]=id;
            BOOL ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);
            DWORD err=GetLastError();
            logLine("  GetInputReport ID=0x%02X ok=%d err=%lu",id,(int)ok,ok?0:err);
            if(ok){
                bool nz=false;
                for(DWORD j=1;j<ctx->pktSize;j++) if(buf[j]){nz=true;break;}
                if(nz){ logLine("  ^-- WORKS!"); workID=id; break; }
                logLine("  ^-- all-zeros, skip");
            }
        }

        if(workID!=0xFF){
            logLine("METHOD: GetInputReport polling ID=0x%02X",workID);
            bool first=true;
            while(!ctx->stop){
                memset(buf.data(),0,ctx->pktSize); buf[0]=workID;
                BOOL ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);
                if(!ok){
                    DWORD e=GetLastError();
                    if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED) break;
                    logErr("GetInputReport loop err=%lu",e); Sleep(50); continue;
                }
                if(first){ LogFirstPkt("GetInputReport",buf.data(),ctx->pktSize); first=false; }
                PushPacket(buf.data(),ctx->pktSize,ctx->hNewPkt);
                Sleep(8);
            }
            logLine("ReadThread [GetInputReport] done");
            return 0;
        }
    }

    // ── [C] ReadFile overlapped — перебор размеров ────────────────
    //
    //  FIX: ctx->devPath передаётся напрямую из main().
    //  Никакого GetFinalPathNameByHandle — он не работает на HID-хэндлах.
    //
    //  Для каждого размера открываем отдельный overlapped хэндл,
    //  пробуем 2 секунды. Если данные пришли — запускаем основной цикл.
    {
        static const DWORD sizes[]={64,65,32,16,128,8};
        logLine("-- Probing ReadFile with overlapped handle (path from ctx) --");

        for(DWORD probeSize:sizes){
            if(ctx->stop) break;
            logLine("  Trying ReadFile size=%lu ...",probeSize);

            HANDLE hProbe=OpenOverlapped(ctx->devPath);
            if(hProbe==INVALID_HANDLE_VALUE){
                logErr("  Cannot open overlapped handle: %lu",GetLastError());
                break; // путь нерабочий — дальше пробовать смысла нет
            }

            HANDLE hEv=CreateEvent(NULL,TRUE,FALSE,NULL);
            std::vector<BYTE> pbuf(probeSize,0);
            OVERLAPPED pov={}; pov.hEvent=hEv;
            DWORD br=0;
            BOOL ok=ReadFile(hProbe,pbuf.data(),probeSize,&br,&pov);
            DWORD err=GetLastError();
            bool gotData=false;

            if(!ok&&err==ERROR_IO_PENDING){
                DWORD wt=WaitForSingleObject(hEv,2000);
                if(wt==WAIT_OBJECT_0&&GetOverlappedResult(hProbe,&pov,&br,FALSE)&&br>0)
                    gotData=true;
                else
                    CancelIo(hProbe); // таймаут — отменяем
            } else if(ok&&br>0){
                gotData=true;
            }

            CloseHandle(hEv);
            CloseHandle(hProbe);

            if(gotData){
                logLine("  ReadFile works! size=%lu  bytes: %02X %02X %02X %02X",
                        probeSize,
                        br>0?pbuf[0]:0,br>1?pbuf[1]:0,
                        br>2?pbuf[2]:0,br>3?pbuf[3]:0);

                // Открываем финальный overlapped хэндл для основного цикла
                HANDLE hFinal=OpenOverlapped(ctx->devPath);
                if(hFinal==INVALID_HANDLE_VALUE){
                    logErr("Cannot open final overlapped handle: %lu",GetLastError());
                    break;
                }
                logLine("METHOD: ReadFile OVERLAPPED size=%lu",probeSize);
                RunReadFileLoop(ctx,hFinal,probeSize);
                CloseHandle(hFinal);
                logLine("ReadThread [ReadFile OVERLAPPED] done");
                return 0;
            }
            logLine("  size=%lu: no data in 2s",probeSize);
        }
    }

    // ── [D] Блокирующий ReadFile на sync-хэндле ──────────────────
    //
    //  Последний шанс. ReadFile блокируется до:
    //    • прихода данных от устройства
    //    • закрытия hDev из main() → err=ERROR_INVALID_HANDLE → выход
    //
    //  Для MFi: данные не придут без Apple-аутентификации,
    //  но этот метод покрывает edge-case когда все overlapped пробы
    //  молча проваливались из-за особенностей конкретного HID minidriver.
    {
        logLine("METHOD: Blocking ReadFile on sync handle (last resort)");
        std::vector<BYTE> bbuf(ctx->pktSize,0);
        bool first=true;
        while(!ctx->stop){
            DWORD br=0;
            BOOL ok=ReadFile(ctx->hDev,bbuf.data(),ctx->pktSize,&br,NULL);
            if(!ok){
                DWORD e=GetLastError();
                if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED||
                   e==ERROR_OPERATION_ABORTED||e==ERROR_BROKEN_PIPE) break;
                logErr("Blocking ReadFile err=%lu",e); Sleep(50); continue;
            }
            if(br==0) continue;
            if(first){ LogFirstPkt("BlockingReadFile",bbuf.data(),br); first=false; }
            PushPacket(bbuf.data(),br,ctx->hNewPkt);
        }
    }

    logLine("ReadThread done");
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox
//  Раскомментируй после получения данных в sniffer.log
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

    // ── D-Pad hat-switch (нейтраль = 0x0F или 0x08) ─────────────
    // switch(buf[?]&0x0F){
    //   case 0: r.wButtons|=XUSB_GAMEPAD_DPAD_UP;                             break;
    //   case 1: r.wButtons|=XUSB_GAMEPAD_DPAD_UP  |XUSB_GAMEPAD_DPAD_RIGHT;  break;
    //   case 2: r.wButtons|=XUSB_GAMEPAD_DPAD_RIGHT;                          break;
    //   case 3: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_RIGHT;  break;
    //   case 4: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN;                           break;
    //   case 5: r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_LEFT;   break;
    //   case 6: r.wButtons|=XUSB_GAMEPAD_DPAD_LEFT;                           break;
    //   case 7: r.wButtons|=XUSB_GAMEPAD_DPAD_UP  |XUSB_GAMEPAD_DPAD_LEFT;   break;
    // }

    // ── Стики ───────────────────────────────────────────────────
    // r.sThumbLX=toAxis(buf[?],false); r.sThumbLY=toAxis(buf[?],true);
    // r.sThumbRX=toAxis(buf[?],false); r.sThumbRY=toAxis(buf[?],true);

    // ── Триггеры ────────────────────────────────────────────────
    // r.bLeftTrigger=buf[?]; r.bRightTrigger=buf[?];

    (void)toAxis;
    return r;
}

// ─── Key edge detection ───────────────────────────────────────────
static bool prevS=false,prevEsc=false;
inline bool keyDown(int vk){ return (GetAsyncKeyState(vk)&0x8000)!=0; }

static ReadCtx rtCtx;

int main(){
    logOpen();
    InitializeCriticalSection(&gPkt.cs);
    memset(&rtCtx,0,sizeof(rtCtx));

    uiInit(); uiFrame();
    uiStatus(false,false,false,0,0);
    uiSnifferState(false);

    // 1. ViGEm ────────────────────────────────────────────────────
    const auto client=vigem_alloc();
    if(!client){ uiMsg("FATAL: vigem_alloc",CC_RED); logErr("vigem_alloc"); Sleep(3000); logClose(); return -1; }
    if(!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found. Install the driver.",CC_RED);
        logErr("vigem_connect"); Sleep(3000); vigem_free(client); logClose(); return -1;
    }
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: vigem_target_add",CC_RED); logErr("vigem_target_add");
        Sleep(3000); vigem_target_free(pad); vigem_disconnect(client); vigem_free(client); logClose(); return -1;
    }
    uiStatus(true,false,true,0,0); logLine("ViGEm OK");

    // 2. Nacon ────────────────────────────────────────────────────
    DWORD devSize=0;
    HG hNacon;

    while(!hNacon.valid()){
        char devPath[512]={};
        if(FindBestNaconInterface(devPath,sizeof(devPath),&devSize)){
            // Сохраняем путь в контексте потока ДО открытия хэндла
            strncpy_s(rtCtx.devPath,sizeof(rtCtx.devPath),devPath,sizeof(devPath)-1);

            HANDLE h=CreateFileA(devPath,GENERIC_READ|GENERIC_WRITE,
                                  FILE_SHARE_READ|FILE_SHARE_WRITE,
                                  NULL,OPEN_EXISTING,0,NULL);
            if(h==INVALID_HANDLE_VALUE){
                logErr("CreateFile RW sync failed (%lu), trying READ-only",GetLastError());
                h=CreateFileA(devPath,GENERIC_READ,
                               FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL,OPEN_EXISTING,0,NULL);
            }
            if(h!=INVALID_HANDLE_VALUE){
                logLine("Sync handle opened OK");
                HidD_SetNumInputBuffers(h,64);
                hNacon.reset(h);
            }
        }
        if(!hNacon.valid()){
            uiMsg("Waiting for Nacon MG-X — plug in the gamepad...",CC_YEL);
            Sleep(1500);
        }
    }
    uiClearMsg();

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
    logLine("Nacon OK, packet size: %lu  path: %s",rSz,rtCtx.devPath);

    // 3. Read thread ───────────────────────────────────────────────
    HG hNewPkt(CreateEvent(NULL,FALSE,FALSE,NULL));
    if(!hNewPkt.valid()){
        uiMsg("FATAL: CreateEvent",CC_RED); logErr("CreateEvent"); Sleep(3000); logClose(); return -1;
    }

    rtCtx.hDev    =hNacon;
    rtCtx.pktSize =rSz;
    rtCtx.hNewPkt =hNewPkt;
    rtCtx.stop    =false;

    HANDLE hThread=CreateThread(NULL,0,ReadThread,&rtCtx,0,NULL);
    if(!hThread){
        uiMsg("FATAL: CreateThread",CC_RED); logErr("CreateThread: %lu",GetLastError());
        Sleep(3000); logClose(); return -1;
    }
    logLine("Read thread started");

    std::vector<BYTE> rbuf(rSz,0),pbuf(rSz,0);
    bool running=true,snifOn=false;
    DWORD pkts=0;

    // 4. Main loop ─────────────────────────────────────────────────
    while(running){
        bool curS=keyDown('S'); bool curEsc=keyDown(VK_ESCAPE);
        if(curEsc&&!prevEsc){ running=false; break; }
        if(curS&&!prevS){
            snifOn=!snifOn; uiSnifferState(snifOn);
            logLine("--- Sniffer %s at PKT %lu ---",snifOn?"ON":"OFF",pkts);
        }
        prevS=curS; prevEsc=curEsc;

        if(WaitForSingleObject(hNewPkt,10)!=WAIT_OBJECT_0) continue;

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
            logErr("vigem_target_x360_update PKT %lu",pkts);
        }
        uiGamepad(xr); uiStatus(true,true,true,rSz,pkts);
    }

    // 5. Cleanup ───────────────────────────────────────────────────
    rtCtx.stop=true;
    hNacon.reset(); // разблокирует блокирующий ReadFile/GetFeature в потоке

    if(WaitForSingleObject(hThread,3000)==WAIT_TIMEOUT){
        logErr("ReadThread timeout — terminating"); TerminateThread(hThread,0);
    }
    CloseHandle(hThread);

    vigem_target_remove(client,pad); vigem_target_free(pad);
    vigem_disconnect(client); vigem_free(client);

    DeleteCriticalSection(&gPkt.cs);
    logLine("\nSession ended. Total packets: %lu",pkts);
    logClose(); uiRestore();
    return 0;
}
