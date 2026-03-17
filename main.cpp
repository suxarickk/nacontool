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
constexpr int  UI_W         = 80;
constexpr int  UI_H         = 24;
constexpr int  HEX_COLS     = 16;
constexpr int  HEX_ROWS     = 3;
constexpr int  SNIFFER_ROWS = 5;
constexpr int  BAR_LEN      = 5;
constexpr DWORD MAX_HID_REQ = 4096;
constexpr DWORD PKT_MAX     = 256;

// Read method used (written to log so we can see which worked)
enum ReadMethod { RM_GETINPUT=0, RM_READFILE=1 };

enum CC : WORD {
    CC_BLK=0,CC_DGRN=2,CC_DGRY=8,CC_GRN=10,
    CC_CYN=11,CC_RED=12,CC_YEL=14,CC_WHT=15,CC_GRY=7
};

static HANDLE hCon   = INVALID_HANDLE_VALUE;
static HANDLE hConIn = INVALID_HANDLE_VALUE;
static FILE*  gLog   = nullptr;
static FILE*  gErr   = nullptr;

// ─── Logging ──────────────────────────────────────────────────────
void logOpen() {
    fopen_s(&gLog,"sniffer.log","w");
    fopen_s(&gErr,"error.log","w");
    if(gLog){fprintf(gLog,"=== sniffer.log ===\n\n");fflush(gLog);}
    if(gErr){fprintf(gErr,"=== error.log ===\n\n");fflush(gErr);}
}
void logLine(const char* fmt,...) {
    if(!gLog)return;
    va_list a;va_start(a,fmt);vfprintf(gLog,fmt,a);va_end(a);
    fputc('\n',gLog);fflush(gLog);
}
void logErr(const char* fmt,...) {
    va_list a;
    if(gErr){va_start(a,fmt);vfprintf(gErr,fmt,a);va_end(a);fputc('\n',gErr);fflush(gErr);}
    if(gLog){fprintf(gLog,"[ERR] ");va_start(a,fmt);vfprintf(gLog,fmt,a);va_end(a);fputc('\n',gLog);fflush(gLog);}
}
void logClose(){
    if(gLog){fclose(gLog);gLog=nullptr;}
    if(gErr){fclose(gErr);gErr=nullptr;}
}

// ─── Shared buffer (read thread → main thread) ────────────────────
struct SharedPacket {
    BYTE  data[PKT_MAX]={};
    DWORD size=0;
    bool  ready=false;
    CRITICAL_SECTION cs;
};
static SharedPacket gPkt;

// ─── Console output ───────────────────────────────────────────────
inline void cWrite(const char* s){
    DWORD n=(DWORD)strlen(s);WriteConsoleA(hCon,s,n,&n,NULL);
}
void cXY(int x,int y){COORD c={(SHORT)x,(SHORT)y};SetConsoleCursorPosition(hCon,c);}
void cCol(CC f,CC b=CC_BLK){SetConsoleTextAttribute(hCon,(WORD)((b<<4)|f));}
void cPr(int x,int y,const char* s,CC f=CC_GRY,CC b=CC_BLK){
    cXY(x,y);cCol(f,b);cWrite(s);
}

void uiInit(){
    hCon  =GetStdHandle(STD_OUTPUT_HANDLE);
    hConIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0;GetConsoleMode(hConIn,&mode);
    mode&=~ENABLE_QUICK_EDIT_MODE;mode|=ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(hConIn,mode);
    CONSOLE_CURSOR_INFO ci={1,FALSE};SetConsoleCursorInfo(hCon,&ci);
    COORD sz={(SHORT)UI_W,(SHORT)UI_H};SetConsoleScreenBufferSize(hCon,sz);
    SMALL_RECT wr={0,0,(SHORT)(UI_W-1),(SHORT)(UI_H-1)};
    SetConsoleWindowInfo(hCon,TRUE,&wr);
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
    cPr(0,0,"  NACON MG-X",CC_CYN);cPr(12,0," -> ",CC_DGRY);
    cPr(16,0,"XBOX 360 BRIDGE",CC_GRN);
    cPr(0,1,SEP,CC_DGRY);
    cPr(1,2,"ViGEm:",CC_DGRY);cPr(18,2,"Nacon:",CC_DGRY);
    cPr(35,2,"Xbox:",CC_DGRY);cPr(50,2,"Size:",CC_DGRY);cPr(64,2,"Pkts:",CC_DGRY);
    cPr(0,3,SEP,CC_DGRY);
    cPr(0,4,"  LT",CC_DGRY);cPr(11,4,"LB",CC_DGRY);cPr(34,4,"BACK",CC_DGRY);
    cPr(42,4,"GUIDE",CC_DGRY);cPr(51,4,"START",CC_DGRY);
    cPr(62,4,"RB",CC_DGRY);cPr(68,4,"RT",CC_DGRY);
    cPr(0,5,SEP,CC_DGRY);
    cPr(0,6,"  DPAD:",CC_DGRY);cPr(24,6,"L-STICK:",CC_DGRY);cPr(46,6,"R-STICK:",CC_DGRY);
    cPr(0,7,SEP,CC_DGRY);
    cPr(0,8,"  FACE:",CC_DGRY);cPr(42,8,"THUMBS:",CC_DGRY);
    cPr(0,9,SEP,CC_DGRY);
    cPr(0,10,"  RAW HID:",CC_DGRY);
    cPr(0,14,SEP,CC_DGRY);cPr(0,15,"  SNIFER",CC_DGRY);
    cPr(0,21,SEP,CC_DGRY);
    cPr(1,22,"[S]",CC_YEL);cPr(4,22," snifer on/off",CC_DGRY);
    cPr(20,22,"[ESC]",CC_YEL);cPr(25,22," exit",CC_DGRY);
    cPr(38,22,"log->",CC_DGRY);cPr(43,22,"sniffer.log",CC_YEL);
}

void uiBtn(int x,int y,const char* l,bool on){
    cXY(x,y);cCol(CC_DGRY);cWrite("[");
    cCol(on?CC_GRN:CC_DGRY);cWrite(l);cCol(CC_DGRY);cWrite("]");
}
void uiBar(int x,int y,BYTE v){
    int f=v*BAR_LEN/255;char s[BAR_LEN+3]={};s[0]='[';
    for(int i=0;i<BAR_LEN;i++)s[i+1]=(i<f)?'#':'.';
    s[BAR_LEN+1]=']';s[BAR_LEN+2]='\0';
    cXY(x,y);cCol(v>10?CC_GRN:CC_DGRY);cWrite(s);
}
void uiAxis(int x,int y,SHORT v){
    char b[7];snprintf(b,sizeof(b),"%+05d",(int)v);
    cPr(x,y,b,v!=0?CC_YEL:CC_DGRY);
}
void uiMsg(const char* s,CC fg=CC_YEL){
    char pad[82]={};snprintf(pad,81,"  %-76s",s);cPr(0,23,pad,fg);
}
void uiClearMsg(){
    char pad[82];memset(pad,' ',80);pad[80]='\0';cPr(0,23,pad,CC_BLK);
}
void uiStatus(bool vig,bool nac,bool xbx,DWORD sz,DWORD pkts){
    cPr(7,2,vig?"[ON] ":"[--] ",vig?CC_GRN:CC_RED);
    cPr(24,2,nac?"[ON] ":"[--] ",nac?CC_GRN:CC_RED);
    cPr(40,2,xbx?"[ON] ":"[--] ",xbx?CC_GRN:CC_RED);
    char tmp[20];
    snprintf(tmp,sizeof(tmp),"%-4lu",sz);cPr(55,2,tmp,CC_YEL);
    snprintf(tmp,sizeof(tmp),"%-9lu",pkts);cPr(69,2,tmp,CC_DGRY);
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
        cCol(CC_DGRY);
        for(DWORD i=drawn;i<(DWORD)HEX_COLS;i++)cWrite("   ");
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
void uiSnifferState(bool on){
    cPr(9,15,on?"[ON] ":"[OFF]",on?CC_GRN:CC_RED);
}

// ─── Delta sniffer ────────────────────────────────────────────────
void SnifferDelta(const std::vector<BYTE>& cur,std::vector<BYTE>& prev,
                  DWORD sz,DWORD pktNum,bool show){
    DWORD m=(DWORD)min((size_t)sz,min(cur.size(),prev.size()));
    char line[UI_W+2]={};int pos=0;
    for(DWORD i=0;i<m&&pos<UI_W-12;i++){
        if(cur[i]!=prev[i]){
            int n=snprintf(line+pos,UI_W-pos,"B%lu:%02X->%02X  ",
                i,prev[i],cur[i]);
            if(n>0)pos+=n;
        }
    }
    if(pos>0){
        if(show)uiSnifferAdd(line);
        logLine("PKT%-6lu  %s",pktNum,line);
    }
    prev=cur;
}

// ─── RAII handle ─────────────────────────────────────────────────
struct HG{
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_=INVALID_HANDLE_VALUE):h(h_){}
    ~HG(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
    HG(const HG&)=delete;HG& operator=(const HG&)=delete;
    void reset(HANDLE nh=INVALID_HANDLE_VALUE){
        if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=nh;
    }
    operator HANDLE()const{return h;}
    bool valid()const{return h!=INVALID_HANDLE_VALUE;}
};

// ─────────────────────────────────────────────────────────────────
//  OpenNacon: находит интерфейс с максимальным InputReportByteLength.
//  Открывает БЕЗ FILE_FLAG_OVERLAPPED для синхронного чтения.
//  Пробует GENERIC_READ, затем GENERIC_READ|GENERIC_WRITE.
// ─────────────────────────────────────────────────────────────────
HANDLE OpenNacon(DWORD* outSize=nullptr){
    GUID hidGuid;HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi=SetupDiGetClassDevs(&hidGuid,NULL,NULL,
        DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
    if(hdi==INVALID_HANDLE_VALUE){
        logErr("SetupDiGetClassDevs failed: %lu",GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    SP_DEVICE_INTERFACE_DATA did={};did.cbSize=sizeof(did);
    char  bestPath[512]={};
    DWORD bestSize=0;

    for(int i=0;SetupDiEnumDeviceInterfaces(hdi,NULL,&hidGuid,i,&did);i++){
        DWORD req=0;
        SetupDiGetDeviceInterfaceDetail(hdi,&did,NULL,0,&req,NULL);
        if(req==0||req>MAX_HID_REQ)continue;

        std::vector<BYTE> buf(req);
        auto* det=reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if(!SetupDiGetDeviceInterfaceDetail(hdi,&did,det,req,NULL,NULL))continue;

        HANDLE ht=CreateFile(det->DevicePath,0,
            FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
        if(ht==INVALID_HANDLE_VALUE)continue;

        HIDD_ATTRIBUTES attr={sizeof(attr)};
        bool match=HidD_GetAttributes(ht,&attr)
            &&attr.VendorID==NACON_VID&&attr.ProductID==NACON_PID;

        if(match){
            PHIDP_PREPARSED_DATA ppd;
            if(HidD_GetPreparsedData(ht,&ppd)){
                HIDP_CAPS caps;
                if(HidP_GetCaps(ppd,&caps)==HIDP_STATUS_SUCCESS){
                    logLine("  iface[%d] UsagePage=0x%02X Usage=0x%02X InputLen=%u",
                        i,caps.UsagePage,caps.Usage,caps.InputReportByteLength);
                    if(caps.InputReportByteLength>bestSize){
                        bestSize=caps.InputReportByteLength;
                        strncpy_s(bestPath,sizeof(bestPath),
                            det->DevicePath,sizeof(bestPath)-1);
                    }
                }
                HidD_FreePreparsedData(ppd);
            }
        }
        CloseHandle(ht);
    }
    SetupDiDestroyDeviceInfoList(hdi);

    if(bestSize==0){
        logErr("No matching interface (VID=%04X PID=%04X)",NACON_VID,NACON_PID);
        return INVALID_HANDLE_VALUE;
    }
    if(outSize)*outSize=bestSize;
    logLine("Best interface InputLen=%u",bestSize);

    // Sync open (no OVERLAPPED) — нужен для HidD_GetInputReport
    HANDLE hr=CreateFile(bestPath,
        GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,OPEN_EXISTING,0,NULL);
    if(hr==INVALID_HANDLE_VALUE){
        logErr("CreateFile GENERIC_READ failed: %lu, trying +WRITE",GetLastError());
        hr=CreateFile(bestPath,
            GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,
            NULL,OPEN_EXISTING,0,NULL);
        if(hr==INVALID_HANDLE_VALUE){
            logErr("CreateFile failed completely: %lu",GetLastError());
            return INVALID_HANDLE_VALUE;
        }
        logLine("Opened READ|WRITE sync");
    } else {
        logLine("Opened READ-only sync");
    }
    HidD_SetNumInputBuffers(hr,64);
    return hr;
}

// ─────────────────────────────────────────────────────────────────
//  Read thread context
// ─────────────────────────────────────────────────────────────────
struct ReadCtx{
    HANDLE hDev;
    DWORD  pktSize;
    HANDLE hNewPkt;   // auto-reset event: new packet ready
    volatile bool stop;
    ReadMethod method;
};

// ─────────────────────────────────────────────────────────────────
//  ReadThread — пробует ОБА метода чтения:
//
//  Метод 0: HidD_GetInputReport — явный poll-запрос.
//    Работает с Usage=0x00 (нестандартный/feature интерфейс).
//    Вызов блокирующий, возвращает когда устройство ответило.
//
//  Метод 1: ReadFile синхронный — стандартный interrupt input.
//    Работает для Usage=0x04/0x05 (стандартный геймпад).
//
//  Если метод 0 сразу вернул FALSE → переключаемся на метод 1.
//  Если оба не работают → пишем в лог и выходим.
// ─────────────────────────────────────────────────────────────────
DWORD WINAPI ReadThread(LPVOID param){
    ReadCtx* ctx=reinterpret_cast<ReadCtx*>(param);
    std::vector<BYTE> buf(ctx->pktSize,0);

    // Проверяем метод 0 (HidD_GetInputReport)
    buf[0]=0;  // report ID = 0
    BOOL test=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);
    DWORD testErr=GetLastError();
    logLine("HidD_GetInputReport probe: ok=%d err=%lu",test,test?0:testErr);

    // Если HidD_GetInputReport не работает, пробуем ReadFile
    bool useGetInput=(test==TRUE);
    if(!useGetInput){
        logLine("HidD_GetInputReport failed -> trying ReadFile");
        // Тест ReadFile
        DWORD br=0;
        // Для ReadFile нужен OVERLAPPED-хэндл. Текущий открыт синхронно.
        // Просто попробуем ReadFile с таймаутом через отдельный OVERLAPPED.
        HANDLE hEv=CreateEvent(NULL,TRUE,FALSE,NULL);
        OVERLAPPED ov={};ov.hEvent=hEv;
        // Перечитаем устройство с OVERLAPPED-флагом нельзя на sync handle.
        // Поэтому при ReadFile-fallback просто читаем синхронно.
        BOOL rf=ReadFile(ctx->hDev,buf.data(),ctx->pktSize,&br,NULL);
        DWORD rfErr=GetLastError();
        CloseHandle(hEv);
        logLine("ReadFile probe: ok=%d br=%lu err=%lu",rf,br,rf?0:rfErr);
        if(rf&&br>0){
            logLine("ReadFile works, using ReadFile method");
            ctx->method=RM_READFILE;
        } else {
            logErr("Both read methods failed. Device may not support input reports.");
            return 1;
        }
    } else {
        ctx->method=RM_GETINPUT;
        logLine("Using HidD_GetInputReport method");
        // Первый пакет уже в buf — отправляем его
        EnterCriticalSection(&gPkt.cs);
        DWORD sz=min((DWORD)buf.size(),(DWORD)PKT_MAX);
        memcpy(gPkt.data,buf.data(),sz);
        gPkt.size=sz;gPkt.ready=true;
        LeaveCriticalSection(&gPkt.cs);
        SetEvent(ctx->hNewPkt);
    }

    logLine("ReadThread main loop started (method=%d)",ctx->method);

    while(!ctx->stop){
        BOOL ok=FALSE;
        DWORD br=0;

        if(ctx->method==RM_GETINPUT){
            // HidD_GetInputReport: report ID в первом байте
            buf[0]=0;
            ok=HidD_GetInputReport(ctx->hDev,buf.data(),ctx->pktSize);
            if(!ok){
                DWORD e=GetLastError();
                if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED)break;
                logErr("HidD_GetInputReport error: %lu",e);
                Sleep(50);
                continue;
            }
            br=ctx->pktSize;
        } else {
            // ReadFile синхронный
            ok=ReadFile(ctx->hDev,buf.data(),ctx->pktSize,&br,NULL);
            if(!ok){
                DWORD e=GetLastError();
                if(e==ERROR_INVALID_HANDLE||e==ERROR_DEVICE_NOT_CONNECTED||
                   e==ERROR_OPERATION_ABORTED)break;
                logErr("ReadFile error: %lu",e);
                Sleep(50);
                continue;
            }
        }

        if(br==0)continue;

        EnterCriticalSection(&gPkt.cs);
        DWORD sz=min(br,(DWORD)PKT_MAX);
        memcpy(gPkt.data,buf.data(),sz);
        gPkt.size=sz;gPkt.ready=true;
        LeaveCriticalSection(&gPkt.cs);
        SetEvent(ctx->hNewPkt);

        // Для GetInputReport добавляем небольшую задержку чтобы не спамить
        // устройство запросами (~125 Hz — стандартная частота геймпадов)
        if(ctx->method==RM_GETINPUT)Sleep(8);
    }

    logLine("ReadThread finished (method=%d)",ctx->method);
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox — заполни после анализа sniffer.log
//
//  Как читать:  PKT000042  B5:00->10
//  Нажал кнопку → байт 5 изменился с 0x00 на 0x10
//  Маска = 0x10. Раскомментируй строку и замени ? на реальные числа.
//
//  Для стиков: байт плавно меняется 0x00..0xFF при движении.
//  Центр ≈ 0x80. Ось Y обычно инвертирована у MFi → inv=true.
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf){
    XUSB_REPORT r={};
    if(buf.size()<12)return r;

    auto toAxis=[](BYTE b,bool inv)->SHORT{
        int v=inv?(128-(int)b):((int)b-128);
        v*=256;
        if(v>32767)v=32767;if(v<-32768)v=-32768;
        return (SHORT)v;
    };

    // ── Кнопки ─────────────────────────────────────────────────
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_A;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_B;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_X;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_Y;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_LEFT_SHOULDER;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_RIGHT_SHOULDER;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_START;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_BACK;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_LEFT_THUMB;
    // if(buf[?]&0x??)r.wButtons|=XUSB_GAMEPAD_RIGHT_THUMB;

    // ── D-Pad hat-switch (0-7, нейтраль=0x0F или 0x08) ─────────
    // switch(buf[?]&0x0F){
    //   case 0:r.wButtons|=XUSB_GAMEPAD_DPAD_UP;break;
    //   case 1:r.wButtons|=XUSB_GAMEPAD_DPAD_UP|XUSB_GAMEPAD_DPAD_RIGHT;break;
    //   case 2:r.wButtons|=XUSB_GAMEPAD_DPAD_RIGHT;break;
    //   case 3:r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_RIGHT;break;
    //   case 4:r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN;break;
    //   case 5:r.wButtons|=XUSB_GAMEPAD_DPAD_DOWN|XUSB_GAMEPAD_DPAD_LEFT;break;
    //   case 6:r.wButtons|=XUSB_GAMEPAD_DPAD_LEFT;break;
    //   case 7:r.wButtons|=XUSB_GAMEPAD_DPAD_UP|XUSB_GAMEPAD_DPAD_LEFT;break;
    // }

    // ── Стики ───────────────────────────────────────────────────
    // r.sThumbLX=toAxis(buf[?],false);
    // r.sThumbLY=toAxis(buf[?],true);
    // r.sThumbRX=toAxis(buf[?],false);
    // r.sThumbRY=toAxis(buf[?],true);

    // ── Триггеры ────────────────────────────────────────────────
    // r.bLeftTrigger=buf[?];
    // r.bRightTrigger=buf[?];

    (void)toAxis;
    return r;
}

// ─── Key edge detection ───────────────────────────────────────────
static bool prevS=false,prevEsc=false;
inline bool keyDown(int vk){return(GetAsyncKeyState(vk)&0x8000)!=0;}

int main(){
    logOpen();
    InitializeCriticalSection(&gPkt.cs);

    uiInit();
    uiFrame();
    uiStatus(false,false,false,0,0);
    uiSnifferState(false);

    // 1. ViGEm
    const auto client=vigem_alloc();
    if(!client){
        uiMsg("FATAL: vigem_alloc failed.",CC_RED);
        logErr("vigem_alloc");Sleep(3000);logClose();return -1;
    }
    if(!VIGEM_SUCCESS(vigem_connect(client))){
        uiMsg("FATAL: ViGEmBus not found. Install the driver.",CC_RED);
        logErr("vigem_connect");
        Sleep(3000);vigem_free(client);logClose();return -1;
    }
    const auto pad=vigem_target_x360_alloc();
    if(!VIGEM_SUCCESS(vigem_target_add(client,pad))){
        uiMsg("FATAL: could not create virtual Xbox pad.",CC_RED);
        logErr("vigem_target_add");
        Sleep(3000);
        vigem_target_free(pad);vigem_disconnect(client);
        vigem_free(client);logClose();return -1;
    }
    uiStatus(true,false,true,0,0);
    logLine("ViGEm OK");

    // 2. Nacon
    DWORD devSize=0;
    HG hNacon;
    while(!hNacon.valid()){
        hNacon.reset(OpenNacon(&devSize));
        if(!hNacon.valid()){
            uiMsg("Waiting for Nacon MG-X — plug in the gamepad...",CC_YEL);
            Sleep(1500);
        }
    }
    uiClearMsg();

    // Финальный размер пакета
    DWORD rSz=devSize;
    {
        PHIDP_PREPARSED_DATA ppd;
        if(HidD_GetPreparsedData(hNacon,&ppd)){
            HIDP_CAPS caps2;HidP_GetCaps(ppd,&caps2);
            if(caps2.InputReportByteLength>rSz)rSz=caps2.InputReportByteLength;
            HidD_FreePreparsedData(ppd);
        }
    }
    if(rSz<8)rSz=8;
    if(rSz>PKT_MAX)rSz=PKT_MAX;

    uiStatus(true,true,true,rSz,0);
    logLine("Nacon OK, packet size: %lu",rSz);

    // 3. Read thread
    HG hNewPkt(CreateEvent(NULL,FALSE,FALSE,NULL)); // auto-reset
    if(!hNewPkt.valid()){
        uiMsg("FATAL: CreateEvent failed.",CC_RED);
        logErr("CreateEvent");Sleep(3000);logClose();return -1;
    }

    ReadCtx rtCtx;
    rtCtx.hDev    =hNacon;
    rtCtx.pktSize =rSz;
    rtCtx.hNewPkt =hNewPkt;
    rtCtx.stop    =false;
    rtCtx.method  =RM_GETINPUT;

    HANDLE hThread=CreateThread(NULL,0,ReadThread,&rtCtx,0,NULL);
    if(!hThread){
        uiMsg("FATAL: CreateThread failed.",CC_RED);
        logErr("CreateThread: %lu",GetLastError());
        Sleep(3000);logClose();return -1;
    }
    logLine("Read thread started");

    std::vector<BYTE> rbuf(rSz,0),pbuf(rSz,0);
    bool running=true,snifOn=false;
    DWORD pkts=0;
    bool firstPkt=true;

    // 4. Main loop
    while(running){

        // Клавиши — edge detection
        bool curS  =keyDown('S');
        bool curEsc=keyDown(VK_ESCAPE);
        if(curEsc&&!prevEsc){running=false;break;}
        if(curS  &&!prevS  ){
            snifOn=!snifOn;
            uiSnifferState(snifOn);
            logLine("--- Sniffer %s at PKT %lu ---",snifOn?"ON":"OFF",pkts);
        }
        prevS=curS;prevEsc=curEsc;

        // Ждём пакет 10 мс
        DWORD wt=WaitForSingleObject(hNewPkt,10);
        if(wt!=WAIT_OBJECT_0)continue;  // WAIT_TIMEOUT — нормально

        // Забираем пакет
        DWORD sz=0;
        EnterCriticalSection(&gPkt.cs);
        if(gPkt.ready){
            sz=min(gPkt.size,(DWORD)rSz);
            memcpy(rbuf.data(),gPkt.data,sz);
            gPkt.ready=false;
        }
        LeaveCriticalSection(&gPkt.cs);
        if(sz==0)continue;

        ++pkts;

        // Первый пакет — полный дамп в лог
        if(firstPkt){
            char raw[512]={};int pos=0;
            for(DWORD j=0;j<sz&&j<64&&pos<500;j++){
                int n=snprintf(raw+pos,sizeof(raw)-pos,"%02X ",rbuf[j]);
                if(n>0)pos+=n;
            }
            logLine("FIRST_PKT size=%lu RAW: %s",sz,raw);
            firstPkt=false;
        }

        uiRawBytes(rbuf.data(),min(sz,(DWORD)(HEX_ROWS*HEX_COLS)));
        SnifferDelta(rbuf,pbuf,sz,pkts,snifOn);

        XUSB_REPORT xr=MapNaconToXbox(rbuf);
        if(!VIGEM_SUCCESS(vigem_target_x360_update(client,pad,xr))){
            uiMsg("vigem update error",CC_RED);
            logErr("vigem_target_x360_update at PKT %lu",pkts);
        }
        uiGamepad(xr);
        uiStatus(true,true,true,rSz,pkts);
    }

    // 5. Cleanup
    rtCtx.stop=true;
    // Прерываем поток: закрываем устройство чтобы разблокировать вызов чтения
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
    logLine("\nSession ended. Total packets: %lu",pkts);
    logClose();
    uiRestore();
    return 0;
}
