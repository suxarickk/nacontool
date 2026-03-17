#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

#define NACON_VID 0x3285
#define NACON_PID 0x0644

constexpr int  UI_W         = 80;
constexpr int  UI_H         = 24;
constexpr int  HEX_COLS     = 16;
constexpr int  HEX_ROWS     = 3;
constexpr int  SNIFFER_ROWS = 5;
constexpr int  BAR_LEN      = 5;
constexpr DWORD MAX_HID_REQ = 4096;

enum CC : WORD {
    CC_BLK=0, CC_DGRN=2, CC_DGRY=8, CC_GRN=10,
    CC_CYN=11, CC_RED=12, CC_YEL=14, CC_WHT=15, CC_GRY=7
};

static HANDLE hCon;
static HANDLE hConIn;
static FILE*  gLog = nullptr;

void logOpen() {
    fopen_s(&gLog, "sniffer.log", "w");
    if (!gLog) return;
    fprintf(gLog, "=== Nacon MG-X sniffer log ===\n");
    fprintf(gLog, "Format: PKT#  B<idx>:<old>-><new>\n\n");
    fflush(gLog);
}
void logLine(const char* fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    vfprintf(gLog, fmt, a);
    va_end(a);
    fputc('\n', gLog);
    fflush(gLog);
}
void logClose() { if (gLog) { fclose(gLog); gLog = nullptr; } }

// ─── Console output ───────────────────────────────────────────────
inline void cWrite(const char* s) {
    DWORD n = (DWORD)strlen(s);
    WriteConsoleA(hCon, s, n, &n, NULL);
}
void cXY(int x, int y) {
    COORD c = {(SHORT)x, (SHORT)y};
    SetConsoleCursorPosition(hCon, c);
}
void cCol(CC f, CC b = CC_BLK) {
    SetConsoleTextAttribute(hCon, (WORD)((b << 4) | f));
}
void cPr(int x, int y, const char* s, CC f = CC_GRY, CC b = CC_BLK) {
    cXY(x, y); cCol(f, b); cWrite(s);
}

// ─── Keyboard: ReadConsoleInput вместо _kbhit/_getch ─────────────
// _kbhit не работает когда консоль в нестандартном режиме
// ReadConsoleInput надёжнее и не зависит от CRT
bool kbCheck(char* outKey) {
    DWORD n = 0;
    if (!GetNumberOfConsoleInputEvents(hConIn, &n) || n == 0)
        return false;
    INPUT_RECORD rec;
    DWORD read = 0;
    while (PeekConsoleInputA(hConIn, &rec, 1, &read) && read > 0) {
        ReadConsoleInputA(hConIn, &rec, 1, &read);
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            *outKey = rec.Event.KeyEvent.uChar.AsciiChar;
            return true;
        }
    }
    return false;
}

void uiInit() {
    hCon   = GetStdHandle(STD_OUTPUT_HANDLE);
    hConIn = GetStdHandle(STD_INPUT_HANDLE);

    // Отключаем Quick Edit Mode — он блокирует вывод если пользователь
    // кликнул в консоль, что может стопорить ReadFile
    DWORD mode = 0;
    GetConsoleMode(hConIn, &mode);
    mode &= ~ENABLE_QUICK_EDIT_MODE;
    mode |= ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(hConIn, mode);

    CONSOLE_CURSOR_INFO ci = {1, FALSE};
    SetConsoleCursorInfo(hCon, &ci);
    COORD sz = {(SHORT)UI_W, (SHORT)UI_H};
    SetConsoleScreenBufferSize(hCon, sz);
    SMALL_RECT wr = {0, 0, (SHORT)(UI_W-1), (SHORT)(UI_H-1)};
    SetConsoleWindowInfo(hCon, TRUE, &wr);
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge");
    DWORD w; COORD o = {0, 0};
    FillConsoleOutputCharacterA(hCon, ' ', UI_W*UI_H, o, &w);
    FillConsoleOutputAttribute(hCon, CC_GRY, UI_W*UI_H, o, &w);
}

static const char* SEP =
    "--------------------------------------------------------------------------------";

void uiFrame() {
    cPr(0,  0, "  NACON MG-X",   CC_CYN);
    cPr(12, 0, " -> ",            CC_DGRY);
    cPr(16, 0, "XBOX 360 BRIDGE", CC_GRN);
    cPr(0,  1, SEP, CC_DGRY);
    cPr(1,  2, "ViGEm:", CC_DGRY);
    cPr(18, 2, "Nacon:", CC_DGRY);
    cPr(35, 2, "Xbox:",  CC_DGRY);
    cPr(50, 2, "Size:",  CC_DGRY);
    cPr(64, 2, "Pkts:",  CC_DGRY);
    cPr(0,  3, SEP, CC_DGRY);
    cPr(0,  4, "  LT",  CC_DGRY);
    cPr(11, 4, "LB",    CC_DGRY);
    cPr(34, 4, "BACK",  CC_DGRY);
    cPr(42, 4, "GUIDE", CC_DGRY);
    cPr(51, 4, "START", CC_DGRY);
    cPr(62, 4, "RB",    CC_DGRY);
    cPr(68, 4, "RT",    CC_DGRY);
    cPr(0,  5, SEP, CC_DGRY);
    cPr(0,  6, "  DPAD:",  CC_DGRY);
    cPr(24, 6, "L-STICK:", CC_DGRY);
    cPr(46, 6, "R-STICK:", CC_DGRY);
    cPr(0,  7, SEP, CC_DGRY);
    cPr(0,  8, "  FACE:",  CC_DGRY);
    cPr(42, 8, "THUMBS:",  CC_DGRY);
    cPr(0,  9, SEP, CC_DGRY);
    cPr(0, 10, "  RAW HID:", CC_DGRY);
    cPr(0, 14, SEP, CC_DGRY);
    cPr(0, 15, "  SNIFER",  CC_DGRY);
    cPr(0, 21, SEP, CC_DGRY);
    cPr(1,  22, "[S]",   CC_YEL);
    cPr(4,  22, " snifer on/off", CC_DGRY);
    cPr(20, 22, "[ESC]", CC_YEL);
    cPr(25, 22, " exit", CC_DGRY);
    cPr(38, 22, "log->", CC_DGRY);
    cPr(43, 22, "sniffer.log", CC_YEL);
}

void uiBtn(int x, int y, const char* l, bool on) {
    cXY(x, y);
    cCol(CC_DGRY); cWrite("[");
    cCol(on ? CC_GRN : CC_DGRY); cWrite(l);
    cCol(CC_DGRY); cWrite("]");
}
void uiBar(int x, int y, BYTE v) {
    int f = v * BAR_LEN / 255;
    char s[BAR_LEN + 3] = {};
    s[0] = '[';
    for (int i = 0; i < BAR_LEN; i++) s[i+1] = (i < f) ? '#' : '.';
    s[BAR_LEN+1] = ']'; s[BAR_LEN+2] = '\0';
    cXY(x, y); cCol(v > 10 ? CC_GRN : CC_DGRY); cWrite(s);
}
void uiAxis(int x, int y, SHORT v) {
    char buf[7];
    snprintf(buf, sizeof(buf), "%+05d", (int)v);
    cPr(x, y, buf, v != 0 ? CC_YEL : CC_DGRY);
}
void uiMsg(const char* s, CC fg = CC_YEL) {
    char pad[82] = {};
    snprintf(pad, 81, "  %-76s", s);
    cPr(0, 23, pad, fg);
}
void uiClearMsg() {
    char pad[82]; memset(pad, ' ', 80); pad[80] = '\0';
    cPr(0, 23, pad, CC_BLK);
}
void uiStatus(bool vig, bool nac, bool xbx, DWORD sz, DWORD pkts) {
    cPr(7,  2, vig ? "[ON] " : "[--] ", vig ? CC_GRN : CC_RED);
    cPr(24, 2, nac ? "[ON] " : "[--] ", nac ? CC_GRN : CC_RED);
    cPr(40, 2, xbx ? "[ON] " : "[--] ", xbx ? CC_GRN : CC_RED);
    char tmp[20];
    snprintf(tmp, sizeof(tmp), "%-4lu",  sz);   cPr(55, 2, tmp, CC_YEL);
    snprintf(tmp, sizeof(tmp), "%-9lu", pkts);  cPr(69, 2, tmp, CC_DGRY);
}
void uiGamepad(const XUSB_REPORT& r) {
    uiBar(4,  4, r.bLeftTrigger);
    uiBar(70, 4, r.bRightTrigger);
    uiBtn(13, 4, "LB", (r.wButtons & XUSB_GAMEPAD_LEFT_SHOULDER)  != 0);
    uiBtn(64, 4, "RB", (r.wButtons & XUSB_GAMEPAD_RIGHT_SHOULDER) != 0);
    uiBtn(38, 4, "<<", (r.wButtons & XUSB_GAMEPAD_BACK)  != 0);
    uiBtn(47, 4, "()", (r.wButtons & XUSB_GAMEPAD_GUIDE) != 0);
    uiBtn(56, 4, ">>", (r.wButtons & XUSB_GAMEPAD_START) != 0);
    uiBtn(7,  6, "^",  (r.wButtons & XUSB_GAMEPAD_DPAD_UP)    != 0);
    uiBtn(10, 6, "v",  (r.wButtons & XUSB_GAMEPAD_DPAD_DOWN)  != 0);
    uiBtn(13, 6, "<",  (r.wButtons & XUSB_GAMEPAD_DPAD_LEFT)  != 0);
    uiBtn(16, 6, ">",  (r.wButtons & XUSB_GAMEPAD_DPAD_RIGHT) != 0);
    uiAxis(32, 6, r.sThumbLX); uiAxis(38, 6, r.sThumbLY);
    uiAxis(54, 6, r.sThumbRX); uiAxis(60, 6, r.sThumbRY);
    uiBtn(7,  8, "Y",  (r.wButtons & XUSB_GAMEPAD_Y)           != 0);
    uiBtn(11, 8, "X",  (r.wButtons & XUSB_GAMEPAD_X)           != 0);
    uiBtn(15, 8, "B",  (r.wButtons & XUSB_GAMEPAD_B)           != 0);
    uiBtn(19, 8, "A",  (r.wButtons & XUSB_GAMEPAD_A)           != 0);
    uiBtn(49, 8, "L3", (r.wButtons & XUSB_GAMEPAD_LEFT_THUMB)  != 0);
    uiBtn(55, 8, "R3", (r.wButtons & XUSB_GAMEPAD_RIGHT_THUMB) != 0);
}
void uiRawBytes(const BYTE* buf, DWORD sz) {
    char tmp[4];
    for (int row = 0; row < HEX_ROWS; row++) {
        cXY(0, 11 + row);
        DWORD start = (DWORD)(row * HEX_COLS), drawn = 0;
        for (DWORD col = 0; col < (DWORD)HEX_COLS && start+col < sz; col++, drawn++) {
            BYTE b = buf[start+col];
            cCol(b ? CC_YEL : CC_DGRY);
            snprintf(tmp, sizeof(tmp), "%02X ", b);
            cWrite(tmp);
        }
        cCol(CC_DGRY);
        for (DWORD i = drawn; i < (DWORD)HEX_COLS; i++) cWrite("   ");
    }
}

static char snLines[SNIFFER_ROWS][UI_W + 2] = {};
static int  snHead = 0;

void uiSnifferAdd(const char* line) {
    strncpy_s(snLines[snHead], UI_W+1, line, UI_W);
    snHead = (snHead + 1) % SNIFFER_ROWS;
    char pad[UI_W + 2];
    for (int i = 0; i < SNIFFER_ROWS; i++) {
        int idx = (snHead + i) % SNIFFER_ROWS;
        snprintf(pad, sizeof(pad), "%-*s", UI_W, snLines[idx]);
        cPr(0, 16+i, pad, snLines[idx][0] ? CC_YEL : CC_DGRY);
    }
}
void uiSnifferState(bool on) {
    cPr(9, 15, on ? "[ON] " : "[OFF]", on ? CC_GRN : CC_RED);
}
void uiRestore() {
    CONSOLE_CURSOR_INFO ci = {10, TRUE};
    SetConsoleCursorInfo(hCon, &ci);
    SetConsoleTextAttribute(hCon, CC_GRY);
    cXY(0, 23); cWrite("\n");
}

// ─── Дельта-снифер: пишет в консоль + в файл всегда ──────────────
void SnifferDelta(const std::vector<BYTE>& cur,
                  std::vector<BYTE>& prev,
                  DWORD /*sz*/, DWORD pktNum, bool showOnScreen) {
    DWORD m = (DWORD)min(cur.size(), prev.size());
    char line[UI_W + 2] = {}; int pos = 0;
    for (DWORD i = 0; i < m && pos < UI_W - 12; i++) {
        if (cur[i] != prev[i]) {
            int n = snprintf(line+pos, UI_W-pos,
                "B%lu:%02X->%02X  ", i, prev[i], cur[i]);
            if (n > 0) pos += n;
        }
    }
    if (pos > 0) {
        if (showOnScreen) uiSnifferAdd(line);
        logLine("PKT%-6lu  %s", pktNum, line);
    }
    prev = cur;
}

struct HG {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit HG(HANDLE h_ = INVALID_HANDLE_VALUE) : h(h_) {}
    ~HG() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HG(const HG&) = delete;
    HG& operator=(const HG&) = delete;
    void reset(HANDLE nh = INVALID_HANDLE_VALUE) {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = nh;
    }
    operator HANDLE() const { return h; }
    bool valid() const { return h != INVALID_HANDLE_VALUE; }
};

// ─── OpenNacon: выбираем интерфейс с максимальным пакетом ─────────
HANDLE OpenNacon() {
    GUID hidGuid; HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi = SetupDiGetClassDevs(&hidGuid, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdi == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    SP_DEVICE_INTERFACE_DATA did = {}; did.cbSize = sizeof(did);
    char  bestPath[512] = {};
    DWORD bestSize = 0;

    for (int i = 0; SetupDiEnumDeviceInterfaces(hdi, NULL, &hidGuid, i, &did); i++) {
        DWORD req = 0;
        SetupDiGetDeviceInterfaceDetail(hdi, &did, NULL, 0, &req, NULL);
        if (req == 0 || req > MAX_HID_REQ) continue;

        std::vector<BYTE> buf(req);
        auto* det = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buf.data());
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (!SetupDiGetDeviceInterfaceDetail(hdi, &did, det, req, NULL, NULL)) continue;

        HANDLE ht = CreateFile(det->DevicePath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (ht == INVALID_HANDLE_VALUE) continue;

        HIDD_ATTRIBUTES attr = {sizeof(attr)};
        bool match = HidD_GetAttributes(ht, &attr)
            && attr.VendorID == NACON_VID && attr.ProductID == NACON_PID;

        if (match) {
            PHIDP_PREPARSED_DATA ppd;
            if (HidD_GetPreparsedData(ht, &ppd)) {
                HIDP_CAPS caps;
                if (HidP_GetCaps(ppd, &caps) == HIDP_STATUS_SUCCESS) {
                    logLine("  iface[%d] UsagePage=0x%02X Usage=0x%02X InputLen=%u",
                        i, caps.UsagePage, caps.Usage, caps.InputReportByteLength);
                    if (caps.InputReportByteLength > bestSize) {
                        bestSize = caps.InputReportByteLength;
                        strncpy_s(bestPath, sizeof(bestPath),
                            det->DevicePath, sizeof(bestPath)-1);
                    }
                }
                HidD_FreePreparsedData(ppd);
            }
        }
        CloseHandle(ht);
    }
    SetupDiDestroyDeviceInfoList(hdi);
    if (bestSize == 0) return INVALID_HANDLE_VALUE;

    logLine("Selected interface with InputLen=%u", bestSize);

    HANDLE hr = CreateFile(bestPath,
        GENERIC_READ
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

    if (hr != INVALID_HANDLE_VALUE) {
        // Увеличиваем буфер HID — это критично для получения пакетов
        HidD_SetNumInputBuffers(hr, 64);
    }
    return hr;
}

// ─────────────────────────────────────────────────────────────────
//  MapNaconToXbox — заполни после анализа sniffer.log
//
//  В sniffer.log ищи строки вида:
//    PKT000042  B5:00->10  <- нажал кнопку A
//    PKT000043  B5:10->00  <- отпустил кнопку A
//  => байт 5, маска 0x10 — кнопка A
//
//  Для стиков ищи байт который плавно меняется при движении стика.
// ─────────────────────────────────────────────────────────────────
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r = {};
    if (buf.size() < 12) return r;

    auto toAxis = [](BYTE b, bool inv) -> SHORT {
        int v = inv ? (128 - (int)b) : ((int)b - 128);
        v = v * 256;
        if (v >  32767) v =  32767;
        if (v < -32768) v = -32768;
        return (SHORT)v;
    };

    // ── Кнопки: раскомментируй и замени ? на данные из sniffer.log ──
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_A;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_B;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_X;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_Y;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_LEFT_SHOULDER;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_RIGHT_SHOULDER;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_START;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_BACK;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_LEFT_THUMB;
    // if (buf[?] & 0x??) r.wButtons |= XUSB_GAMEPAD_RIGHT_THUMB;

    // ── D-Pad hat-switch ──
    // switch (buf[?] & 0x0F) {
    //     case 0: r.wButtons |= XUSB_GAMEPAD_DPAD_UP;                              break;
    //     case 1: r.wButtons |= XUSB_GAMEPAD_DPAD_UP   | XUSB_GAMEPAD_DPAD_RIGHT; break;
    //     case 2: r.wButtons |= XUSB_GAMEPAD_DPAD_RIGHT;                           break;
    //     case 3: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN | XUSB_GAMEPAD_DPAD_RIGHT; break;
    //     case 4: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN;                            break;
    //     case 5: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN | XUSB_GAMEPAD_DPAD_LEFT;  break;
    //     case 6: r.wButtons |= XUSB_GAMEPAD_DPAD_LEFT;                            break;
    //     case 7: r.wButtons |= XUSB_GAMEPAD_DPAD_UP   | XUSB_GAMEPAD_DPAD_LEFT;  break;
    // }

    // ── Стики ──
    // r.sThumbLX = toAxis(buf[?], false);
    // r.sThumbLY = toAxis(buf[?], true);
    // r.sThumbRX = toAxis(buf[?], false);
    // r.sThumbRY = toAxis(buf[?], true);

    // ── Триггеры ──
    // r.bLeftTrigger  = buf[?];
    // r.bRightTrigger = buf[?];

    (void)toAxis;
    return r;
}

int main() {
    logOpen();
    uiInit();
    uiFrame();
    uiStatus(false, false, false, 0, 0);
    uiSnifferState(false);

    // 1. ViGEm
    const auto client = vigem_alloc();
    if (!client) {
        uiMsg("FATAL: vigem_alloc failed.", CC_RED);
        logLine("FATAL: vigem_alloc"); Sleep(3000); logClose(); return -1;
    }
    if (!VIGEM_SUCCESS(vigem_connect(client))) {
        uiMsg("FATAL: ViGEmBus not found. Install the driver.", CC_RED);
        logLine("FATAL: vigem_connect failed");
        Sleep(3000); vigem_free(client); logClose(); return -1;
    }
    const auto pad = vigem_target_x360_alloc();
    if (!VIGEM_SUCCESS(vigem_target_add(client, pad))) {
        uiMsg("FATAL: could not create virtual Xbox pad.", CC_RED);
        logLine("FATAL: vigem_target_add failed");
        Sleep(3000);
        vigem_target_free(pad); vigem_disconnect(client); vigem_free(client);
        logClose(); return -1;
    }
    uiStatus(true, false, true, 0, 0);
    logLine("ViGEm OK");

    // 2. Ждём Nacon
    HG hNacon;
    while (!hNacon.valid()) {
        hNacon.reset(OpenNacon());
        if (!hNacon.valid()) {
            uiMsg("Waiting for Nacon MG-X — plug in the gamepad...", CC_YEL);
            Sleep(1500);
        }
    }
    uiClearMsg();
    logLine("Nacon opened OK");

    // 3. Размер пакета
    PHIDP_PREPARSED_DATA ppd;
    if (!HidD_GetPreparsedData(hNacon, &ppd)) {
        uiMsg("FATAL: HidD_GetPreparsedData failed.", CC_RED);
        logLine("FATAL: HidD_GetPreparsedData");
        Sleep(3000); logClose(); return -1;
    }
    HIDP_CAPS caps; HidP_GetCaps(ppd, &caps);
    DWORD rSz = caps.InputReportByteLength;
    HidD_FreePreparsedData(ppd);
    if (rSz < 64) rSz = 64;
    uiStatus(true, true, true, rSz, 0);
    logLine("Packet size: %lu bytes\n", rSz);

    // 4. OVERLAPPED
    HG hEv(CreateEvent(NULL, TRUE, FALSE, NULL));
    if (!hEv.valid()) {
        uiMsg("FATAL: CreateEvent failed.", CC_RED);
        logLine("FATAL: CreateEvent"); Sleep(3000); logClose(); return -1;
    }
    OVERLAPPED ov = {}; ov.hEvent = hEv;

    std::vector<BYTE> rbuf(rSz), pbuf(rSz, 0);
    bool running  = true;
    bool pending  = false;
    bool snifOn   = false;
    DWORD pkts    = 0;
    bool firstPkt = true;

    // 5. Главный цикл
    while (running) {

        // Клавиатура через ReadConsoleInput — работает в любом режиме консоли
        char key = 0;
        if (kbCheck(&key)) {
            if (key == 27) { running = false; break; }
            if (key == 's' || key == 'S') {
                snifOn = !snifOn;
                uiSnifferState(snifOn);
                logLine("--- Sniffer %s at PKT %lu ---", snifOn ? "ON" : "OFF", pkts);
            }
        }

        if (!pending) {
            ResetEvent(ov.hEvent);
            DWORD imm = 0;
            BOOL ok = ReadFile(hNacon, rbuf.data(), rSz, &imm, &ov);
            if (ok) {
                // Данные уже готовы
                SetEvent(ov.hEvent);
                pending = true;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    pending = true;
                } else {
                    // Устройство отключилось
                    logLine("ReadFile error: %lu — reconnecting", err);
                    CancelIoEx(hNacon, NULL);
                    hNacon.reset();
                    uiStatus(true, false, true, rSz, pkts);
                    uiMsg("Nacon disconnected — reconnecting...", CC_YEL);
                    while (!hNacon.valid()) {
                        Sleep(2000);
                        hNacon.reset(OpenNacon());
                    }
                    uiClearMsg();
                    ov.hEvent = hEv;
                    uiStatus(true, true, true, rSz, pkts);
                    firstPkt = true;
                    continue;
                }
            }
        }

        // Ждём 10 мс — чтобы клавиатура проверялась на каждой итерации
        DWORD wt = WaitForSingleObject(ov.hEvent, 10);
        if (wt == WAIT_OBJECT_0) {
            DWORD br = 0;
            if (GetOverlappedResult(hNacon, &ov, &br, FALSE)) {
                pending = false;
                if (br > 0) {
                    ++pkts;
                    if (br < rSz) memset(rbuf.data() + br, 0, rSz - br);

                    // Первый пакет — пишем полный дамп
                    if (firstPkt) {
                        char raw[256] = {};
                        int pos = 0;
                        for (DWORD j = 0; j < br && j < 64; j++) {
                            int n = snprintf(raw+pos, sizeof(raw)-pos, "%02X ", rbuf[j]);
                            if (n > 0) pos += n;
                        }
                        logLine("FIRST_PKT RAW[%lu]: %s", br, raw);
                        firstPkt = false;
                    }

                    uiRawBytes(rbuf.data(), min(br, (DWORD)(HEX_ROWS * HEX_COLS)));

                    // Дельта пишется в файл ВСЕГДА, на экран только если snifOn
                    SnifferDelta(rbuf, pbuf, br, pkts, snifOn);

                    XUSB_REPORT xr = MapNaconToXbox(rbuf);
                    if (!VIGEM_SUCCESS(vigem_target_x360_update(client, pad, xr)))
                        uiMsg("vigem update error — ViGEm disconnected?", CC_RED);
                    uiGamepad(xr);
                    uiStatus(true, true, true, rSz, pkts);
                }
            } else {
                DWORD err = GetLastError();
                if (err != ERROR_IO_INCOMPLETE) {
                    logLine("GetOverlappedResult error: %lu", err);
                    pending = false;
                }
            }
        } else if (wt != WAIT_TIMEOUT) {
            logLine("WaitForSingleObject unexpected: %lu", wt);
            break;
        }
    }

    // 6. Очистка
    if (pending) CancelIoEx(hNacon, NULL);
    vigem_target_remove(client, pad);
    vigem_target_free(pad);
    vigem_disconnect(client);
    vigem_free(client);
    logLine("\nSession ended. Total packets: %lu", pkts);
    logClose();
    uiRestore();
    return 0;
}
