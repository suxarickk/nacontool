#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <vector>
#include <cstdio>
#include <cstring>
#include <conio.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

// ─────────────────────────────────────────────────────────────────
//  НАСТРОЙКА: проверь свой PID в Диспетчере устройств
//  Диспетчер → Устройства HID → ПКМ → Свойства → Сведения →
//  "ИД оборудования" → HID\VID_3285&PID_XXXX
// ─────────────────────────────────────────────────────────────────
#define NACON_VID 0x045E
#define NACON_PID 0x028E   // <-- меняй если твой PID отличается

// ─── Константы разметки консоли ───────────────────────────────────
constexpr int  UI_W          = 80;
constexpr int  UI_H          = 24;
constexpr int  HEX_COLS      = 16;
constexpr int  HEX_ROWS      = 3;
constexpr int  SNIFFER_ROWS  = 5;
constexpr int  BAR_LEN       = 5;
constexpr DWORD MAX_HID_REQ  = 4096;

// ─── Цвета консоли (4-битная палитра Windows) ─────────────────────
enum CC : WORD {
    CC_BLK=0, CC_DGRN=2, CC_DGRY=8, CC_GRN=10,
    CC_CYN=11, CC_RED=12, CC_YEL=14, CC_WHT=15, CC_GRY=7
};

static HANDLE hCon;

// ─── Весь вывод через WriteConsoleA — без CRT-буферизации ─────────
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

// ─── Инициализация консоли ────────────────────────────────────────
void uiInit() {
    hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci = {1, FALSE};
    SetConsoleCursorInfo(hCon, &ci);
    COORD sz = {(SHORT)UI_W, (SHORT)UI_H};
    SetConsoleScreenBufferSize(hCon, sz);
    SMALL_RECT wr = {0, 0, (SHORT)(UI_W-1), (SHORT)(UI_H-1)};
    SetConsoleWindowInfo(hCon, TRUE, &wr);
    SetConsoleTitleA("Nacon MG-X -> Xbox 360 Bridge");
    DWORD w; COORD o = {0,0};
    FillConsoleOutputCharacterA(hCon, ' ', UI_W*UI_H, o, &w);
    FillConsoleOutputAttribute(hCon, CC_GRY, UI_W*UI_H, o, &w);
}

// ─── Статичная рамка (рисуется один раз) ──────────────────────────
static const char* SEP = "--------------------------------------------------------------------------------";

void uiFrame() {
    cPr(0,  0, "  NACON MG-X",    CC_CYN);
    cPr(12, 0, " -> ",             CC_DGRY);
    cPr(16, 0, "XBOX 360 BRIDGE",  CC_GRN);
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
    cPr(0,  6, "  DPAD:",   CC_DGRY);
    cPr(24, 6, "L-STICK:",  CC_DGRY);
    cPr(46, 6, "R-STICK:",  CC_DGRY);
    cPr(0,  7, SEP, CC_DGRY);
    cPr(0,  8, "  FACE:",   CC_DGRY);
    cPr(42, 8, "THUMBS:",   CC_DGRY);
    cPr(0,  9, SEP, CC_DGRY);
    cPr(0, 10, "  RAW HID:", CC_DGRY);
    cPr(0, 14, SEP, CC_DGRY);
    cPr(0, 15, "  SNIFER",  CC_DGRY);
    cPr(0, 21, SEP, CC_DGRY);
    cPr(1,  22, "[S]",   CC_YEL);
    cPr(4,  22, " snifer on/off", CC_DGRY);
    cPr(20, 22, "[ESC]", CC_YEL);
    cPr(25, 22, " exit", CC_DGRY);
}

// ─── UI-компоненты ────────────────────────────────────────────────
void uiBtn(int x, int y, const char* lbl, bool on) {
    cXY(x, y);
    cCol(CC_DGRY); cWrite("[");
    cCol(on ? CC_GRN : CC_DGRY); cWrite(lbl);
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

// ─── Дельта-снифер ────────────────────────────────────────────────
void SnifferDelta(const std::vector<BYTE>& cur,
                  std::vector<BYTE>& prev, DWORD /*sz*/) {
    DWORD m = (DWORD)min(cur.size(), prev.size());
    char line[UI_W + 2] = {}; int pos = 0;
    for (DWORD i = 0; i < m && pos < UI_W - 12; i++) {
        if (cur[i] != prev[i]) {
            int n = snprintf(line+pos, UI_W-pos,
                "B%lu:%02X->%02X  ", i, prev[i], cur[i]);
            if (n > 0) pos += n;
        }
    }
    if (pos > 0) uiSnifferAdd(line);
    prev = cur;
}

// ─── RAII-обёртка для HANDLE ──────────────────────────────────────
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

// ─── Поиск и открытие Nacon ───────────────────────────────────────
HANDLE OpenNacon() {
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);
    HDEVINFO hdi = SetupDiGetClassDevs(&hidGuid, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdi == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    SP_DEVICE_INTERFACE_DATA did = {};
    did.cbSize = sizeof(did);

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
            && attr.VendorID  == NACON_VID
            && attr.ProductID == NACON_PID;
        CloseHandle(ht);
        if (!match) continue;

        HANDLE hr = CreateFile(det->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        SetupDiDestroyDeviceInfoList(hdi);
        return hr;
    }
    SetupDiDestroyDeviceInfoList(hdi);
    return INVALID_HANDLE_VALUE;
}

// ─── Маппинг Nacon → Xbox 360 ─────────────────────────────────────
//
//  КАК ЗАПОЛНИТЬ:
//  1. Запусти программу, нажми S → снифер включится
//  2. Зажми одну кнопку → в консоли: B3:00->10
//     Байт 3, маска 0x10 → эта кнопка
//  3. Раскомментируй нужную строку, подставь свои значения
//  4. Пересобери (Ctrl+Shift+B)
//
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r = {};

    auto toAxis = [](BYTE b, bool inv) -> SHORT {
        int v = inv ? (128 - (int)b) : ((int)b - 128);
        v = v * 256;
        if (v >  32767) v =  32767;
        if (v < -32768) v = -32768;
        return (SHORT)v;
    };

    // ── Кнопки ──────────────────────────────────────────────────
    // if (buf[3] & 0x10) r.wButtons |= XUSB_GAMEPAD_A;
    // if (buf[3] & 0x20) r.wButtons |= XUSB_GAMEPAD_B;
    // if (buf[3] & 0x40) r.wButtons |= XUSB_GAMEPAD_X;
    // if (buf[3] & 0x80) r.wButtons |= XUSB_GAMEPAD_Y;
    // if (buf[4] & 0x01) r.wButtons |= XUSB_GAMEPAD_LEFT_SHOULDER;
    // if (buf[4] & 0x02) r.wButtons |= XUSB_GAMEPAD_RIGHT_SHOULDER;
    // if (buf[4] & 0x04) r.wButtons |= XUSB_GAMEPAD_START;
    // if (buf[4] & 0x08) r.wButtons |= XUSB_GAMEPAD_BACK;
    // if (buf[4] & 0x40) r.wButtons |= XUSB_GAMEPAD_LEFT_THUMB;
    // if (buf[4] & 0x80) r.wButtons |= XUSB_GAMEPAD_RIGHT_THUMB;

    // ── D-Pad hat-switch (значения 0-7, нейтраль=0x0F) ──────────
    // switch (buf[5] & 0x0F) {
    //     case 0: r.wButtons |= XUSB_GAMEPAD_DPAD_UP;                              break;
    //     case 1: r.wButtons |= XUSB_GAMEPAD_DPAD_UP   | XUSB_GAMEPAD_DPAD_RIGHT; break;
    //     case 2: r.wButtons |= XUSB_GAMEPAD_DPAD_RIGHT;                           break;
    //     case 3: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN | XUSB_GAMEPAD_DPAD_RIGHT; break;
    //     case 4: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN;                            break;
    //     case 5: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN | XUSB_GAMEPAD_DPAD_LEFT;  break;
    //     case 6: r.wButtons |= XUSB_GAMEPAD_DPAD_LEFT;                            break;
    //     case 7: r.wButtons |= XUSB_GAMEPAD_DPAD_UP   | XUSB_GAMEPAD_DPAD_LEFT;  break;
    // }

    // ── Стики (центр=0x80, Y обычно инвертирован у MFi) ─────────
    // r.sThumbLX = toAxis(buf[6], false);
    // r.sThumbLY = toAxis(buf[7], true);
    // r.sThumbRX = toAxis(buf[8], false);
    // r.sThumbRY = toAxis(buf[9], true);

    // ── Триггеры (0x00-0xFF) ─────────────────────────────────────
    // r.bLeftTrigger  = buf[10];
    // r.bRightTrigger = buf[11];

    (void)toAxis;
    return r;
}

// ─── Main ─────────────────────────────────────────────────────────
int main() {
    uiInit();
    uiFrame();
    uiStatus(false, false, false, 0, 0);
    uiSnifferState(false);

    // 1. ViGEm — жёсткий выход при ошибке
    const auto client = vigem_alloc();
    if (!client) {
        uiMsg("FATAL: vigem_alloc failed — out of memory.", CC_RED);
        Sleep(3000); return -1;
    }
    if (!VIGEM_SUCCESS(vigem_connect(client))) {
        uiMsg("FATAL: ViGEmBus not found. Install the driver.", CC_RED);
        Sleep(3000); vigem_free(client); return -1;
    }
    const auto pad = vigem_target_x360_alloc();
    if (!VIGEM_SUCCESS(vigem_target_add(client, pad))) {
        uiMsg("FATAL: could not create virtual Xbox pad.", CC_RED);
        Sleep(3000);
        vigem_target_free(pad); vigem_disconnect(client); vigem_free(client);
        return -1;
    }
    uiStatus(true, false, true, 0, 0);

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

    // 3. Размер HID-пакета
    PHIDP_PREPARSED_DATA ppd;
    if (!HidD_GetPreparsedData(hNacon, &ppd)) {
        uiMsg("FATAL: HidD_GetPreparsedData failed.", CC_RED);
        Sleep(3000); return -1;
    }
    HIDP_CAPS caps; HidP_GetCaps(ppd, &caps);
    DWORD rSz = caps.InputReportByteLength;
    HidD_FreePreparsedData(ppd);
    uiStatus(true, true, true, rSz, 0);

    // 4. Асинхронное событие
    HG hEv(CreateEvent(NULL, TRUE, FALSE, NULL));
    if (!hEv.valid()) {
        uiMsg("FATAL: CreateEvent failed.", CC_RED);
        Sleep(3000); return -1;
    }
    OVERLAPPED ov = {}; ov.hEvent = hEv;

    std::vector<BYTE> rbuf(rSz), pbuf(rSz, 0);
    bool running = true, pending = false, snifOn = false;
    DWORD pkts = 0;

    // 5. Главный цикл
    while (running) {
        if (_kbhit()) {
            int k = _getch();
            if (k == 27) { running = false; break; }
            if (k == 's' || k == 'S') { snifOn = !snifOn; uiSnifferState(snifOn); }
        }

        if (!pending) {
            ResetEvent(ov.hEvent);
            DWORD imm = 0;
            if (ReadFile(hNacon, rbuf.data(), rSz, &imm, &ov)) {
                SetEvent(ov.hEvent);
            } else if (GetLastError() != ERROR_IO_PENDING) {
                CancelIoEx(hNacon, NULL);
                hNacon.reset();
                uiStatus(true, false, true, rSz, pkts);
                uiMsg("Nacon disconnected — reconnecting...", CC_YEL);
                while (!hNacon.valid()) { Sleep(2000); hNacon.reset(OpenNacon()); }
                uiClearMsg();
                ov.hEvent = hEv;
                uiStatus(true, true, true, rSz, pkts);
                continue;
            }
            pending = true;
        }

        DWORD wt = WaitForSingleObject(ov.hEvent, 10);
        if (wt == WAIT_OBJECT_0) {
            DWORD br = 0;
            if (GetOverlappedResult(hNacon, &ov, &br, FALSE)) {
                pending = false;
                if (br == rSz) {
                    ++pkts;
                    uiRawBytes(rbuf.data(), rSz);
                    if (snifOn) SnifferDelta(rbuf, pbuf, rSz);
                    XUSB_REPORT xr = MapNaconToXbox(rbuf);
                    if (!VIGEM_SUCCESS(vigem_target_x360_update(client, pad, xr)))
                        uiMsg("vigem update error — ViGEm disconnected?", CC_RED);
                    uiGamepad(xr);
                    uiStatus(true, true, true, rSz, pkts);
                }
            }
        } else if (wt != WAIT_TIMEOUT) {
            break;
        }
    }

    // 6. Очистка
    if (pending) CancelIoEx(hNacon, NULL);
    vigem_target_remove(client, pad);
    vigem_target_free(pad);
    vigem_disconnect(client);
    vigem_free(client);
    uiRestore();
    return 0;
}
