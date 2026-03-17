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

#define NACON_VID 0x3285
#define NACON_PID 0x0644 

enum CC : WORD { CC_BLK=0, CC_DGRN=2, CC_DGRY=8, CC_GRN=10, CC_CYN=11, CC_RED=12, CC_YEL=14, CC_WHT=15, CC_GRY=7 };
static HANDLE hCon;

void cXY(int x, int y) { COORD c = {(SHORT)x, (SHORT)y}; SetConsoleCursorPosition(hCon, c); }
void cCol(CC f) { SetConsoleTextAttribute(hCon, (WORD)f); }
void cWrite(const char* s) { DWORD n; WriteConsoleA(hCon, s, (DWORD)strlen(s), &n, NULL); }

void uiFrame() {
    system("cls");
    cCol(CC_CYN); cXY(0,0); cWrite("  NACON MG-X"); cCol(CC_DGRY); cWrite(" -> "); cCol(CC_GRN); cWrite("XBOX 360 BRIDGE");
    cCol(CC_DGRY); cXY(0,1); cWrite("--------------------------------------------------------------------------------");
    cXY(1, 2); cWrite("ViGEm:"); cXY(18, 2); cWrite("Nacon:"); cXY(35, 2); cWrite("Xbox:"); 
    cXY(0, 3); cWrite("--------------------------------------------------------------------------------");
    cXY(2, 5); cWrite("RAW DATA:");
    cXY(0, 9); cWrite("--------------------------------------------------------------------------------");
    cXY(2, 10); cWrite("BUTTONS TEST:");
    cXY(2, 22); cCol(CC_YEL); cWrite("[ESC] Exit");
}

void uiStatus(bool v, bool n) {
    cXY(8, 2); cCol(v ? CC_GRN : CC_RED); cWrite(v ? "[ON] " : "[OFF]");
    cXY(25, 2); cCol(n ? CC_GRN : CC_RED); cWrite(n ? "[ON] " : "[OFF]");
}

HANDLE OpenNacon() {
    GUID g; HidD_GetHidGuid(&g);
    HDEVINFO hdi = SetupDiGetClassDevs(&g, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    SP_DEVICE_INTERFACE_DATA did = { sizeof(did) };
    for (int i = 0; SetupDiEnumDeviceInterfaces(hdi, NULL, &g, i, &did); i++) {
        DWORD r = 0; SetupDiGetDeviceInterfaceDetail(hdi, &did, NULL, 0, &r, NULL);
        std::vector<BYTE> db(r); auto* det = (PSP_DEVICE_INTERFACE_DETAIL_DATA)db.data();
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        SetupDiGetDeviceInterfaceDetail(hdi, &did, det, r, NULL, NULL);
        HANDLE h = CreateFile(det->DevicePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        HIDD_ATTRIBUTES at = {sizeof(at)};
        if (HidD_GetAttributes(h, &at) && at.VendorID == NACON_VID && at.ProductID == NACON_PID) {
            PHIDP_PREPARSED_DATA ppd;
            if (HidD_GetPreparsedData(h, &ppd)) {
                HIDP_CAPS cp; HidP_GetCaps(ppd, &cp); HidD_FreePreparsedData(ppd);
                if (cp.InputReportByteLength > 0) { SetupDiDestroyDeviceInfoList(hdi); return h; }
            }
        }
        CloseHandle(h);
    }
    SetupDiDestroyDeviceInfoList(hdi); return INVALID_HANDLE_VALUE;
}

int main() {
    hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    uiFrame();
    
    auto cl = vigem_alloc();
    bool vOk = (cl && VIGEM_SUCCESS(vigem_connect(cl)));
    auto pad = vigem_target_x360_alloc();
    vigem_target_add(cl, pad);

    HANDLE hN = INVALID_HANDLE_VALUE;
    while(hN == INVALID_HANDLE_VALUE) {
        uiStatus(vOk, false);
        hN = OpenNacon();
        if (hN == INVALID_HANDLE_VALUE) Sleep(1000);
    }
    uiStatus(vOk, true);

    PHIDP_PREPARSED_DATA ppd; HidD_GetPreparsedData(hN, &ppd);
    HIDP_CAPS cp; HidP_GetCaps(ppd, &cp); HidD_FreePreparsedData(ppd);
    std::vector<BYTE> buf(cp.InputReportByteLength);
    OVERLAPPED ov = {0}; ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while(true) {
        if (_kbhit() && _getch() == 27) break;
        DWORD br = 0; ResetEvent(ov.hEvent);
        if (!ReadFile(hN, buf.data(), (DWORD)buf.size(), &br, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                WaitForSingleObject(ov.hEvent, 10);
                GetOverlappedResult(hN, &ov, &br, FALSE);
            }
        }
        if (br > 0) {
            cXY(0, 6); cCol(CC_WHT);
            for(DWORD i=0; i<br; i++) printf("%02X ", buf[i]);
            
            // Тестовый маппинг (если данные идут, Xbox-контроллер будет активен)
            XUSB_REPORT xr = {};
            if (br > 5) {
                xr.sThumbLX = (SHORT)(((int)buf[1]-128)*256);
                xr.sThumbLY = (SHORT)((128-(int)buf[2])*256);
            }
            vigem_target_x360_update(cl, pad, xr);
        }
    }
    return 0;
}
