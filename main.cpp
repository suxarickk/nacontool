#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <vector>
#include <iostream>
#include <conio.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

#define NACON_VID 0x3285
#define NACON_PID 0x1604

XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r = {};
    return r;
}

int main() {
    std::cout << "Nacon Bridge Scanner Started\n";
    auto client = vigem_alloc();
    if (!client) return -1;
    vigem_connect(client);
    auto pad = vigem_target_x360_alloc();
    vigem_target_add(client, pad);

    std::cout << "Waiting for Nacon...\n";
    return 0;
}
