#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <ViGEm/Client.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <conio.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

#define NACON_VID 0x3285
#define NACON_PID 0x1604

// --- RAII-обёртка для HANDLE ---
struct HandleGuard {
    HANDLE h = INVALID_HANDLE_VALUE;
    HandleGuard() = default;
    explicit HandleGuard(HANDLE h) : h(h) {}
    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(HandleGuard&&) noexcept = default;
    operator HANDLE() const { return h; }
    bool valid() const { return h != INVALID_HANDLE_VALUE; }
};

// --- Поиск и открытие устройства Nacon ---
HANDLE OpenNaconDevice() {
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO hDevInfo = SetupDiGetClassDevs(
        &hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    SP_DEVICE_INTERFACE_DATA devIntData = {};
    devIntData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (int i = 0; SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &hidGuid, i, &devIntData); i++) {
        DWORD reqSize = 0;
        SetupDiGetDeviceInterfaceDetail(hDevInfo, &devIntData, NULL, 0, &reqSize, NULL);

        std::vector<BYTE> detailBuf(reqSize);
        auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(detailBuf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &devIntData, detail, reqSize, NULL, NULL))
            continue; // BUG FIX: раньше здесь утекал malloc-буфер

        // Шаг 1: проверяем VID/PID без прав доступа
        HandleGuard hTest(CreateFile(detail->DevicePath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL));

        if (!hTest.valid()) continue;

        HIDD_ATTRIBUTES attr = {};
        attr.Size = sizeof(attr);
        if (!HidD_GetAttributes(hTest, &attr)) continue;
        if (attr.VendorID != NACON_VID || attr.ProductID != NACON_PID) continue;

        // Шаг 2: открываем с правами чтения/записи + OVERLAPPED
        HANDLE hRead = CreateFile(detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

        SetupDiDestroyDeviceInfoList(hDevInfo);

        if (hRead == INVALID_HANDLE_VALUE)
            std::cerr << "[!] Nacon найден, но доступ запрещён. Код: " << GetLastError() << "\n";

        return hRead;
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return INVALID_HANDLE_VALUE;
}

// --- Дельта-снифер: печатает только изменившиеся байты ---
void PrintDelta(const std::vector<BYTE>& cur, std::vector<BYTE>& prev, DWORD size) {
    bool changed = false;
    for (DWORD i = 0; i < size; i++) {
        if (cur[i] != prev[i]) {
            if (!changed) {
                std::cout << "\n[DELTA] ";
                changed = true;
            }
            std::cout << "B" << std::dec << i << "="
                      << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << (int)cur[i] << " ";
        }
    }
    if (changed) std::cout << std::dec << "\n";
    prev = cur;
}

// --- Маппинг Nacon -> Xbox 360 (заполни после реверса) ---
XUSB_REPORT MapNaconToXbox(const std::vector<BYTE>& buf) {
    XUSB_REPORT r = {};
    /*
        Инструкция по заполнению:
        1. Запусти программу, нажми 'S' для включения снифера
        2. Зажимай кнопки по одной, смотри на дельту
        3. Запиши номер байта и значение для каждой кнопки
        4. Раскомментируй и заполни строки ниже:

        Кнопки (wButtons — битовые флаги):
        if (buf[3] & 0x10) r.wButtons |= XUSB_GAMEPAD_A;
        if (buf[3] & 0x20) r.wButtons |= XUSB_GAMEPAD_B;
        if (buf[3] & 0x40) r.wButtons |= XUSB_GAMEPAD_X;
        if (buf[3] & 0x80) r.wButtons |= XUSB_GAMEPAD_Y;
        if (buf[4] & 0x01) r.wButtons |= XUSB_GAMEPAD_LEFT_SHOULDER;
        if (buf[4] & 0x02) r.wButtons |= XUSB_GAMEPAD_RIGHT_SHOULDER;
        if (buf[4] & 0x04) r.wButtons |= XUSB_GAMEPAD_START;
        if (buf[4] & 0x08) r.wButtons |= XUSB_GAMEPAD_BACK;

        D-Pad (обычно hat-switch, один байт, значения 0-7):
        switch (buf[5] & 0x0F) {
            case 0: r.wButtons |= XUSB_GAMEPAD_DPAD_UP;    break;
            case 2: r.wButtons |= XUSB_GAMEPAD_DPAD_RIGHT; break;
            case 4: r.wButtons |= XUSB_GAMEPAD_DPAD_DOWN;  break;
            case 6: r.wButtons |= XUSB_GAMEPAD_DPAD_LEFT;  break;
        }

        Аналоговые оси (обычно 0x00-0xFF, центр 0x80):
        r.sThumbLX = (SHORT)((buf[6] - 128) * 258);
        r.sThumbLY = (SHORT)((127 - buf[7]) * 258); // Y инвертирован
        r.sThumbRX = (SHORT)((buf[8] - 128) * 258);
        r.sThumbRY = (SHORT)((127 - buf[9]) * 258);

        Триггеры (0x00-0xFF):
        r.bLeftTrigger  = buf[10];
        r.bRightTrigger = buf[11];
    */
    return r;
}

int main() {
    std::cout << "[*] Nacon MG-X -> Xbox 360 Bridge\n";
    std::cout << "[*] S = включить/выключить снифер | ESC = выход\n\n";

    // 1. ViGEm инициализация
    const auto client = vigem_alloc();
    if (!client) { std::cerr << "[!] Нет памяти для ViGEm.\n"; return -1; }

    if (!VIGEM_SUCCESS(vigem_connect(client))) {
        std::cerr << "[!] ViGEmBus не найден. Установи драйвер.\n";
        vigem_free(client);
        return -1;
    }

    const auto pad = vigem_target_x360_alloc();
    if (!VIGEM_SUCCESS(vigem_target_add(client, pad))) {
        std::cerr << "[!] Не удалось создать виртуальный геймпад.\n";
        vigem_target_free(pad);
        vigem_disconnect(client);
        vigem_free(client);
        return -1;
    }
    std::cout << "[+] Виртуальный Xbox 360 создан.\n";

    // 2. Поиск физического Nacon (с поддержкой переподключения)
    HandleGuard hNacon;
    while (!hNacon.valid()) {
        hNacon = HandleGuard(OpenNaconDevice());
        if (!hNacon.valid()) {
            std::cerr << "[!] Nacon не найден. Подключи геймпад...\n";
            Sleep(2000);
        }
    }
    std::cout << "[+] Nacon MG-X захвачен!\n";

    // 3. Размер пакета
    PHIDP_PREPARSED_DATA ppd;
    if (!HidD_GetPreparsedData(hNacon, &ppd)) {
        std::cerr << "[!] Не удалось получить HID-дескриптор.\n";
        return -1;
    }
    HIDP_CAPS caps;
    HidP_GetCaps(ppd, &caps);
    DWORD reportSize = caps.InputReportByteLength;
    HidD_FreePreparsedData(ppd);
    std::cout << "[*] Размер HID-пакета: " << reportSize << " байт.\n";

    std::vector<BYTE> reportBuffer(reportSize);
    std::vector<BYTE> prevBuffer(reportSize, 0);

    HandleGuard hEvent(CreateEvent(NULL, TRUE, FALSE, NULL));
    if (!hEvent.valid()) { std::cerr << "[!] Ошибка создания события.\n"; return -1; }

    OVERLAPPED ov = {};
    ov.hEvent = hEvent;

    bool isRunning    = true;
    bool isReadPending = false;
    bool snifferOn    = false;
    DWORD bytesRead   = 0;

    std::cout << "[*] Цикл запущен. ESC — выход, S — снифер.\n\n";

    while (isRunning) {
        // Клавиши управления
        if (_kbhit()) {
            int key = _getch();
            if (key == 27) { // ESC
                std::cout << "\n[*] Выход...\n";
                break;
            }
            if (key == 's' || key == 'S') {
                snifferOn = !snifferOn;
                std::cout << "[*] Снифер: " << (snifferOn ? "ВКЛ (дельта)" : "ВЫКЛ") << "\n";
            }
        }

        // Запускаем новое асинхронное чтение
        if (!isReadPending) {
            ResetEvent(ov.hEvent);
            DWORD immedBytes = 0;
            BOOL readOk = ReadFile(hNacon, reportBuffer.data(), reportSize, &immedBytes, &ov);

            if (readOk) {
                // BUG FIX: ReadFile вернул TRUE — данные уже готовы, берём байты напрямую
                bytesRead = immedBytes;
                // Искусственно сигналим событие для единого пути обработки
                SetEvent(ov.hEvent);
                isReadPending = true;
            } else if (GetLastError() == ERROR_IO_PENDING) {
                isReadPending = true;
            } else {
                std::cerr << "[!] Ошибка ReadFile. Код: " << GetLastError() << "\n";
                // Попытка переподключения
                CancelIo(hNacon);
                hNacon = HandleGuard();
                isReadPending = false;
                std::cout << "[*] Ожидание переподключения Nacon...\n";
                while (!hNacon.valid()) {
                    Sleep(2000);
                    hNacon = HandleGuard(OpenNaconDevice());
                }
                ov.hEvent = hEvent;
                std::cout << "[+] Nacon переподключён!\n";
                continue;
            }
        }

        // Ждём завершения чтения (10 мс таймаут для отклика на клавиши)
        if (isReadPending) {
            DWORD waitResult = WaitForSingleObject(ov.hEvent, 10);

            if (waitResult == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hNacon, &ov, &bytesRead, FALSE)) {
                    isReadPending = false;

                    if (bytesRead == reportSize) {
                        // Снифер
                        if (snifferOn)
                            PrintDelta(reportBuffer, prevBuffer, bytesRead);

                        // Маппинг и отправка
                        XUSB_REPORT xReport = MapNaconToXbox(reportBuffer);
                        VIGEM_ERROR err = vigem_target_x360_update(client, pad, xReport);
                        if (!VIGEM_SUCCESS(err))
                            std::cerr << "[!] vigem_target_x360_update ошибка: " << err << "\n";
                    }
                }
            } else if (waitResult == WAIT_TIMEOUT) {
                continue; // Нормально, ждём следующей итерации
            } else {
                std::cerr << "[!] WaitForSingleObject: неожиданный результат.\n";
                break;
            }
        }
    }

    // 4. Очистка
    if (isReadPending)
        CancelIo(hNacon);

    std::cout << "[*] Удаление виртуального геймпада...\n";
    vigem_target_remove(client, pad);
    vigem_target_free(pad);
    vigem_disconnect(client);
    vigem_free(client);

    return 0;
}
