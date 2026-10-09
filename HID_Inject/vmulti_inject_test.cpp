#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <setupapi.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "user32.lib")

namespace {

constexpr USHORT kVendorId = 0x00FF;
constexpr USHORT kProductId = 0xBACC;
constexpr USHORT kVendorUsagePage = 0xFF00;
constexpr UCHAR kEnvelopeReportId = 0x40;

struct HidEndpoint {
    std::wstring path;
    HIDD_ATTRIBUTES attributes{};
    HIDP_CAPS caps{};
    std::vector<UCHAR> outputReportIds;
};

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~ScopedHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_;
};

std::vector<HidEndpoint> EnumerateHidEndpoints() {
    GUID hidGuid{};
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO deviceInfo = SetupDiGetClassDevsW(
        &hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfo == INVALID_HANDLE_VALUE) {
        return {};
    }

    std::vector<HidEndpoint> endpoints;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(deviceInfo, nullptr, &hidGuid, index, &interfaceData)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                break;
            }
            continue;
        }

        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(
            deviceInfo, &interfaceData, nullptr, 0, &requiredSize, nullptr);
        if (requiredSize < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            continue;
        }

        std::vector<BYTE> detailStorage(requiredSize);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(
            detailStorage.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(
                deviceInfo,
                &interfaceData,
                detail,
                requiredSize,
                nullptr,
                nullptr)) {
            continue;
        }

        ScopedHandle queryHandle(CreateFileW(
            detail->DevicePath,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr));
        if (!queryHandle.valid()) {
            continue;
        }

        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(attributes);
        if (!HidD_GetAttributes(queryHandle.get(), &attributes)) {
            continue;
        }

        PHIDP_PREPARSED_DATA preparsedData = nullptr;
        if (!HidD_GetPreparsedData(queryHandle.get(), &preparsedData)) {
            continue;
        }

        HIDP_CAPS caps{};
        const NTSTATUS capsStatus = HidP_GetCaps(preparsedData, &caps);
        if (capsStatus != HIDP_STATUS_SUCCESS) {
            HidD_FreePreparsedData(preparsedData);
            continue;
        }

        std::vector<UCHAR> outputReportIds;
        if (caps.NumberOutputValueCaps != 0) {
            USHORT count = caps.NumberOutputValueCaps;
            std::vector<HIDP_VALUE_CAPS> valueCaps(count);
            if (HidP_GetValueCaps(
                    HidP_Output, valueCaps.data(), &count, preparsedData) ==
                HIDP_STATUS_SUCCESS) {
                for (USHORT capIndex = 0; capIndex < count; ++capIndex) {
                    const UCHAR reportId = valueCaps[capIndex].ReportID;
                    if (std::find(
                            outputReportIds.begin(), outputReportIds.end(), reportId) ==
                        outputReportIds.end()) {
                        outputReportIds.push_back(reportId);
                    }
                }
            }
        }
        HidD_FreePreparsedData(preparsedData);

        HidEndpoint endpoint;
        endpoint.path = detail->DevicePath;
        endpoint.attributes = attributes;
        endpoint.caps = caps;
        endpoint.outputReportIds = std::move(outputReportIds);
        endpoints.push_back(std::move(endpoint));
    }

    SetupDiDestroyDeviceInfoList(deviceInfo);
    return endpoints;
}

bool IsInjectionEndpoint(const HidEndpoint& endpoint) {
    return endpoint.attributes.VendorID == kVendorId &&
           endpoint.attributes.ProductID == kProductId &&
           endpoint.caps.UsagePage >= kVendorUsagePage &&
           endpoint.caps.OutputReportByteLength >= 65 &&
           std::find(
               endpoint.outputReportIds.begin(),
               endpoint.outputReportIds.end(),
               kEnvelopeReportId) != endpoint.outputReportIds.end();
}

const HidEndpoint* FindInputEndpoint(
    const std::vector<HidEndpoint>& endpoints,
    USHORT usagePage,
    USHORT usage,
    USHORT inputReportLength = 0) {
    const auto endpoint = std::find_if(
        endpoints.begin(), endpoints.end(),
        [=](const HidEndpoint& candidate) {
            return candidate.attributes.VendorID == kVendorId &&
                   candidate.attributes.ProductID == kProductId &&
                   candidate.caps.UsagePage == usagePage &&
                   candidate.caps.Usage == usage &&
                   (inputReportLength == 0 ||
                    candidate.caps.InputReportByteLength == inputReportLength);
        });
    return endpoint == endpoints.end() ? nullptr : &*endpoint;
}

void PrintEndpoint(const HidEndpoint& endpoint) {
    std::wcout << L"VID=" << std::hex << endpoint.attributes.VendorID
               << L" PID=" << endpoint.attributes.ProductID
               << L" UsagePage=" << endpoint.caps.UsagePage
               << L" Usage=" << endpoint.caps.Usage << std::dec
               << L" Input=" << endpoint.caps.InputReportByteLength
               << L" Output=" << endpoint.caps.OutputReportByteLength
               << L" Feature=" << endpoint.caps.FeatureReportByteLength;
    if (!endpoint.outputReportIds.empty()) {
        std::wcout << L" OutputReportIds=";
        for (UCHAR reportId : endpoint.outputReportIds) {
            std::wcout << L"0x" << std::hex << static_cast<unsigned>(reportId)
                       << L' ' << std::dec;
        }
    }
    std::wcout << L"\n  " << endpoint.path << L'\n';
}

ScopedHandle OpenForWrite(const HidEndpoint& endpoint) {
    HANDLE handle = CreateFileW(
        endpoint.path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        handle = CreateFileW(
            endpoint.path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
    }
    return ScopedHandle(handle);
}

bool SendEnvelope(
    HANDLE handle,
    USHORT outputReportLength,
    const std::vector<UCHAR>& payload) {
    if (payload.size() > 0xFF || payload.size() + 2 > outputReportLength) {
        std::wcerr << L"Payload is too large for the HID output report.\n";
        return false;
    }

    std::vector<UCHAR> report(outputReportLength, 0);
    report[0] = kEnvelopeReportId;
    report[1] = static_cast<UCHAR>(payload.size());
    std::copy(payload.begin(), payload.end(), report.begin() + 2);

    DWORD bytesWritten = 0;
    if (!WriteFile(
            handle,
            report.data(),
            static_cast<DWORD>(report.size()),
            &bytesWritten,
            nullptr)) {
        std::wcerr << L"WriteFile failed: " << GetLastError() << L'\n';
        return false;
    }
    if (bytesWritten != report.size()) {
        std::wcerr << L"Short HID write: " << bytesWritten << L" of "
                   << report.size() << L" bytes.\n";
        return false;
    }
    return true;
}

void AppendLe16(std::vector<UCHAR>& output, USHORT value);

bool SendRelativeMouse(
    HANDLE handle,
    USHORT outputReportLength,
    int dx,
    int dy,
    UCHAR buttons,
    int wheel = 0) {
    dx = std::clamp(dx, -127, 127);
    dy = std::clamp(dy, -127, 127);
    wheel = std::clamp(wheel, -127, 127);

    const std::vector<UCHAR> payload = {
        0x04,
        static_cast<UCHAR>(buttons & 0x1F),
        static_cast<UCHAR>(static_cast<std::int8_t>(dx)),
        static_cast<UCHAR>(static_cast<std::int8_t>(dy)),
        static_cast<UCHAR>(static_cast<std::int8_t>(wheel)),
    };
    return SendEnvelope(handle, outputReportLength, payload);
}

bool SendAbsoluteMouse(
    HANDLE handle,
    USHORT outputReportLength,
    USHORT x,
    USHORT y,
    UCHAR buttons,
    int wheel = 0) {
    x = std::min<USHORT>(x, 32767);
    y = std::min<USHORT>(y, 32767);
    wheel = std::clamp(wheel, -127, 127);

    std::vector<UCHAR> payload = {0x03, static_cast<UCHAR>(buttons & 0x1F)};
    AppendLe16(payload, x);
    AppendLe16(payload, y);
    payload.push_back(static_cast<UCHAR>(static_cast<std::int8_t>(wheel)));
    return SendEnvelope(handle, outputReportLength, payload);
}

void AppendLe16(std::vector<UCHAR>& output, USHORT value) {
    output.push_back(static_cast<UCHAR>(value & 0xFF));
    output.push_back(static_cast<UCHAR>((value >> 8) & 0xFF));
}

bool SendDigitizer(
    HANDLE handle,
    USHORT outputReportLength,
    USHORT inputReportLength,
    USHORT x,
    USHORT y,
    USHORT pressure,
    UCHAR status) {
    x = std::min<USHORT>(x, 32767);
    y = std::min<USHORT>(y, 32767);
    pressure = std::min<USHORT>(pressure, 2047);

    std::vector<UCHAR> payload;
    payload.reserve(inputReportLength);
    payload.push_back(0x05);
    // The public vmulti build uses a 6-byte digitizer report. The analyzed
    // Pentablet build uses an 8-byte variant with a pressure field.
    payload.push_back(status);
    AppendLe16(payload, x);
    AppendLe16(payload, y);
    if (inputReportLength == 8) {
        AppendLe16(payload, pressure);
    }
    return SendEnvelope(handle, outputReportLength, payload);
}

bool ParseInt(const wchar_t* text, long minimum, long maximum, int& result) {
    wchar_t* end = nullptr;
    SetLastError(ERROR_SUCCESS);
    const long value = wcstol(text, &end, 0);
    if (GetLastError() != ERROR_SUCCESS || end == text || *end != L'\0' ||
        value < minimum || value > maximum) {
        return false;
    }
    result = static_cast<int>(value);
    return true;
}

void PrintUsage() {
    std::wcout
        << L"Usage:\n"
        << L"  vmulti_inject_test.exe list\n"
        << L"  vmulti_inject_test.exe mouse <dx> <dy>\n"
        << L"  vmulti_inject_test.exe mouse-absolute <x:0-32767> <y:0-32767>\n"
        << L"  vmulti_inject_test.exe click\n"
        << L"  vmulti_inject_test.exe digitizer <x:0-32767> <y:0-32767>\n"
        << L"  vmulti_inject_test.exe digitizer-hover <x:0-32767> <y:0-32767>\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    const auto endpoints = EnumerateHidEndpoints();
    const std::wstring command = argv[1];
    if (command == L"list") {
        for (const auto& endpoint : endpoints) {
            if (endpoint.attributes.VendorID == kVendorId &&
                endpoint.attributes.ProductID == kProductId) {
                PrintEndpoint(endpoint);
            }
        }
        return 0;
    }

    const auto endpointIt = std::find_if(
        endpoints.begin(), endpoints.end(), IsInjectionEndpoint);
    if (endpointIt == endpoints.end()) {
        std::wcerr
            << L"The vmulti vendor endpoint was not found. Run 'list' first.\n";
        return 1;
    }

    PrintEndpoint(*endpointIt);
    auto handle = OpenForWrite(*endpointIt);
    if (!handle.valid()) {
        std::wcerr << L"The endpoint was found but cannot be opened for writing. "
                   << L"CreateFile error: " << GetLastError() << L'\n';
        return 1;
    }

    const USHORT outputLength = endpointIt->caps.OutputReportByteLength;

    if (command == L"mouse") {
        int dx = 0;
        int dy = 0;
        if (argc != 4 || !ParseInt(argv[2], -127, 127, dx) ||
            !ParseInt(argv[3], -127, 127, dy)) {
            PrintUsage();
            return 2;
        }
        if (!FindInputEndpoint(endpoints, 0x0001, 0x0002, 5)) {
            std::wcerr << L"No 5-byte relative mouse collection was found.\n";
            return 1;
        }
        POINT before{};
        POINT after{};
        GetCursorPos(&before);
        const bool sent = SendRelativeMouse(handle.get(), outputLength, dx, dy, 0);
        Sleep(150);
        GetCursorPos(&after);
        std::wcout << L"Cursor: (" << before.x << L", " << before.y << L") -> ("
                   << after.x << L", " << after.y << L")\n";
        return sent ? 0 : 1;
    }

    if (command == L"mouse-absolute") {
        int x = 0;
        int y = 0;
        if (argc != 4 || !ParseInt(argv[2], 0, 32767, x) ||
            !ParseInt(argv[3], 0, 32767, y)) {
            PrintUsage();
            return 2;
        }
        if (!FindInputEndpoint(endpoints, 0x0001, 0x0002, 7)) {
            std::wcerr << L"No 7-byte absolute mouse collection was found.\n";
            return 1;
        }
        POINT before{};
        POINT after{};
        GetCursorPos(&before);
        const bool sent = SendAbsoluteMouse(
            handle.get(), outputLength, static_cast<USHORT>(x),
            static_cast<USHORT>(y), 0);
        Sleep(150);
        GetCursorPos(&after);
        std::wcout << L"Cursor: (" << before.x << L", " << before.y << L") -> ("
                   << after.x << L", " << after.y << L")\n";
        return sent ? 0 : 1;
    }

    if (command == L"click") {
        if (!SendRelativeMouse(handle.get(), outputLength, 0, 0, 1)) {
            return 1;
        }
        Sleep(50);
        return SendRelativeMouse(handle.get(), outputLength, 0, 0, 0) ? 0 : 1;
    }

    if (command == L"digitizer" || command == L"digitizer-hover") {
        int x = 0;
        int y = 0;
        if (argc != 4 || !ParseInt(argv[2], 0, 32767, x) ||
            !ParseInt(argv[3], 0, 32767, y)) {
            PrintUsage();
            return 2;
        }
        const HidEndpoint* digitizer = FindInputEndpoint(endpoints, 0x000D, 0x0001);
        if (!digitizer || (digitizer->caps.InputReportByteLength != 6 &&
                           digitizer->caps.InputReportByteLength != 8)) {
            std::wcerr
                << L"This installed device does not expose a Digitizer "
                << L"top-level collection. The loaded report descriptor "
                << L"does not match the IDB, so Report ID 5 was not sent.\n";
            return 1;
        }
        const UCHAR inRange =
            digitizer->caps.InputReportByteLength == 6 ? 0x02 : 0x20;
        const UCHAR tipDown = static_cast<UCHAR>(inRange | 0x01);
        const USHORT reportLength = digitizer->caps.InputReportByteLength;

        POINT before{};
        POINT after{};
        GetCursorPos(&before);

        if (!SendDigitizer(
                handle.get(), outputLength, reportLength,
                static_cast<USHORT>(x), static_cast<USHORT>(y), 0, inRange)) {
            return 1;
        }
        Sleep(150);

        if (command == L"digitizer-hover") {
            Sleep(1000);
        } else {
            if (!SendDigitizer(
                    handle.get(), outputLength, reportLength,
                    static_cast<USHORT>(x), static_cast<USHORT>(y), 1024,
                    tipDown)) {
                return 1;
            }
            Sleep(500);
            if (!SendDigitizer(
                    handle.get(), outputLength, reportLength,
                    static_cast<USHORT>(x), static_cast<USHORT>(y), 0,
                    inRange)) {
                return 1;
            }
            Sleep(150);
        }

        if (!SendDigitizer(
                handle.get(), outputLength, reportLength,
                static_cast<USHORT>(x), static_cast<USHORT>(y), 0, 0)) {
            return 1;
        }
        Sleep(150);
        GetCursorPos(&after);
        std::wcout << L"Cursor: (" << before.x << L", " << before.y << L") -> ("
                   << after.x << L", " << after.y << L")\n";
        return 0;
    }

    PrintUsage();
    return 2;
}
