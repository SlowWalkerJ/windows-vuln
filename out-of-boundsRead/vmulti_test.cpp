#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <setupapi.h>

#include <algorithm>
#include <cwchar>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

namespace {
constexpr USHORT kVendorId = 0x00FF;
constexpr USHORT kProductId = 0xBACC;
constexpr USHORT kUsagePage = 0xFF00;
constexpr USHORT kUsage = 0x0001;

struct HidEndpoint {
    std::wstring path;
    HIDD_ATTRIBUTES attributes{};
    HIDP_CAPS caps{};
};

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~ScopedHandle() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE handle_;
};

std::vector<HidEndpoint> EnumerateEndpoints() {
    GUID hidGuid{};
    HidD_GetHidGuid(&hidGuid);
    HDEVINFO info = SetupDiGetClassDevsW(
        &hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (info == INVALID_HANDLE_VALUE) return {};

    std::vector<HidEndpoint> result;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(
                info, nullptr, &hidGuid, index, &interfaceData)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            continue;
        }

        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(
            info, &interfaceData, nullptr, 0, &requiredSize, nullptr);
        if (requiredSize < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) continue;

        std::vector<BYTE> storage(requiredSize);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(
            storage.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(
                info, &interfaceData, detail, requiredSize, nullptr, nullptr)) {
            continue;
        }

        ScopedHandle handle(CreateFileW(
            detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        if (!handle.valid()) continue;

        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(attributes);
        if (!HidD_GetAttributes(handle.get(), &attributes) ||
            attributes.VendorID != kVendorId || attributes.ProductID != kProductId) {
            continue;
        }

        PHIDP_PREPARSED_DATA preparsed = nullptr;
        if (!HidD_GetPreparsedData(handle.get(), &preparsed)) continue;
        HIDP_CAPS caps{};
        const NTSTATUS status = HidP_GetCaps(preparsed, &caps);
        HidD_FreePreparsedData(preparsed);
        if (status != HIDP_STATUS_SUCCESS || caps.UsagePage != kUsagePage ||
            caps.Usage != kUsage) continue;

        result.push_back({detail->DevicePath, attributes, caps});
    }
    SetupDiDestroyDeviceInfoList(info);
    return result;
}

void PrintEndpoint(const HidEndpoint& endpoint) {
    std::wcout << L"VID=" << std::hex << endpoint.attributes.VendorID
               << L" PID=" << endpoint.attributes.ProductID
               << L" UsagePage=" << endpoint.caps.UsagePage
               << L" Usage=" << endpoint.caps.Usage << std::dec
               << L" Input=" << endpoint.caps.InputReportByteLength
               << L" Output=" << endpoint.caps.OutputReportByteLength
               << L" Feature=" << endpoint.caps.FeatureReportByteLength
               << L"\n  " << endpoint.path << L'\n';
}

ScopedHandle OpenRead(const HidEndpoint& endpoint) {
    return ScopedHandle(CreateFileW(
        endpoint.path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
}

void DumpBytes(const std::vector<UCHAR>& bytes, size_t begin, size_t end) {
    end = std::min(end, bytes.size());
    for (size_t offset = begin; offset < end; offset += 16) {
        std::wcout << L"  +0x" << std::hex << offset << L": ";
        const size_t lineEnd = std::min(offset + 16, end);
        for (size_t i = offset; i < lineEnd; ++i) {
            std::wcout << (bytes[i] < 0x10 ? L"0" : L"")
                       << static_cast<unsigned>(bytes[i]) << L' ';
        }
        std::wcout << std::dec << L'\n';
    }
}

bool ProbeString(HANDLE handle, const wchar_t* name, ULONG requestedBytes,
                 ULONG expectedBytes,
                 BOOLEAN(WINAPI* query)(HANDLE, PVOID, ULONG)) {
    std::vector<UCHAR> buffer(requestedBytes, 0xCC);
    SetLastError(ERROR_SUCCESS);
    const BOOL ok = query(handle, buffer.data(), requestedBytes);
    const DWORD error = GetLastError();
    std::wcout << name << L": ok=" << (ok ? L"true" : L"false")
               << L" requested=" << requestedBytes << L" bytes\n";
    if (!ok) {
        std::wcout << L"  error=" << error << L'\n';
        return false;
    }

    size_t changedTailBytes = 0;
    for (size_t i = expectedBytes; i < buffer.size(); ++i) {
        if (buffer[i] != 0xCC) ++changedTailBytes;
    }
    std::wcout << L"  bytes changed after expected string length ("
               << expectedBytes << L"): " << changedTailBytes << L"\n";
    DumpBytes(buffer, expectedBytes, expectedBytes + 128);
    return true;
}

bool ParseSize(const wchar_t* text, ULONG& value) {
    wchar_t* end = nullptr;
    SetLastError(ERROR_SUCCESS);
    const unsigned long parsed = wcstoul(text, &end, 0);
    if (GetLastError() != ERROR_SUCCESS || end == text || *end != L'\0' ||
        parsed < 64 || parsed > 0x100000) return false;
    value = static_cast<ULONG>(parsed);
    return true;
}

int RunStrings(const std::vector<HidEndpoint>& endpoints, ULONG requestedBytes) {
    if (endpoints.empty()) {
        std::wcerr << L"The vmulti vendor HID collection was not found.\n";
        return 1;
    }

    bool anySuccess = false;
    for (const auto& endpoint : endpoints) {
        PrintEndpoint(endpoint);
        auto handle = OpenRead(endpoint);
        if (!handle.valid()) {
            std::wcerr << L"Cannot open the HID collection for reading. Error: "
                       << GetLastError() << L'\n';
            continue;
        }
        anySuccess |= ProbeString(handle.get(), L"Manufacturer (0x0E)",
                                  requestedBytes, 18, HidD_GetManufacturerString);
        anySuccess |= ProbeString(handle.get(), L"Product (0x0F)",
                                  requestedBytes, 52, HidD_GetProductString);
        anySuccess |= ProbeString(handle.get(), L"Serial (0x10)",
                                  requestedBytes, 20, HidD_GetSerialNumberString);
    }
    return anySuccess ? 0 : 1;
}

void PrintUsage() {
    std::wcout << L"Usage:\n"
               << L"  vmulti_test.exe strings [buffer-bytes]\n"
               << L"\nExamples:\n"
               << L"  vmulti_test.exe strings 0x100\n"
               << L"  vmulti_test.exe strings 0x10000\n";
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2 || std::wstring(argv[1]) != L"strings" || argc > 3) {
        PrintUsage();
        return 2;
    }
    ULONG requestedBytes = 0x1000;
    if (argc == 3 && !ParseSize(argv[2], requestedBytes)) {
        PrintUsage();
        return 2;
    }
    return RunStrings(EnumerateEndpoints(), requestedBytes);
}
