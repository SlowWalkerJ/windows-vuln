# Out-of-Bounds Read in vmulti.sys HID String Descriptor Handling

## Summary

`vmulti.sys` (Virtual Multitouch HID minidriver, vendor string "DJP Inc.",
device "Virtual Multitouch Device") is vulnerable to an out-of-bounds read
(CWE-125). When the driver services a HID string descriptor request
(Manufacturer, Product, or Serial Number), it copies the static string from
the driver image into a caller-provided buffer using a copy length derived
from the caller-controlled buffer size rather than the actual string length.
As a result the kernel-mode copy reads past the string and into adjacent
driver image memory.

- If the over-read stays within mapped pages, the excess bytes are returned
  to the caller (kernel information disclosure).
- If the requested length crosses into unmapped or non-accessible pages, the
  kernel access violation raises a BugCheck (blue screen / denial of
  service). The driver imports `KeBugCheckEx`.

The bug is reachable from a low-privilege local process that can open the
device's HID interface; no special privileges are required.

## Affected Component

| Field            | Value                                                        |
| ---------------- | ------------------------------------------------------------ |
| Component        | `vmulti.sys` (KMDF Virtual HID minidriver)                    |
| Vendor string    | `DJP Inc.` / `Virtual Multitouch Device`                      |
| Hardware IDs     | `VID=0x00FF`, `PID=0xBACC`, `UsagePage=0xFF00`, `Usage=0x01`  |
| File / version   | `vmulti.sys` (file dated 2020-03-21; internal version not determined) |

The vulnerable code path is exercised by the HID string-descriptor I/O paths
exposed to the HID class driver (`HidD_GetManufacturerString`,
`HidD_GetProductString`, `HidD_GetSerialNumberString`).

## Root Cause

The driver stores its HID string descriptors as static strings inside the
driver image:

| Descriptor | Index | Static string              | Actual size (incl. NUL) |
| ---------- | ----- | -------------------------- | ----------------------- |
| Manufacturer | 0x0E | `DJP Inc.`                | 18 bytes                |
| Product      | 0x0F | `Virtual Multitouch Device` | 52 bytes                |
| Serial       | 0x10 | `123123123`               | 20 bytes                |

When a request specifies a buffer larger than the real string, the copy
length passed into the kernel memory-copy operation is not clamped to the
static string's size. The kernel therefore reads beyond the string:

1. **Information disclosure** — bytes immediately following the string in the
   driver image are copied back to the caller.
2. **Denial of service** — a sufficiently large length walks past the mapped
   image into an unmapped region, and the resulting fault triggers a BugCheck.

## Impact

- **Information disclosure** — kernel data beyond the real string length is
  returned to user mode.
- **Denial of service (system crash)** — an oversized buffer length can blue
  screen the host.

Whether a crash occurs is conditional: it depends on the OS build, driver
image layout, and requested length. A crash is not required to prove the
bug; returning bytes past the real string length is already sufficient
evidence of the out-of-bounds read.

## Setup — Install the Driver

Install the driver from an **elevated** command prompt:

```powershell
cd driver_vmulti
.\install_vmulti_64.bat
```

The script self-elevates through UAC and installs the device using:

```text
devcon.exe /r install vmulti.inf pentablet\hid
```

A reboot is normally required afterwards. Use `remove_vmulti_64.bat` (also
elevated) to uninstall the driver.

## Proof of Concept — Reproduction

```powershell
.\vmulti_test.exe strings [buffer-bytes]
```

- `buffer-bytes` is parsed as an integer (`0x...` for hex); it must be in
  the range `64 .. 0x100000`. If omitted it defaults to `0x1000`.
- The program enumerates the vmulti HID collection, opens it for read, then
  queries the Manufacturer (`0x0E`), Product (`0x0F`), and Serial (`0x10`)
  string descriptors with the requested buffer size.
- For each descriptor it reports how many bytes were modified past the
  string's expected length and dumps the leaked tail bytes.

Safe, non-crashing confirmation:

```powershell
.\vmulti_test.exe strings 0x1000
```

Only in an isolated VM snapshot with a kernel debugger attached, and where a
reboot is acceptable, increase the length to observe the crash:

```powershell
.\vmulti_test.exe strings 0x10000
```

The program does not loop and does not send a high-risk length by default.

## Kernel Debugging Evidence

On the target system, set a breakpoint on the internal memory-copy to observe
the copy length:

```text
lm m vmulti
bp vmulti+0x1d40
```

At the breakpoint, the x64 calling convention is:

```text
rcx = destination buffer
rdx = static string source address
r8  = copy length
```

If the requested length is `0x1000` and `r8=0x1000`, the caller-controlled
length is being carried directly into the kernel copy.

## Environment / Notes

This POC can crash the system. Run it only in an authorized, isolated test
environment — never on a production host or a machine with unsaved data.
