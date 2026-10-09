# vmulti HID Input Injection PoC

This proof of concept demonstrates that the `vmulti.sys` virtual HID driver
accepts crafted vendor-specific output reports that are translated into
synthetic mouse and digitizer input.

The PoC is intended for testing the affected driver in an isolated Windows
virtual machine. It can move the cursor, generate a mouse click, and send a
digitizer/touch sequence. Do not run it on a production system or while an
unexpected click could cause harm.

## Driver installation

1. Use a Windows x64 test system or virtual machine.
2. Open an elevated Command Prompt (Run as administrator).
3. From the directory containing the driver package, install the driver with:

   ```bat
   driver_vmulti\install_vmulti_64.bat
   ```

4. Reconnect or enable the virtual device if Windows requests it. Confirm that
   the Pentablet HID device is present before running the test program.

## Test program

Run the executable from the directory containing the test files:

```text
vmulti_inject_test.exe <command> [arguments]
```

Available commands:

```text
vmulti_inject_test.exe list
vmulti_inject_test.exe mouse <dx> <dy>
vmulti_inject_test.exe mouse-absolute <x> <y>
vmulti_inject_test.exe click
vmulti_inject_test.exe digitizer <x> <y>
vmulti_inject_test.exe digitizer-hover <x> <y>
```

### Examples

```bat
vmulti_inject_test.exe list
vmulti_inject_test.exe mouse 50 0
vmulti_inject_test.exe mouse-absolute 16000 16000
vmulti_inject_test.exe click
vmulti_inject_test.exe digitizer 16384 16384
vmulti_inject_test.exe digitizer-hover 16384 16384
```

`mouse` sends relative movement. `mouse-absolute` uses coordinates in the
0-32767 HID range. `click` sends a press followed by a release. `digitizer`
sends a short touch sequence, while `digitizer-hover` sends a hover/in-range
sequence without a tip-down event.

The program first enumerates the HID collections for VID `0x00FF` and PID
`0xBACC`, then opens the vendor output collection and submits the corresponding
HID report. The exact result depends on the installed report descriptor and
Windows HID stack. The program does not implement keyboard injection or the
string/OOB-read test.

## Removing the driver

From an elevated Command Prompt in the directory containing the driver package,
run:

```bat
   driver_vmulti\remove_vmulti_64.bat
```

Reboot the test system if Windows requests a restart.

## Safety and cleanup

The generated reports are processed as real input by Windows. Keep the cursor
away from destructive controls during testing, and use a disposable test
account or virtual machine. The driver should be removed after testing.
