"""Native Windows IPv4 transport using the WinDivert 2.x C API via ctypes.

Packet construction and OS detection remain in scanner.py. WinDivert supplies
only packet capture/injection. Obtain the DLL and signed driver separately:
https://reqrypt.org/windivert.html
"""

import ctypes as c
from pathlib import Path
import queue
import sys
import threading
import time


class DivertAddress(c.Structure):
    # WinDivert 2.x WINDIVERT_ADDRESS: timestamp, flag word, reserved, union.
    # Fixed-width integers avoid host-dependent C long sizes in offline tests.
    _fields_ = [("timestamp", c.c_int64), ("flags", c.c_uint32),
                ("reserved", c.c_uint32), ("data", c.c_uint8 * 64)]


def load_library(directory):
    if sys.platform != "win32":
        raise ValueError("WinDivert transport requires Windows")
    directory = (Path(directory) if directory is not None else
                 Path(__file__).with_name("WinDivert")).resolve()
    path = directory / "WinDivert.dll"
    if not path.is_file():
        raise ValueError("WinDivert.dll not found in %s. Download WinDivert 2.x from "
                         "https://reqrypt.org/windivert.html and use --windivert-dir "
                         "with the folder containing its DLL and signed driver." % directory)
    try:
        # Absolute path and restricted dependency lookup; never search PATH/CWD.
        # WinDivert exports C functions (cdecl, significant for 32-bit Python).
        dll = c.CDLL(str(path), use_last_error=True, winmode=0x1100)
    except OSError as error:
        raise OSError("Cannot load %s: %s. Match the DLL architecture to Python "
                      "(x64 for 64-bit Python, x86 for 32-bit)." % (path, error)) from error
    handle, uint, boolean = c.c_void_p, c.c_uint32, c.c_int32
    address = c.POINTER(DivertAddress)
    signatures = {
        "WinDivertOpen": ([c.c_char_p, c.c_int, c.c_int16, c.c_uint64], handle),
        "WinDivertRecv": ([handle, c.c_void_p, uint, c.POINTER(uint), address], boolean),
        "WinDivertSend": ([handle, c.c_void_p, uint, c.POINTER(uint), address], boolean),
        "WinDivertShutdown": ([handle, c.c_int], boolean),
        "WinDivertClose": ([handle], boolean),
        "WinDivertGetParam": ([handle, c.c_int, c.POINTER(c.c_uint64)], boolean),
    }
    try:
        for name, (arguments, result) in signatures.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = arguments, result
    except AttributeError as error:
        raise ValueError("This scanner requires the WinDivert 2.x API") from error
    return dll


def driver_error(operation):
    code = c.get_last_error()
    hint = {2: "Keep the signed WinDivert driver beside WinDivert.dll.",
            5: "Run PowerShell or Command Prompt as Administrator.",
            577: "Windows rejected the driver signature; use an official signed release.",
            1275: "Windows blocked this driver; check the system's driver policy.",
            1753: "Check that the Windows Base Filtering Engine service is running."}.get(code, "")
    return OSError("%s failed (Windows error %d): %s %s" %
                   (operation, code, c.FormatError(code).strip(), hint))


class WinDivertTransport:
    def __init__(self, source, target, directory=None):
        self.dll = load_library(directory)
        self.handle = None
        self.thread = None
        self.stopping = threading.Event()
        self.packets = queue.Queue(maxsize=4096)
        self.error = None
        # Sniff copies preserve normal delivery. Include router ICMP errors and
        # outbound loopback replies (WinDivert has no inbound loopback path).
        expression = ("ip and (inbound or loopback) and ip.DstAddr == %s and "
                      "((tcp and ip.SrcAddr == %s) or icmp)" % (source, target))
        handle = self.dll.WinDivertOpen(expression.encode("ascii"), 0, 0, 1)
        if handle in (None, c.c_void_p(-1).value):
            raise driver_error("WinDivertOpen")
        self.handle = handle
        try:
            major = c.c_uint64()
            if not self.dll.WinDivertGetParam(handle, 3, c.byref(major)):
                raise driver_error("WinDivertGetParam")
            if major.value != 2:
                raise ValueError("This scanner requires WinDivert 2.x")
            self.thread = threading.Thread(target=self._capture, name="scanner-capture", daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def _capture(self):
        buffer = c.create_string_buffer(65535)
        size, address = c.c_uint32(), DivertAddress()
        try:
            while not self.stopping.is_set():
                if not self.dll.WinDivertRecv(self.handle, buffer, len(buffer),
                                              c.byref(size), c.byref(address)):
                    if not self.stopping.is_set():
                        self.error = driver_error("WinDivertRecv")
                    return
                try:
                    self.packets.put_nowait((buffer.raw[:size.value], time.monotonic()))
                except queue.Full:
                    self.error = OSError("Windows capture queue overflow; reduce --parallel or increase --delay")
                    return
        except Exception as error:
            self.error = OSError("Windows capture failed: %s" % error)

    def send(self, packet):
        if self.error is not None:
            raise self.error
        address = DivertAddress()
        # Outbound plus valid IP/TCP/UDP checksums; scanner built them itself.
        # Interface indices are ignored for outbound NETWORK-layer injection.
        address.flags = (1 << 17) | (1 << 21) | (1 << 22) | (1 << 23)
        size = c.c_uint32()
        if not self.dll.WinDivertSend(self.handle, packet, len(packet),
                                      c.byref(size), c.byref(address)):
            raise driver_error("WinDivertSend")
        if size.value != len(packet):
            raise OSError("WinDivertSend injected an incomplete packet")

    def receive(self, timeout):
        if self.error is not None:
            raise self.error
        try:
            rows = [self.packets.get(timeout=timeout)]
        except queue.Empty:
            if self.error is not None:
                raise self.error
            return []
        for _ in range(255):
            try:
                rows.append(self.packets.get_nowait())
            except queue.Empty:
                break
        return rows

    def close(self):
        if self.handle is None:
            return
        self.stopping.set()
        # Shutdown releases a blocking receive even when no reply ever arrives.
        self.dll.WinDivertShutdown(self.handle, 3)
        self.dll.WinDivertClose(self.handle)
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=2)
        self.handle = None
