"""
NexusHelm Live Win32 USB HID Hardware Bridge (`hid_bridge.py`).

Provides a zero-dependency `ctypes` Win32 SetupAPI / `hid.dll` / `kernel32.dll`
(`CreateFileA`, `WriteFile`, `ReadFile`, `CloseHandle`) hardware bridge for
Sony DualSense (`VID_054C`, `PID_0CE6`) and DualSense Edge (`VID_054C`, `PID_0DF2`)
controllers over USB HID.

When `probe_hardware=True`:
  - Enumerates active HID device interfaces via `SetupDiGetClassDevsA`,
    `SetupDiEnumDeviceInterfaces`, and `SetupDiGetDeviceInterfaceDetailA`.
  - Opens matching `vid_054c&pid_0ce6` or `vid_054c&pid_0df2` device paths via
    `kernel32.CreateFileA`.
  - Transmits the 64-byte USB Output Report `0x02` (`0x21` R2 hard detent /
    `0x26` L2 40 Hz warning pulse / Lightbar RGB) via `kernel32.WriteFile`.
  - Reads 64-byte USB Input Report `0x01` via `kernel32.ReadFile` for physical
    R2 + Cross ratification or Touchpad E-Brake (`G0_EBRAKE_STOP`).
  - Falls back deterministically to the in-memory 64-byte packet verifier when
    headless, disconnected, or running in non-Windows CI environments.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import sys
from typing import Any, Protocol


DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value or -1


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("InterfaceClassGuid", GUID),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_size_t),
    ]


DEFAULT_HID_GUID = GUID(
    0x4D1E55B2,
    0xF16F,
    0x11CF,
    (ctypes.c_uint8 * 8)(0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30),
)


@dataclass(frozen=True)
class HapticTransmissionReceipt:
    """Deterministic receipt for 64-byte DualSense USB HID Report 0x02 transmission."""

    transmitted_to_hardware: bool
    mode: str
    device_path: str | None
    bytes_written: int
    packet_verified_64b: bool
    right_trigger_mode: int
    left_trigger_mode: int
    lightbar_rgb: tuple[int, int, int]


class Win32HidBackend(Protocol):
    """Injectable low-level Win32 HID / SetupAPI / Kernel32 interface for live + mock testing."""

    def enumerate_device_paths(self) -> list[str]: ...
    def open_device(self, device_path: str, read_write: bool = True) -> int | None: ...
    def write_report(self, handle: int, data: bytes) -> int: ...
    def read_report(self, handle: int, length: int = 64) -> bytes | None: ...
    def close_device(self, handle: int) -> None: ...


class CtypesWin32HidBackend:
    """
    Live Win32 `ctypes` implementation backed by `hid.dll`, `setupapi.dll`, and `kernel32.dll`.
    """

    def __init__(self) -> None:
        self._supported = sys.platform == "win32" and hasattr(ctypes, "windll")
        self._hid = getattr(ctypes.windll, "hid", None) if self._supported else None
        self._setupapi = getattr(ctypes.windll, "setupapi", None) if self._supported else None
        self._kernel32 = getattr(ctypes.windll, "kernel32", None) if self._supported else None
        if self._supported and self._setupapi and self._kernel32:
            self._configure_prototypes()

    def _configure_prototypes(self) -> None:
        assert self._setupapi is not None and self._kernel32 is not None
        if self._hid is not None:
            self._hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(GUID)]
            self._hid.HidD_GetHidGuid.restype = None

        self._setupapi.SetupDiGetClassDevsA.argtypes = [
            ctypes.POINTER(GUID),
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._setupapi.SetupDiGetClassDevsA.restype = ctypes.c_void_p

        self._setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(GUID),
            ctypes.c_uint32,
            ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
        ]
        self._setupapi.SetupDiEnumDeviceInterfaces.restype = ctypes.c_int

        self._setupapi.SetupDiGetDeviceInterfaceDetailA.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._setupapi.SetupDiGetDeviceInterfaceDetailA.restype = ctypes.c_int

        self._setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
        self._setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_int

        self._kernel32.CreateFileA.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self._kernel32.CreateFileA.restype = ctypes.c_void_p

        self._kernel32.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._kernel32.WriteFile.restype = ctypes.c_int

        self._kernel32.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._kernel32.ReadFile.restype = ctypes.c_int

        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = ctypes.c_int

    def _get_hid_guid(self) -> GUID:
        guid = GUID(
            DEFAULT_HID_GUID.Data1,
            DEFAULT_HID_GUID.Data2,
            DEFAULT_HID_GUID.Data3,
            DEFAULT_HID_GUID.Data4,
        )
        if self._hid is not None:
            try:
                self._hid.HidD_GetHidGuid(ctypes.byref(guid))
            except Exception:
                pass
        return guid

    def enumerate_device_paths(self) -> list[str]:
        if not (self._supported and self._setupapi):
            return []

        hid_guid = self._get_hid_guid()
        hdevinfo = self._setupapi.SetupDiGetClassDevsA(
            ctypes.byref(hid_guid),
            None,
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
        if hdevinfo is None or hdevinfo == INVALID_HANDLE_VALUE:
            return []

        paths: list[str] = []
        # On 64-bit Windows SetupAPI packs SP_DEVICE_INTERFACE_DETAIL_DATA_A to 8 bytes; on 32-bit x86 it is 5 bytes.
        detail_cb_size = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 5

        try:
            index = 0
            while index < 256:
                if_data = SP_DEVICE_INTERFACE_DATA()
                if_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
                ok = self._setupapi.SetupDiEnumDeviceInterfaces(
                    hdevinfo,
                    None,
                    ctypes.byref(hid_guid),
                    index,
                    ctypes.byref(if_data),
                )
                if not ok:
                    break

                required_size = ctypes.c_uint32(0)
                self._setupapi.SetupDiGetDeviceInterfaceDetailA(
                    hdevinfo,
                    ctypes.byref(if_data),
                    None,
                    0,
                    ctypes.byref(required_size),
                    None,
                )
                if required_size.value >= detail_cb_size:
                    buf = ctypes.create_string_buffer(required_size.value)
                    ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = detail_cb_size
                    if self._setupapi.SetupDiGetDeviceInterfaceDetailA(
                        hdevinfo,
                        ctypes.byref(if_data),
                        buf,
                        required_size.value,
                        None,
                        None,
                    ):
                        raw_path = ctypes.string_at(ctypes.addressof(buf) + 4)
                        path_str = raw_path.decode("ascii", errors="ignore")
                        if path_str:
                            paths.append(path_str)
                index += 1
        finally:
            self._setupapi.SetupDiDestroyDeviceInfoList(hdevinfo)

        return paths

    def open_device(self, device_path: str, read_write: bool = True) -> int | None:
        if not (self._supported and self._kernel32):
            return None
        encoded = device_path.encode("ascii", errors="ignore")
        access_modes = (
            (GENERIC_READ | GENERIC_WRITE, GENERIC_WRITE)
            if read_write
            else (GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE)
        )
        for desired_access in access_modes:
            handle = self._kernel32.CreateFileA(
                encoded,
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle is not None and handle != INVALID_HANDLE_VALUE and handle != 0:
                return int(handle)
        return None

    def write_report(self, handle: int, data: bytes) -> int:
        if not (self._supported and self._kernel32):
            return 0
        buf = ctypes.create_string_buffer(data, len(data))
        written = ctypes.c_uint32(0)
        ok = self._kernel32.WriteFile(
            ctypes.c_void_p(handle),
            buf,
            len(data),
            ctypes.byref(written),
            None,
        )
        return int(written.value) if ok else 0

    def read_report(self, handle: int, length: int = 64) -> bytes | None:
        if not (self._supported and self._kernel32):
            return None
        buf = ctypes.create_string_buffer(length)
        read_bytes = ctypes.c_uint32(0)
        ok = self._kernel32.ReadFile(
            ctypes.c_void_p(handle),
            buf,
            length,
            ctypes.byref(read_bytes),
            None,
        )
        if not ok or read_bytes.value == 0:
            return None
        return bytes(buf.raw[: read_bytes.value])

    def close_device(self, handle: int) -> None:
        if self._supported and self._kernel32 and handle and handle != INVALID_HANDLE_VALUE:
            self._kernel32.CloseHandle(ctypes.c_void_p(handle))


class DualSenseHidBridge:
    """
    High-Assurance DualSense (`VID_054C`, `PID_0CE6` / `0DF2`) USB HID Bridge.
    Automatically transmits 64-byte Output Report `0x02` (`0x21` / `0x26`) to live
    DualSense hardware when `probe_hardware=True`, and deterministically falls back
    to the in-memory 64-byte packet verifier when headless or disconnected.
    """

    DUALSENSE_TOKENS: tuple[str, ...] = (
        "vid_054c&pid_0ce6",  # DualSense Wireless Controller (USB)
        "vid_054c&pid_0df2",  # DualSense Edge Wireless Controller (USB)
    )

    VALID_TRIGGER_MODES: frozenset[int] = frozenset({0x00, 0x05, 0x21, 0x26})

    def __init__(self, backend: Win32HidBackend | None = None) -> None:
        self.backend: Win32HidBackend = backend or CtypesWin32HidBackend()
        self.transmission_history: list[HapticTransmissionReceipt] = []

    @classmethod
    def is_dualsense_device_path(cls, device_path: str | bytes) -> bool:
        text = (
            device_path.decode("ascii", errors="ignore")
            if isinstance(device_path, bytes)
            else str(device_path)
        ).lower()
        return any(token in text for token in cls.DUALSENSE_TOKENS)

    @classmethod
    def verify_packet_in_memory(cls, raw_report_64b: bytes) -> bool:
        """
        Deterministically verifies the 64-byte DualSense USB HID Output Report 0x02
        structure and trigger/lightbar invariants in memory.
        """
        if not isinstance(raw_report_64b, (bytes, bytearray)) or len(raw_report_64b) != 64:
            raise ValueError(
                f"DualSense USB Output Report 0x02 must be exactly 64 bytes, got {len(raw_report_64b) if isinstance(raw_report_64b, (bytes, bytearray)) else type(raw_report_64b)}."
            )
        if raw_report_64b[0] != 0x02:
            raise ValueError(
                f"Invalid DualSense USB Output Report ID: expected 0x02, got 0x{raw_report_64b[0]:02X}."
            )
        if raw_report_64b[1] != 0xFF or raw_report_64b[2] != 0xF7:
            raise ValueError(
                f"Invalid DualSense Output Report feature flags: (0x{raw_report_64b[1]:02X}, 0x{raw_report_64b[2]:02X})."
            )
        r_mode = raw_report_64b[11]
        l_mode = raw_report_64b[22]
        if r_mode not in cls.VALID_TRIGGER_MODES or l_mode not in cls.VALID_TRIGGER_MODES:
            raise ValueError(
                f"Unsupported trigger modes in 64-byte packet: R2=0x{r_mode:02X}, L2=0x{l_mode:02X}."
            )
        # Verify high-blast asymmetric detent invariants when R2=0x21
        if r_mode == 0x21:
            if l_mode != 0x26 or raw_report_64b[23] != 40:
                raise ValueError(
                    "High-blast 0x21 R2 hard detent requires L2=0x26 @ 40 Hz active warning vibration."
                )
        return True

    def discover_dualsense_paths(self) -> list[str]:
        """Enumerates all currently connected DualSense USB HID device interface paths."""
        all_paths = self.backend.enumerate_device_paths()
        return [p for p in all_paths if self.is_dualsense_device_path(p)]

    def transmit_haptic_packet(
        self,
        packet_or_bytes: Any,
        probe_hardware: bool = True,
    ) -> HapticTransmissionReceipt:
        """
        Verifies the 64-byte Report 0x02 packet and, when `probe_hardware=True`,
        attempts live Win32 USB HID transmission to a connected DualSense controller.
        Falls back deterministically to the in-memory 64-byte verifier if disconnected.
        """
        raw_bytes: bytes = (
            packet_or_bytes.raw_report_64b
            if hasattr(packet_or_bytes, "raw_report_64b")
            else bytes(packet_or_bytes)
        )
        verified = self.verify_packet_in_memory(raw_bytes)
        r_mode = raw_bytes[11]
        l_mode = raw_bytes[22]
        rgb = (raw_bytes[45], raw_bytes[46], raw_bytes[47])

        if probe_hardware:
            for dev_path in self.discover_dualsense_paths():
                handle = self.backend.open_device(dev_path, read_write=False)
                if handle is not None:
                    try:
                        written = self.backend.write_report(handle, raw_bytes)
                        if written == 64:
                            receipt = HapticTransmissionReceipt(
                                transmitted_to_hardware=True,
                                mode="win32_hid_live",
                                device_path=dev_path,
                                bytes_written=written,
                                packet_verified_64b=verified,
                                right_trigger_mode=r_mode,
                                left_trigger_mode=l_mode,
                                lightbar_rgb=rgb,
                            )
                            self.transmission_history.append(receipt)
                            return receipt
                    finally:
                        self.backend.close_device(handle)

        fallback_receipt = HapticTransmissionReceipt(
            transmitted_to_hardware=False,
            mode="in_memory_fallback",
            device_path=None,
            bytes_written=64,
            packet_verified_64b=verified,
            right_trigger_mode=r_mode,
            left_trigger_mode=l_mode,
            lightbar_rgb=rgb,
        )
        self.transmission_history.append(fallback_receipt)
        return fallback_receipt

    def read_input_report_0x01(
        self,
        probe_hardware: bool = True,
        fallback_report_64b: bytes | None = None,
    ) -> tuple[bytes, str]:
        """
        Reads a 64-byte USB Input Report `0x01` from a live DualSense controller via
        `kernel32.ReadFile` when connected, or returns the deterministic fallback report.
        """
        if probe_hardware:
            for dev_path in self.discover_dualsense_paths():
                handle = self.backend.open_device(dev_path, read_write=True)
                if handle is not None:
                    try:
                        report = self.backend.read_report(handle, 64)
                        if report is not None and len(report) == 64 and report[0] == 0x01:
                            return report, "win32_hid_live"
                    finally:
                        self.backend.close_device(handle)

        if fallback_report_64b is not None:
            if len(fallback_report_64b) != 64 or fallback_report_64b[0] != 0x01:
                raise ValueError("fallback_report_64b must be a 64-byte Input Report 0x01.")
            return bytes(fallback_report_64b), "in_memory_fallback"

        default_report = bytearray(64)
        default_report[0] = 0x01
        return bytes(default_report), "in_memory_fallback"
