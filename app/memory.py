"""Low-level Windows process memory access (ctypes).

Read/write only - no injection, no hooks. Used against the local, single-player
valheim.exe process the user owns.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass
from typing import Iterator

import numpy as np

if sys.platform != "win32":
    raise RuntimeError("Windows only")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
_READABLE_PROTS = frozenset({0x02, 0x04, 0x08, 0x20, 0x40, 0x80})

TH32CS_SNAPPROCESS = 0x2


class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("_pad", wintypes.WORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("_pad2", wintypes.DWORD),
    ]


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_uint64),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_k32.ReadProcessMemory.restype = wintypes.BOOL
_k32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_k32.WriteProcessMemory.restype = wintypes.BOOL
_k32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(_MBI), ctypes.c_size_t,
]
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_k32.Process32FirstW.restype = wintypes.BOOL
_k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_k32.Process32NextW.restype = wintypes.BOOL


def find_processes(name: str) -> list[int]:
    """PIDs of running processes whose image name matches (case-insensitive)."""
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1, wintypes.HANDLE(-1).value):
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    want = name.lower()
    pids: list[int] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = _k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == want:
                pids.append(int(entry.th32ProcessID))
            ok = _k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _k32.CloseHandle(snap)
    return pids


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    type: int
    protect: int

    @property
    def end(self) -> int:
        return self.base + self.size


class ProcessMemory:
    """Handle to a process' address space: regions, bulk scan, typed read/write."""

    def __init__(self, pid: int):
        self.pid = pid
        access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
        self._h = _k32.OpenProcess(access, False, pid)
        if not self._h:
            raise OSError(ctypes.get_last_error(), f"OpenProcess({pid}) failed - run as admin?")
        self._regions: list[Region] | None = None

    # ---------- lifetime ----------
    def close(self) -> None:
        if self._h:
            _k32.CloseHandle(self._h)
            self._h = None

    def __enter__(self) -> "ProcessMemory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- regions ----------
    def regions(self) -> list[Region]:
        if self._regions is None:
            out: list[Region] = []
            addr = 0
            mbi = _MBI()
            size = ctypes.sizeof(_MBI)
            while addr < 0x00007FFF_FFFF_FFFF:
                r = _k32.VirtualQueryEx(self._h, ctypes.c_void_p(addr), ctypes.byref(mbi), size)
                if not r:
                    break
                base = int(mbi.BaseAddress)
                rsize = int(mbi.RegionSize)
                out.append(Region(base, rsize, int(mbi.Type), int(mbi.Protect)))
                if rsize == 0 or base + rsize <= addr:
                    break
                addr = base + rsize
            self._regions = out
        return self._regions

    def scannable_regions(self, *, private_only: bool = True) -> list[Region]:
        """Committed, readable, non-guard regions (optionally private heap only)."""
        out = []
        for r in self.regions():
            if (r.protect & PAGE_GUARD) or (r.protect & 0xFF) == PAGE_NOACCESS:
                continue
            if (r.protect & 0xFF) not in _READABLE_PROTS:
                continue
            if private_only and r.type != MEM_PRIVATE:
                continue
            out.append(r)
        return out

    def classify(self, addr: int) -> str | None:
        """'image', 'heap' (private/mapped readable) or None for an address."""
        for r in self.regions():
            if r.base <= addr < r.end:
                if r.type == MEM_IMAGE:
                    return "image"
                if r.type in (MEM_PRIVATE, MEM_MAPPED):
                    return "heap"
                return "other"
        return None

    def is_image(self, addr: int) -> bool:
        return self.classify(addr) == "image"

    def is_heap(self, addr: int) -> bool:
        return self.classify(addr) == "heap"

    # ---------- raw read / write ----------
    def read(self, addr: int, size: int) -> bytes | None:
        if size <= 0:
            return b""
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(self._h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
        if not ok or got.value != size:
            return None
        return bytes(buf)

    def read_u32(self, addr: int) -> int | None:
        b = self.read(addr, 4)
        return int.from_bytes(b, "little") if b else None

    def read_i32(self, addr: int) -> int | None:
        b = self.read(addr, 4)
        return int.from_bytes(b, "little", signed=True) if b else None

    def read_u64(self, addr: int) -> int | None:
        b = self.read(addr, 8)
        return int.from_bytes(b, "little") if b else None

    def read_f32(self, addr: int) -> float | None:
        b = self.read(addr, 4)
        return float(np.frombuffer(b, dtype="<f4")[0]) if b else None

    def write(self, addr: int, data: bytes) -> bool:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        got = ctypes.c_size_t(0)
        return bool(_k32.WriteProcessMemory(
            self._h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(got)))

    def write_u32(self, addr: int, value: int) -> bool:
        return self.write(addr, int(value & 0xFFFFFFFF).to_bytes(4, "little"))

    def write_f32(self, addr: int, value: float) -> bool:
        return self.write(addr, np.float32(value).tobytes())

    # ---------- bulk scanning ----------
    def iter_chunks(self, regions: list[Region], chunk: int = 1 << 20) -> Iterator[tuple[int, np.ndarray]]:
        """Yield (addr, uint64 view) per chunk. Chunk size is a multiple of 8 and
        region bases are 64K aligned, so 8-byte values never straddle chunks."""
        for r in regions:
            pos, end = r.base, r.end
            while pos < end:
                want = min(chunk, end - pos) & ~7
                if want == 0:
                    break
                data = self.read(pos, want)
                if data is not None and len(data) == want:
                    yield pos, np.frombuffer(data, dtype="<u8")
                pos += want

    def find_u64_values(self, targets: set[int], regions: list[Region]) -> list[tuple[int, int]]:
        """All 8-aligned addresses holding one of the target qwords -> [(addr, value)]."""
        if not targets:
            return []
        tarr = np.array(sorted(targets), dtype="<u8")
        hits: list[tuple[int, int]] = []
        for base, arr in self.iter_chunks(regions):
            idx = np.searchsorted(tarr, arr)
            idx_c = np.clip(idx, 0, len(tarr) - 1)
            mask = tarr[idx_c] == arr
            for i in np.nonzero(mask)[0]:
                hits.append((base + int(i) * 8, int(arr[i])))
        return hits

    def find_pattern(self, pattern: bytes, regions: list[Region],
                     stride: int = 1) -> list[int]:
        """Addresses where a byte pattern occurs (optionally stride-aligned)."""
        hits: list[int] = []
        plen = len(pattern)
        for r in regions:
            pos, end = r.base, r.end
            while pos < end:
                want = min(1 << 20, end - pos)
                data = self.read(pos, want)
                if not data:
                    pos += want
                    continue
                start = 0
                while True:
                    i = data.find(pattern, start)
                    if i < 0:
                        break
                    if (pos + i) % stride == 0:
                        hits.append(pos + i)
                    start = i + 1
                pos += want
        return hits

    def find_i32_values(self, value: int, regions: list[Region]) -> list[int]:
        """4-byte-aligned addresses holding a given int32 (tiny false-positive
        window at chunk tails is ignored by design - chunk sizes are 8-aligned
        and the final <4 bytes of a region are not game state we rely on)."""
        pat = int(value & 0xFFFFFFFF).to_bytes(4, "little")
        return self.find_pattern(pat, regions, stride=4)
