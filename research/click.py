"""Synthetic mouse click at screen coordinates.

usage: python research\click.py X Y [double]
"""
import ctypes
import sys
import time
from ctypes import wintypes

u32 = ctypes.WinDLL("user32")

MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


def click(x: int, y: int, double: bool = False) -> None:
    u32.SetCursorPos(int(x), int(y))
    time.sleep(0.15)
    n = 2 if double else 1
    for _ in range(n):
        u32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        time.sleep(0.05)
        u32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        time.sleep(0.12)


if __name__ == "__main__":
    x, y = int(sys.argv[1]), int(sys.argv[2])
    dbl = len(sys.argv) > 3 and sys.argv[3] == "double"
    click(x, y, dbl)
    print(f"clicked ({x},{y}){' double' if dbl else ''}")
