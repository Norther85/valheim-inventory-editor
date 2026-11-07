"""Screenshot helper: grab the screen (or one window) and save to PNG.

usage: python research\shot.py out.png [window_title_substring]
"""
import sys
import time

from PIL import ImageGrab


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "shot.png"
    title = sys.argv[2] if len(sys.argv) > 2 else None
    time.sleep(0.4)
    img = ImageGrab.grab()
    if title:
        import ctypes
        from ctypes import wintypes

        u32 = ctypes.WinDLL("user32")
        u32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        u32.FindWindowW.restype = wintypes.HWND
        u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        u32.GetWindowRect.restype = wintypes.BOOL
        u32.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                                       wintypes.LPARAM),
                                    wintypes.LPARAM]
        u32.EnumWindows.restype = wintypes.BOOL
        u32.IsWindowVisible.argtypes = [wintypes.HWND]
        u32.IsWindowVisible.restype = wintypes.BOOL
        u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        u32.GetWindowTextW.restype = ctypes.c_int

        found = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def cb(hwnd, _lp):
            if not u32.IsWindowVisible(hwnd):
                return True
            buf = ctypes.create_unicode_buffer(512)
            u32.GetWindowTextW(hwnd, buf, 512)
            if title.lower() in buf.value.lower():
                found.append(hwnd)
            return True

        u32.EnumWindows(cb, 0)
        if not found:
            print(f"window containing '{title}' not found; saving full screen")
        else:
            r = wintypes.RECT()
            u32.GetWindowRect(found[0], ctypes.byref(r))
            img = img.crop((r.left, r.top, r.right, r.bottom))
            print(f"window '{title}' at ({r.left},{r.top})-({r.right},{r.bottom})")
    img.save(out)
    print(f"saved {out} size={img.size}")


if __name__ == "__main__":
    main()
