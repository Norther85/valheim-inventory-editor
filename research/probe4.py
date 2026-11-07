"""Probe4: find the Inventory object (m_width/m_height/m_name), identify which
array is the PLAYER inventory, and locate m_maxStack by diffing SharedData
across items with different known maxima (eitr 30 / roundlog 50 / arrow 100).
"""
import sys

sys.path.insert(0, r"C:\Users\tomek\repos\valheim-cheat")

from app.memory import ProcessMemory, find_processes
from app.discovery import read_mono_string, ANCHOR_NAME

STACK_OFF = 0x38
DUR_OFF = 0x3C
GRID_OFF = 0x58


def item_name(mem, ib):
    shared = mem.read_u64(ib + 0x10)
    if not shared:
        return None
    sb = mem.read_u64(shared + 0x10)
    return read_mono_string(mem, sb) if sb else None


def dump(mem, addr, size, label=""):
    print(f"  -- dump 0x{addr:X} {label}")
    win = mem.read(addr, size)
    if not win:
        print("   unreadable")
        return
    for o in range(0, size, 8):
        q = int.from_bytes(win[o:o + 8], "little")
        i0 = int.from_bytes(win[o:o + 4], "little", signed=True)
        i1 = int.from_bytes(win[o + 4:o + 8], "little", signed=True)
        f0 = __import__("struct").unpack_from("<f", win, o)[0]
        s = read_mono_string(mem, q) if (q and q & 7 == 0) else None
        extra = f"  str='{s}'" if s else ""
        print(f"    0x{addr + o:X}  {q:016X}  i32[{i0},{i1}] f32[{f0:.4g}]{extra}")


def main() -> None:
    pid = find_processes("valheim.exe")[0]
    print(f"valheim pid={pid} (0x{pid:X})")
    mem = ProcessMemory(pid)
    regions = mem.scannable_regions(private_only=True)

    # quick anchor re-derivation
    bases = set()
    for h in mem.find_pattern(ANCHOR_NAME.encode("utf-16-le"), regions, stride=4):
        for sb in (h - 0x14, h - 0x0C):
            if read_mono_string(mem, sb) == ANCHOR_NAME:
                bases.add(sb)
                break
    name_hits = mem.find_u64_values(bases, regions)
    shared_cands = {nf - 0x10 for nf, _ in name_hits}
    shared_hits = mem.find_u64_values(shared_cands, regions)
    fire_items = set()
    shared_of = {}
    for sf, sval in shared_hits:
        ib = sf - 0x10
        if item_name(mem, ib) == ANCHOR_NAME and mem.read_i32(ib + STACK_OFF) == 100:
            fire_items.add(ib)
            shared_of[ib] = sval
    print(f"fire-arrow anchor items (stack=100): {len(fire_items)}")

    ptr_hits = mem.find_u64_values(fire_items, regions)
    addrs = sorted(a for a, _ in ptr_hits)
    # runs of strictly +8
    runs = []
    cur = [addrs[0]] if addrs else []
    for a in addrs[1:]:
        if a == cur[-1] + 8:
            cur.append(a)
        else:
            runs.append(cur)
            cur = [a]
    if cur:
        runs.append(cur)
    runs = [r for r in runs if len(r) >= 20]
    print(f"contiguous runs >= 20 refs: {[(hex(r[0]), len(r)) for r in runs]}")

    # for each run: find array base (first_elem - hdr) and max_length
    for run in runs:
        first = run[0]
        print(f"\n=== run @ 0x{first:X} ({len(run)} elems) ===")
        dump(mem, first - 0x30, 0x30, "before first elem")
        # guess array base candidates: first - 0x18 / -0x20 / -0x28
        for hdr in (0x18, 0x20, 0x28, 0x30):
            ab = first - hdr
            ml = mem.read_u64(ab + 0x10)
            ml2 = mem.read_u64(ab + 0x18)
            print(f"   array_base guess 0x{ab:X} (hdr {hdr:#x}): +0x10={ml} +0x18={ml2}")

    # search pointers to array bases -> List._items
    print("\n== List objects ==")
    arr_bases = set()
    for run in runs:
        for hdr in (0x18, 0x20, 0x28, 0x30):
            arr_bases.add(run[0] - hdr)
    list_hits = mem.find_u64_values(arr_bases, regions)
    print(f"pointers to array-base candidates: {len(list_hits)}")
    for lh, lv in sorted(list_hits):
        print(f"  List._items? @ 0x{lh:X} -> array 0x{lv:X}")
        dump(mem, lh - 0x10, 0x40, "List object around _items field")

    # search pointers to List bases -> Inventory.m_inventory
    print("\n== Inventory objects ==")
    list_bases = {lh - 0x10 for lh, _ in list_hits}
    inv_hits = mem.find_u64_values(list_bases, regions)
    print(f"pointers to List bases: {len(inv_hits)}")
    for ih, iv in sorted(inv_hits):
        print(f"  Inventory.m_inventory? @ 0x{ih:X} -> List 0x{iv:X}")
        dump(mem, ih - 0x20, 0x60, "Inventory object around m_inventory")

    # SharedData diff for max stack
    print("\n== SharedData diffs (max stack hunt) ==")
    samples = {}
    for ib in fire_items:
        samples.setdefault("arrow", ib)
    # find other item types via the run elements
    for run in runs[:1]:
        for a in run:
            p = mem.read_u64(a)
            nm = item_name(mem, p) if p else None
            if nm and nm not in ("$item_arrow_fire",) and nm not in samples:
                samples[nm] = p
    for nm, ib in samples.items():
        shared = mem.read_u64(ib + 0x10)
        st = mem.read_i32(ib + STACK_OFF)
        print(f"\n [{nm}] stack={st} shared=0x{shared:X}")
        win = mem.read(shared, 0x160)
        if win:
            for o in range(0, 0x160, 4):
                v = int.from_bytes(win[o:o + 4], "little", signed=True)
                if v in (1, 5, 10, 20, 30, 50, 100, 200, 500, 999, 1000, 9999):
                    print(f"    +0x{o:02X} = {v}")

    # item raw windows: arrow vs bow-like (durability items)
    print("\n== ItemData raw (arrow) ==")
    ib = next(iter(fire_items))
    dump(mem, ib, 0x80, "fire arrow ItemData")
    for nm, ib2 in samples.items():
        if nm != "arrow":
            print(f"\n== ItemData raw ({nm}) ==")
            dump(mem, ib2, 0x80, nm)

    mem.close()


if __name__ == "__main__":
    main()
