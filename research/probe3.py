"""Probe3: map the inventory array, grid positions, durability and max-stack.

Chain (validated in probe2):
  Mono string '$item_arrow_fire'  (len @ +0x10, chars @ +0x14)
  SharedData.m_name @ +0x10   (object base = name_field - 0x10)
  ItemData.m_shared  @ +0x10  (object base = shared_field - 0x10)
  ItemData.m_stack   @ +0x38  (int32)   m_durability @ +0x3C (float)

Now: find List<ItemData>._items arrays via pointers to fire-arrow ItemData,
dump every element generically, vote m_gridPos, find Inventory w/h, max stack.
"""
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\tomek\repos\valheim-cheat")

from app.memory import ProcessMemory, find_processes
from app.discovery import read_mono_string, ANCHOR_NAME

STACK_OFF = 0x38
DUR_OFF = 0x3C


def item_name(mem, ib):
    shared = mem.read_u64(ib + 0x10)
    if not shared:
        return None
    sb = mem.read_u64(shared + 0x10)
    return read_mono_string(mem, sb) if sb else None


def looks_like_item(mem, p):
    if not p or p & 7:
        return False
    if not mem.is_heap(p):
        return False
    shared = mem.read_u64(p + 0x10)
    if not shared or not mem.is_heap(shared):
        return False
    sb = mem.read_u64(shared + 0x10)
    return bool(sb and read_mono_string(mem, sb))


def main() -> None:
    pid = find_processes("valheim.exe")[0]
    print(f"valheim pid={pid} (0x{pid:X})")
    mem = ProcessMemory(pid)
    regions = mem.scannable_regions(private_only=True)

    # -- string -> name fields -> shared candidates -> ItemData bases ------
    bases = set()
    for h in mem.find_pattern(ANCHOR_NAME.encode("utf-16-le"), regions, stride=4):
        for sb in (h - 0x14, h - 0x0C):
            if read_mono_string(mem, sb) == ANCHOR_NAME:
                bases.add(sb)
                break
    name_hits = mem.find_u64_values(bases, regions)
    shared_cands = {nf - 0x10 for nf, _ in name_hits}
    shared_hits = mem.find_u64_values(shared_cands, regions)
    print(f"strings={len(bases)} name_fields={len(name_hits)} shared_ptrs={len(shared_hits)}")

    fire_items = []
    for sf, sval in shared_hits:
        ib = sf - 0x10
        if item_name(mem, ib) == ANCHOR_NAME:
            st = mem.read_i32(ib + STACK_OFF)
            fire_items.append((ib, st))
    print(f"fire-arrow ItemData objects: {len(fire_items)}")
    for ib, st in fire_items[:10]:
        print(f"  0x{ib:X} stack={st}")

    # -- pointers to those ItemData -> arrays -----------------------------
    item_bases = {ib for ib, st in fire_items}
    ptr_hits = mem.find_u64_values(item_bases, regions)
    print(f"\npointers to fire-arrow ItemData: {len(ptr_hits)}")
    addrs = sorted(a for a, _ in ptr_hits)

    # cluster: consecutive 8-aligned ptr addresses
    clusters = []
    cur = []
    for a in addrs:
        if cur and a - cur[-1] <= 8:
            cur.append(a)
        else:
            if cur:
                clusters.append(cur)
            cur = [a]
    if cur:
        clusters.append(cur)
    print(f"clusters of adjacent pointers: {len(clusters)}")

    for cl in sorted(clusters, key=len, reverse=True)[:4]:
        first, last = cl[0], cl[-1]
        print(f"\n--- cluster @ 0x{first:X}..0x{last:X} ({len(cl)} refs) ---")
        # widen: read a window and collect all item-like pointers
        span_lo = first - 0x200
        win = mem.read(span_lo, (last - span_lo) + 0x200 + 8)
        if not win:
            print("  unreadable")
            continue
        elems = []
        for o in range(0, len(win) - 7, 8):
            p = int.from_bytes(win[o:o + 8], "little")
            if p and p & 7 == 0 and mem.is_heap(p) and looks_like_item(mem, p):
                elems.append((span_lo + o, p))
        print(f"  item-like ptrs in window: {len(elems)}")
        # find array/list header before the first element
        arr0 = elems[0][0] if elems else first
        hdr = mem.read(arr0 - 0x30, 0x30)
        if hdr:
            for o in range(0, 0x30, 8):
                q = int.from_bytes(hdr[o:o + 8], "little")
                i0 = int.from_bytes(hdr[o:o + 4], "little", signed=True)
                i1 = int.from_bytes(hdr[o + 4:o + 8], "little", signed=True)
                print(f"    hdr 0x{arr0 - 0x30 + o:X}  {q:016X}  i32[{i0},{i1}]")
        for a, p in elems:
            nm = item_name(mem, p) or "?"
            st = mem.read_i32(p + STACK_OFF)
            du = mem.read_f32(p + DUR_OFF)
            # gridPos candidates: 2 int32 in range, dump a few fields
            flds = []
            for off in (0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70):
                b = mem.read(p + off, 8)
                if b:
                    x = int.from_bytes(b[:4], "little", signed=True)
                    y = int.from_bytes(b[4:], "little", signed=True)
                    flds.append(f"+0x{off:X}=({x},{y})")
            print(f"    @0x{a:X} -> item 0x{p:X} '{nm}' stack={st} dur={du} " + " ".join(flds))

    # -- gridPos voting across the biggest cluster -----------------------
    print("\n== m_gridPos voting (unique pairs in 0..7 x 0..5) ==")
    best_cl = max(clusters, key=len) if clusters else []
    if best_cl:
        span_lo = best_cl[0] - 0x200
        win = mem.read(span_lo, (best_cl[-1] - span_lo) + 0x200 + 8)
        elems = []
        if win:
            for o in range(0, len(win) - 7, 8):
                p = int.from_bytes(win[o:o + 8], "little")
                if p and p & 7 == 0 and mem.is_heap(p) and looks_like_item(mem, p):
                    elems.append(p)
        elems = sorted(set(elems))
        print(f"items in best cluster: {len(elems)}")
        for off in range(0x40, 0x84, 4):
            pairs = []
            ok = True
            for p in elems:
                b = mem.read(p + off, 8)
                if not b:
                    ok = False
                    break
                x = int.from_bytes(b[:4], "little", signed=True)
                y = int.from_bytes(b[4:], "little", signed=True)
                if not (0 <= x < 8 and 0 <= y < 6):
                    ok = False
                    break
                pairs.append((x, y))
            if ok and len(set(pairs)) == len(pairs):
                print(f"  +0x{off:X}: ALL valid & unique -> {pairs}")

    # -- SharedData wide dump for max-stack ------------------------------
    print("\n== SharedData dump (fire arrow) for m_maxStack ==")
    if fire_items:
        ib = fire_items[0][0]
        shared = mem.read_u64(ib + 0x10)
        win = mem.read(shared, 0xC0)
        if win:
            for o in range(0, 0xC0, 8):
                q = int.from_bytes(win[o:o + 8], "little")
                i0 = int.from_bytes(win[o:o + 4], "little", signed=True)
                i1 = int.from_bytes(win[o + 4:o + 8], "little", signed=True)
                s = read_mono_string(mem, q) if (q and q & 7 == 0) else None
                extra = f"  str='{s}'" if s else ""
                print(f"    +0x{o:02X}  {q:016X}  i32[{i0},{i1}]{extra}")

    mem.close()


if __name__ == "__main__":
    main()
