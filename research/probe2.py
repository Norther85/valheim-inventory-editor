"""Probe2: drop the vtable assumption; use stack==100 as the validator.

For each name-field pointer F (*F == '$item_arrow_fire' string):
  - dump the words before F to see the real object header
  - candidate SharedData bases at F - off (off = 0x10..0x38)
  - search pointers to those bases (ItemData.m_shared fields)
  - around each hit look for int32 == 100 at a *consistent* relative offset
"""
import sys
from collections import Counter, defaultdict

sys.path.insert(0, r"C:\Users\tomek\repos\valheim-cheat")

from app.memory import ProcessMemory, find_processes
from app.discovery import read_mono_string, ANCHOR_NAME


def tag(mem: ProcessMemory, q: int) -> str:
    if q == 0:
        return ""
    if mem.is_image(q):
        return " img"
    if mem.is_heap(q):
        return " heap"
    return " ??"


def main() -> None:
    pid = find_processes("valheim.exe")[0]
    print(f"valheim pid={pid} (0x{pid:X})")
    mem = ProcessMemory(pid)
    regions = mem.scannable_regions(private_only=True)

    pat = ANCHOR_NAME.encode("utf-16-le")
    bases = set()
    for h in mem.find_pattern(pat, regions, stride=4):
        for sb in (h - 0x14, h - 0x0C):
            if read_mono_string(mem, sb) == ANCHOR_NAME:
                bases.add(sb)
                break
    print(f"string bases: {len(bases)}")

    ptr_hits = mem.find_u64_values(set(bases), regions)
    print(f"name-field pointers: {len(ptr_hits)}")

    # 1) show object headers before name fields
    print("\n== words before name field (first 6 hits) ==")
    for nf, sv in sorted(ptr_hits)[:6]:
        win = mem.read(nf - 0x30, 0x38)
        if not win:
            continue
        print(f" name_field @ 0x{nf:X} -> str 0x{sv:X}")
        for o in range(0, 0x30, 8):
            q = int.from_bytes(win[o:o + 8], "little")
            mark = " <== name field" if nf - 0x30 + o == nf else ""
            print(f"    0x{nf - 0x30 + o:X}  {q:016X}{tag(mem, q)}{mark}")

    # also show a string object header
    sb = sorted(bases)[0]
    win = mem.read(sb, 0x30)
    print(f"\n== string object @ 0x{sb:X} ==")
    if win:
        for o in range(0, 0x30, 8):
            q = int.from_bytes(win[o:o + 8], "little")
            print(f"    +0x{o:02X}  {q:016X}{tag(mem, q)}")

    # 2) candidate shared bases without vtable filter
    cand_by_off: dict[int, set[int]] = defaultdict(set)
    for nf, sv in ptr_hits:
        for off in range(0x10, 0x40, 8):
            cand_by_off[off].add(nf - off)
    print("\n== pointer search to candidate SharedData bases ==")
    hits_by_off: dict[int, list] = {}
    for off, cands in sorted(cand_by_off.items()):
        hits = mem.find_u64_values(cands, regions)
        hits_by_off[off] = hits
        print(f"  name_off=+0x{off:X}: {len(cands)} candidates -> {len(hits)} ptr hits")

    # 3) around each ptr hit, find stack==100 relative offsets
    print("\n== stack==100 pattern near candidate m_shared fields ==")
    for off, hits in hits_by_off.items():
        rel_votes: Counter[int] = Counter()
        for sf, sval in hits:
            win = mem.read(sf - 0x40, 0x90)
            if not win:
                continue
            for o in range(0, 0x8C, 4):
                v = int.from_bytes(win[o:o + 4], "little", signed=True)
                if v == 100:
                    rel_votes[o - 0x40] += 1
        if rel_votes:
            print(f"  name_off=+0x{off:X}: rel offsets of 100 -> {rel_votes.most_common(8)}")

    # 4) full dump around the best (name_off, rel) combo
    best = None
    for off, hits in hits_by_off.items():
        rel_votes: Counter[int] = Counter()
        for sf, sval in hits:
            win = mem.read(sf - 0x40, 0x90)
            if not win:
                continue
            for o in range(0, 0x8C, 4):
                v = int.from_bytes(win[o:o + 4], "little", signed=True)
                if v == 100:
                    rel_votes[o - 0x40] += 1
        if rel_votes:
            rel, n = rel_votes.most_common(1)[0]
            if best is None or n > best[2]:
                best = (off, rel, n, hits)
    if best:
        off, rel, n, hits = best
        print(f"\n== BEST: name_off=+0x{off:X} stack_rel={rel:+#x} votes={n} ==")
        sf, sval = hits[0]
        # find a hit that actually has 100 at rel
        for sf, sval in hits:
            win = mem.read(sf - 0x40, 0x90)
            if not win:
                continue
            v = int.from_bytes(win[rel + 0x40:rel + 0x44], "little", signed=True)
            if v == 100:
                break
        print(f" sample m_shared field @ 0x{sf:X} (shared base 0x{sval:X})")
        base = sf - 0x40
        win = mem.read(base, 0x90)
        if win:
            for o in range(0, 0x90, 8):
                q = int.from_bytes(win[o:o + 8], "little")
                i0 = int.from_bytes(win[o:o + 4], "little", signed=True)
                i1 = int.from_bytes(win[o + 4:o + 8], "little", signed=True)
                s = read_mono_string(mem, q) if (q and q & 7 == 0) else None
                extra = f"  str='{s}'" if s else ""
                mark = ""
                if base + o == sf:
                    mark = " <== m_shared field"
                if base + o == sf + rel:
                    mark += " <== stack 100"
                print(f"    0x{base + o:X}  {q:016X}  i32[{i0},{i1}]{tag(mem, q)}{mark}{extra}")
        print(f" shared object @ 0x{sval:X}:")
        win = mem.read(sval, 0x60)
        if win:
            for o in range(0, 0x60, 8):
                q = int.from_bytes(win[o:o + 8], "little")
                s = read_mono_string(mem, q) if (q and q & 7 == 0) else None
                extra = f"  str='{s}'" if s else ""
                print(f"    +0x{o:02X}  {q:016X}{tag(mem, q)}{extra}")

    mem.close()


if __name__ == "__main__":
    main()
