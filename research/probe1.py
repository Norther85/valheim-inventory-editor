"""Step-by-step probe of the live valheim memory chain (read-only).

Walks: '$item_arrow_fire' string -> name ptr -> SharedData -> ItemData,
validating candidates with the stack==100 pattern (the anchor the user
places in the inventory).
"""
import sys
from collections import Counter

sys.path.insert(0, r"C:\Users\tomek\repos\valheim-cheat")

from app.memory import ProcessMemory, find_processes
from app.discovery import read_mono_string, ANCHOR_NAME


def main() -> None:
    pids = find_processes("valheim.exe")
    if not pids:
        print("valheim.exe not running")
        return
    pid = pids[0]
    print(f"valheim pid={pid} (0x{pid:X})")
    mem = ProcessMemory(pid)
    regions = mem.scannable_regions(private_only=True)
    print(f"scannable regions: {len(regions)}")

    pat = ANCHOR_NAME.encode("utf-16-le")
    raw_hits = mem.find_pattern(pat, regions, stride=4)
    print(f"\n== raw utf16 pattern hits: {len(raw_hits)}")
    bases = []
    for h in raw_hits:
        for sb in (h - 0x14, h - 0x0C):
            s = read_mono_string(mem, sb)
            if s == ANCHOR_NAME:
                bases.append(sb)
                break
    bases = sorted(set(bases))
    print(f"validated string bases: {len(bases)}")
    for b in bases[:8]:
        print(f"  str @ 0x{b:X}")

    ptr_hits = mem.find_u64_values(set(bases), regions)
    print(f"\n== pointers to string bases: {len(ptr_hits)}")
    for a, v in ptr_hits[:12]:
        print(f"  ptr @ 0x{a:X} -> 0x{v:X}")

    # candidate SharedData bases = name-field - name_off
    print("\n== SharedData candidates (base = namefield - off, vtable check)")
    shared_by_off: dict[int, list[int]] = {}
    for name_off in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        lst = []
        for nf, sv in ptr_hits:
            b = nf - name_off
            if b & 7:
                continue
            vt = mem.read_u64(b)
            if vt and mem.is_image(vt):
                lst.append(b)
        shared_by_off[name_off] = sorted(set(lst))
        print(f"  name_off=+0x{name_off:X}: {len(lst)} candidates with image vtable")

    # for each candidate shared base, find pointers to it, look for stack==100 nearby
    print("\n== ItemData search: pointers to SharedData with stack==100 nearby")
    for name_off, shared_bases in shared_by_off.items():
        if not shared_bases:
            continue
        hits = mem.find_u64_values(set(shared_bases), regions)
        print(f"\n-- name_off=+0x{name_off:X}: {len(hits)} ptrs to {len(shared_bases)} shared bases")
        offs = Counter()
        samples = []
        for sf, sval in hits:
            win = mem.read(sf - 0x40, 0x80)
            if not win:
                continue
            for o in range(0, 0x80 - 4, 4):
                val = int.from_bytes(win[o:o + 4], "little", signed=True)
                if val == 100:
                    # offset of stack field relative to shared-field (sf)
                    rel = o - 0x40
                    offs[rel] += 1
                    if len(samples) < 6:
                        samples.append((sf, sval, rel))
        if offs:
            print(f"   stack==100 relative to shared-field: {offs.most_common(6)}")
            for sf, sval, rel in samples:
                print(f"     shared_field@0x{sf:X} shared=0x{sval:X} stack_rel={rel:+#x} "
                      f"-> itembase=0x{sf - (rel - 0x18 if rel > 0 else 0):X}")

    # brute-force: what does an item object look like around one shared ptr?
    print("\n== window dump around first shared-ptr hit (if any)")
    for name_off in (0x10, 0x18):
        shared_bases = shared_by_off.get(name_off) or []
        if not shared_bases:
            continue
        hits = mem.find_u64_values(set(shared_bases), regions)
        if not hits:
            continue
        sf, sval = hits[0]
        print(f"  name_off=+0x{name_off:X} shared_field@0x{sf:X} shared_base=0x{sval:X}")
        win = mem.read(sf - 0x60, 0x100)
        if win:
            for o in range(0, 0x100, 8):
                a = sf - 0x60 + o
                q = int.from_bytes(win[o:o + 8], "little")
                i0 = int.from_bytes(win[o:o + 4], "little", signed=True)
                i1 = int.from_bytes(win[o + 4:o + 8], "little", signed=True)
                tag = ""
                if q and mem.is_image(q):
                    tag = " img"
                elif q and mem.is_heap(q):
                    tag = " heap"
                mark = " <== shared field" if a == sf else ""
                print(f"    0x{a:X}  {q:016X}  i32[{i0},{i1}]{tag}{mark}")
        # also dump the shared object itself
        print(f"  shared object window @ 0x{sval:X}:")
        win = mem.read(sval, 0x80)
        if win:
            for o in range(0, 0x80, 8):
                q = int.from_bytes(win[o:o + 8], "little")
                s = read_mono_string(mem, q) if (q and q & 7 == 0) else None
                extra = f"  str='{s}'" if s else ""
                i0 = int.from_bytes(win[o:o + 4], "little", signed=True)
                i1 = int.from_bytes(win[o + 4:o + 8], "little", signed=True)
                print(f"    +0x{o:02X}  {q:016X}  i32[{i0},{i1}]{extra}")
        break

    mem.close()


if __name__ == "__main__":
    main()
