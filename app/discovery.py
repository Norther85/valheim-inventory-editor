"""Live discovery of Valheim's inventory layout inside a running game.

Nothing is hardcoded to an address: heap addresses change every launch
(that is why the two rows in adressess.txt differ), so the whole chain is
re-derived on every attach and validated by the user's anchor pattern
(100 fire arrows, quantity 100, in the player inventory).

Chain (confirmed live against valheim.exe):
  Mono string '$item_arrow_fire'      len @ +0x10, chars @ +0x14
  SharedData.m_name      @ +0x10      (object base = name_field - 0x10)
  ItemData.m_shared      @ +0x10      (object base = shared_field - 0x10)
  ItemData.m_stack       @ +0x38      int32
  ItemData.m_durability  @ +0x3C      float
  ItemData.m_gridPos     @ +0x58      2x int32 (x = column 0..7, y = row 0..5)
  SharedData.m_maxStack  @ +0x138     int32 (validated per attach, may be absent)

Mono note: vtables are heap-allocated (MonoVTable), NOT image pointers,
so object validation is done through the name chain instead.

Run `python -m app.discovery` for a live dump (auto-finds valheim.exe).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .memory import ProcessMemory, find_processes

ANCHOR_NAME = "$item_arrow_fire"
ANCHOR_STACK = 100

# offsets confirmed live (validated again on every attach)
NAME_OFF = 0x10        # in SharedData
SHARED_OFF = 0x10      # in ItemData
STACK_OFF = 0x38       # in ItemData (int32)
DUR_OFF = 0x3C         # in ItemData (float)
GRID_OFF = 0x58        # in ItemData (2x int32)
MAX_OFF_CANDIDATES = (0x138, 0x130, 0x13C, 0x140, 0x148, 0x128, 0x120)
MAX_STACK_VALUES = (1, 5, 10, 20, 30, 50, 100, 200, 500, 999, 1000, 9999)

_STRING_LAYOUTS = ((0x10, 0x14), (0x08, 0x0C))


class DiscoveryError(RuntimeError):
    pass


# ---------------------------------------------------------------- anchors

def _norm_name(s: str) -> str:
    """'  $item_Arrow Bloodgold ' -> 'arrowbloodgold' (fuzzy compare)."""
    s = s.strip().lower()
    if s.startswith("$item_"):
        s = s[6:]
    return "".join(ch for ch in s if ch.isalnum())


@dataclass
class Anchor:
    """One search criterion: item-name pattern + expected quantity.

    qty == 0 means 'any quantity'. The two anchors together identify the
    player inventory: placed as the LAST items (last picked up), they form
    a tail pattern no chest/stash should replicate.
    """
    pattern: str
    qty: int

    def matches(self, it: Item) -> bool:
        if not self.pattern:
            return False
        p, n = _norm_name(self.pattern), _norm_name(it.name)
        if not p or (p not in n and n not in p):
            return False
        return self.qty == 0 or it.stack == self.qty


DEFAULT_ANCHORS = (Anchor("arrow_bloodgold", 100), Anchor("arrow_fire", 100))


def _score_items(items: list[Item], anchors: list[Anchor]) -> int:
    """3 = anchors are the tail (array order or grid order), 2 = adjacent,
    1 = both present somewhere, 0 = no match."""
    if not anchors or not items:
        return 0
    n = len(anchors)
    if len(items) >= n:
        tail = items[-n:]
        if all(a.matches(tail[i]) for i, a in enumerate(anchors)):
            return 3
        g = sorted(items, key=lambda i: (i.grid_y, i.grid_x))
        tail = g[-n:]
        if all(a.matches(tail[i]) for i, a in enumerate(anchors)):
            return 3
        for i in range(len(items) - n + 1):
            if all(a.matches(items[i + j]) for j, a in enumerate(anchors)):
                return 2
    if all(any(a.matches(it) for it in items) for a in anchors):
        return 1
    return 0


def read_mono_string(mem: ProcessMemory, sbase: int) -> str | None:
    """Read a Mono/CLR string object (length-prefixed UTF-16)."""
    if not sbase or (sbase & 7) != 0:
        return None
    for len_off, chars_off in _STRING_LAYOUTS:
        b = mem.read(sbase + len_off, 4)
        if not b:
            return None
        n = int.from_bytes(b, "little")
        if not 0 < n <= 256:
            continue
        raw = mem.read(sbase + chars_off, n * 2)
        if not raw or len(raw) != n * 2:
            continue
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if all(32 <= ord(c) <= 126 for c in s):
            return s
    return None


@dataclass
class Item:
    name: str
    base: int
    stack: int
    durability: float
    grid_x: int
    grid_y: int
    max_stack: int | None
    shared: int

    @property
    def display_name(self) -> str:
        n = self.name
        if n.startswith("$item_"):
            n = n[6:]
        return n.replace("_", " ").strip().title()

    @property
    def is_stackable(self) -> bool:
        return (self.max_stack or 1) > 1 or self.stack > 1

    @property
    def key(self) -> str:
        return self.name


@dataclass
class Layout:
    name_off: int = NAME_OFF
    shared_off: int = SHARED_OFF
    stack_off: int = STACK_OFF
    dur_off: int = DUR_OFF
    grid_off: int = GRID_OFF
    max_off: int | None = None
    anchor_base: int = 0
    anchor_count: int = 0


@dataclass
class Source:
    """One discovered item-pointer array (a candidate inventory)."""
    label: str
    items: list[Item]
    anchor_count: int
    span: tuple[int, int]
    match_score: int = 0

    @property
    def item_count(self) -> int:
        return len(self.items)


class Inventory:
    """Live inventory view: items + the layout that finds them."""

    def __init__(self, mem: ProcessMemory, layout: Layout, source: Source,
                 sources: list[Source]):
        self.mem = mem
        self.layout = layout
        self.source = source
        self.sources = sources
        self.items = source.items

    @property
    def grid_cols(self) -> int:
        return max((i.grid_x for i in self.items), default=-1) + 1

    @property
    def grid_rows(self) -> int:
        return max((i.grid_y for i in self.items), default=-1) + 1

    def refresh(self) -> None:
        lay = self.layout
        for it in self.items:
            v = self.mem.read_i32(it.base + lay.stack_off)
            if v is None:
                continue
            it.stack = v
            d = self.mem.read_f32(it.base + lay.dur_off)
            if d is not None and d == d:
                it.durability = d

    def set_stack(self, item: Item, value: int) -> bool:
        value = max(1, min(999_999, int(value)))
        if self.mem.write_u32(item.base + self.layout.stack_off, value):
            item.stack = value
            return True
        return False

    def add_stack(self, item: Item, delta: int) -> bool:
        return self.set_stack(item, item.stack + int(delta))

    def set_max(self, item: Item) -> bool:
        target = item.max_stack or max(item.stack, 100)
        return self.set_stack(item, target)

    def set_durability(self, item: Item, value: float) -> bool:
        value = max(0.0, float(value))
        if self.mem.write_f32(item.base + self.layout.dur_off, value):
            item.durability = value
            return True
        return False

    def at(self, x: int, y: int) -> Item | None:
        for it in self.items:
            if it.grid_x == x and it.grid_y == y:
                return it
        return None


# ---------------------------------------------------------------- helpers

def _name_of(mem: ProcessMemory, item_base: int) -> str | None:
    shared = mem.read_u64(item_base + SHARED_OFF)
    if not shared:
        return None
    sb = mem.read_u64(shared + NAME_OFF)
    return read_mono_string(mem, sb) if sb else None


def _looks_like_item(mem: ProcessMemory, p: int) -> bool:
    if not p or p & 7:
        return False
    if not mem.is_heap(p):
        return False
    shared = mem.read_u64(p + SHARED_OFF)
    if not shared or shared & 7 or not mem.is_heap(shared):
        return False
    return _name_of(mem, p) is not None


def _build_item(mem: ProcessMemory, ib: int, lay: Layout) -> Item | None:
    shared = mem.read_u64(ib + lay.shared_off)
    name = _name_of(mem, ib)
    if not name:
        return None
    stack = mem.read_i32(ib + lay.stack_off)
    if stack is None:
        return None
    dur = mem.read_f32(ib + lay.dur_off)
    g = mem.read(ib + lay.grid_off, 8)
    if not g:
        return None
    x, y = struct.unpack_from("<ii", g)
    max_stack = None
    if lay.max_off is not None and shared:
        max_stack = mem.read_i32(shared + lay.max_off)
    return Item(name=name, base=ib, stack=stack,
                durability=(dur if dur is not None and dur == dur else 0.0),
                grid_x=x, grid_y=y, max_stack=max_stack, shared=shared or 0)


# ---------------------------------------------------------------- discovery

def _find_strings(mem: ProcessMemory, regions) -> set[int]:
    out: set[int] = set()
    pat = ANCHOR_NAME.encode("utf-16-le")
    for hit in mem.find_pattern(pat, regions, stride=4):
        for sb in (hit - 0x14, hit - 0x0C):
            if read_mono_string(mem, sb) == ANCHOR_NAME:
                out.add(sb)
                break
    return out


def _shared_candidates(mem: ProcessMemory, regions) -> dict[int, int]:
    """shared base -> anchor string base, validated through the name chain."""
    str_bases = _find_strings(mem, regions)
    if not str_bases:
        raise DiscoveryError(
            f"'{ANCHOR_NAME}' not found - load into the world with the "
            "fire arrows in your inventory, then Rescan")
    name_hits = mem.find_u64_values(str_bases, regions)
    out: dict[int, int] = {}
    for nf, sv in name_hits:
        cand = nf - NAME_OFF
        if cand in out or cand & 7:
            continue
        # strict: the candidate itself must resolve to the anchor name
        if read_mono_string(mem, sv) == ANCHOR_NAME:
            out[cand] = sv
    return out


def _anchor_items(mem: ProcessMemory, regions, shared_cands: dict[int, int]) -> dict[int, int]:
    """item base -> shared base for ItemData objects of the anchor item."""
    hits = mem.find_u64_values(set(shared_cands), regions)
    out: dict[int, int] = {}
    for sf, sval in hits:
        ib = sf - SHARED_OFF
        if ib in out or ib & 7:
            continue
        if _name_of(mem, ib) != ANCHOR_NAME:
            continue
        out[ib] = sval
    return out


def _collect_runs(mem: ProcessMemory, anchor_bases: set[int],
                  regions) -> list[list[int]]:
    """Maximal contiguous runs of ItemData pointers containing an anchor."""
    hits = mem.find_u64_values(anchor_bases, regions)
    if not hits:
        raise DiscoveryError("anchor items referenced nowhere - rescan")
    runs: list[list[int]] = []
    for haddr, _ in hits:
        members = [haddr]
        # walk right
        a = haddr
        while True:
            a += 8
            p = mem.read_u64(a)
            if p is None or not _looks_like_item(mem, p):
                break
            members.append(a)
        # walk left
        a = haddr
        while True:
            a -= 8
            p = mem.read_u64(a)
            if p is None or not _looks_like_item(mem, p):
                break
            members.insert(0, a)
        if len(members) < 2:
            continue
        # dedupe overlapping runs
        s = set(members)
        for r in runs:
            if s & set(r):
                r.extend(members)
                break
        else:
            runs.append(members)
    merged: list[list[int]] = []
    for r in runs:
        uniq = sorted(set(r))
        for m in merged:
            if set(uniq) & set(m):
                m.extend(uniq)
                break
        else:
            merged.append(uniq)
    return [sorted(set(r)) for r in merged]


def _vote_max_off(mem: ProcessMemory, items: list[Item]) -> int | None:
    best_off, best_ok = None, 0
    for off in MAX_OFF_CANDIDATES:
        ok = 0
        for it in items:
            if not it.shared:
                continue
            v = mem.read_i32(it.shared + off)
            if v in MAX_STACK_VALUES:
                ok += 1
        if items and ok > best_ok:
            best_off, best_ok = off, ok
    # require a clear majority so one odd item can't break it
    if best_off is not None and best_ok >= max(2, (len(items) * 3) // 4):
        return best_off
    return None


def discover(mem: ProcessMemory, anchors: list[Anchor] | None = None,
             log=print) -> tuple[Layout, list[Source]]:
    anchors = list(anchors) if anchors else list(DEFAULT_ANCHORS)
    regions = mem.scannable_regions(private_only=True)
    if not regions:
        raise DiscoveryError("no readable memory regions - wrong process?")

    log("[1/5] searching anchor item strings...")
    shared_cands = _shared_candidates(mem, regions)
    log(f"      {len(shared_cands)} SharedData objects named '{ANCHOR_NAME}'")

    log("[2/5] locating ItemData objects...")
    anchor_items = _anchor_items(mem, regions, shared_cands)
    if not anchor_items:
        raise DiscoveryError("no ItemData with that name - rescan")
    log(f"      {len(anchor_items)} ItemData instances")

    log("[3/5] locating inventory arrays...")
    runs = _collect_runs(mem, set(anchor_items), regions)
    log(f"      {len(runs)} candidate inventory arrays")

    lay = Layout(anchor_base=next(iter(anchor_items)),
                 anchor_count=len(anchor_items))

    log("[4/5] scoring candidate arrays...")
    # build sources in ARRAY ORDER (needed for tail matching)
    sources: list[Source] = []
    for run in runs:
        items = []
        for slot_addr in run:
            p = mem.read_u64(slot_addr)
            if not p:
                continue
            it = _build_item(mem, p, lay)
            if it:
                items.append(it)
        if len(items) < 2:
            continue
        ac = sum(1 for i in items
                 if i.name == ANCHOR_NAME and i.stack == ANCHOR_STACK)
        sources.append(Source(
            label=f"{len(items)} items @ 0x{run[0]:X}",
            items=items, anchor_count=ac,
            span=(run[0], run[-1] + 8),
            match_score=_score_items(items, anchors)))
    if not sources:
        raise DiscoveryError("no inventory arrays found")
    for s in sources:
        log(f"      {s.label}  tail-match={s.match_score} "
            f"fire100={s.anchor_count}")

    best = max(sources, key=lambda s: (s.match_score, s.anchor_count,
                                       s.item_count))
    lay.max_off = _vote_max_off(mem, best.items)
    log(f"      m_maxStack={'+' + hex(lay.max_off) if lay.max_off else 'not found'}")

    log("[5/5] reading item fields...")
    for src in sources:
        for it in src.items:
            if lay.max_off and it.shared:
                it.max_stack = mem.read_i32(it.shared + lay.max_off)
    best.items.sort(key=lambda i: (i.grid_y, i.grid_x))
    return lay, sources


def attach(anchors: list[Anchor] | None = None, log=print) -> Inventory:
    """Auto-find valheim.exe and discover its inventory."""
    pids = find_processes("valheim.exe")
    if not pids:
        raise DiscoveryError("valheim.exe is not running")
    pid = pids[0]
    log(f"valheim.exe pid={pid} (0x{pid:X})")
    mem = ProcessMemory(pid)
    lay, sources = discover(mem, anchors, log=log)
    best = max(sources, key=lambda s: (s.match_score, s.anchor_count,
                                       s.item_count))
    return Inventory(mem, lay, best, sources)


if __name__ == "__main__":
    import sys
    # usage: python -m app.discovery [name1 qty1 [name2 qty2]]
    # e.g.:  python -m app.discovery arrow_bloodgold 100 arrow_fire 100
    argv = sys.argv[1:]
    anchors = list(DEFAULT_ANCHORS)
    if len(argv) >= 2:
        anchors = [Anchor(argv[0], int(argv[1]))]
        if len(argv) >= 4:
            anchors.append(Anchor(argv[2], int(argv[3])))
        print(f"anchors: {[(a.pattern, a.qty) for a in anchors]}")
    try:
        inv = attach(anchors, log=print)
    except DiscoveryError as e:
        print(f"discovery failed: {e}")
        sys.exit(1)
    lay = inv.layout
    print(f"\nlayout: shared=+0x{lay.shared_off:X} name=+0x{lay.name_off:X} "
          f"stack=+0x{lay.stack_off:X} dur=+0x{lay.dur_off:X} "
          f"grid=+0x{lay.grid_off:X} "
          f"max={hex(lay.max_off) if lay.max_off else '?'}")
    for src in inv.sources:
        print(f"source: {src.label}  items={src.item_count} "
              f"tail-match={src.match_score} fire100={src.anchor_count}")
    print(f"\nselected source ({inv.source.item_count} items):")
    for it in inv.items:
        print(f"  ({it.grid_x},{it.grid_y}) {it.display_name:<28} "
              f"stack={it.stack:<6} max={it.max_stack} dur={it.durability:.0f} "
              f"@0x{it.base:X}")
