# Valheim Inventory Editor

Single-player inventory editor for Valheim. Edits item quantities directly in the game's memory — no injection, no game files
modified, just reads/writes against the local `valheim.exe` process.

> For your own single-player game only.

## Run

```
python -m app
```

Requirements: Windows, Python 3.12+, `pip install customtkinter numpy pillow`
(pillow only for the research screenshots).

The app **auto-attaches**: it finds `valheim.exe` by itself, re-scans when the
game restarts, and live-refreshes quantities while you play.

## How it works

Heap addresses change every launch (see `adressess.txt` — two sessions, two
totally different addresses), so nothing is hardcoded. Each attach re-derives
the layout from the game:

1. find Mono strings `$item_arrow_fire` (UTF-16, length-prefixed)
2. follow `SharedData.m_name → ItemData.m_shared` pointer chain
3. locate the inventory arrays (runs of `ItemData` pointers)
4. **identify YOUR inventory** via the tail pattern (below)
5. vote field offsets per attach (`m_stack`, `m_gridPos`, `m_maxStack`, …)

Confirmed layout (verified live 2026-11, valheim.exe Mono build):

| field | offset | type |
|---|---|---|
| `SharedData.m_name` | +0x10 | string ptr |
| `ItemData.m_shared` | +0x10 | ptr |
| `ItemData.m_stack` | +0x38 | int32 |
| `ItemData.m_durability` | +0x3C | float |
| `ItemData.m_gridPos` | +0x58 | 2×int32 (x=col 0-7, y=row 0-5) |
| `SharedData.m_maxStack` | +0x138 | int32 (voted per attach) |

Note: Mono vtables live on the heap, *not* in an image — object validation
goes through the name chain instead.

## Identifying your inventory (important)

The game world contains several item arrays (chests, stashes, the player
inventory). To pick the right one, keep a **unique tail pattern** in your
inventory — the last two items picked up:

1. **100 gold-blood arrows** (`arrow_bloodgold`)
2. **100 fire arrows** (`arrow_fire`) — last

The pattern bar at the bottom of the window lets you change both criteria
(name + quantity) and hit **Apply & Rescan**. Matching is fuzzy on names
(`$item_` prefix, spaces/case ignored) and scores each candidate array:

- **3** = criteria are the last 2 items (array or grid order) ← your inventory
- **2** = adjacent somewhere
- **1** = both present
- **0** = no match (falls back to "most fire-arrow-100 stacks")

## Using the editor

- Click a slot → editor panel shows name, quantity, max stack
- **−100…+100** nudge buttons, **Set exact value** entry (Enter works)
- **Presets**: 10 / 20 / 30 / 50 / 100 / 9999
- **SET TO MAX** = the item's own `m_maxStack` (e.g. meads 10, coal 50)
- Gear (stack=1) shows durability with a blue bar; durability setter appears
  in the editor panel

Values above the item's max stack work in memory but the game may clamp
them when it next touches the stack.

## Research tools (`research/`)

- `probe1–4.py` — the live recon that derived the layout above
- `recon1.cs/.ps1` — earlier C# scanner (string/pass A-C), kept for reference
- `shot.py`, `click.py` — screenshot / synthetic-click helpers for testing
- `python -m app.discovery [name qty [name qty]]` — CLI dump, e.g.:
  `python -m app.discovery arrow_bloodgold 100 arrow_fire 100`
