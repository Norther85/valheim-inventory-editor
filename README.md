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

- put 2 differen arrows, quantity 100 to last 2 slots
- needed 8x6 inventory
- rescan
- only works in single player, if you connect to online server > restart game

![Screenshot](images/valheimt.jpeg)
