"""Valheim Inventory Editor - GUI (CustomTkinter, dark Valheim theme).

UX layout:
  header   process pill (auto-detect) + Rescan
  body     8x6 inventory grid (left) | item editor (right)
  footer   status log

The app auto-attaches to valheim.exe: when the game is restarted it
notices the new PID and re-scans on its own.
"""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk

import customtkinter as ctk

from .discovery import (DEFAULT_ANCHORS, Anchor, DiscoveryError, Inventory,
                        Item, discover)
from .memory import ProcessMemory, find_processes

# ---------- palette ----------
BG = "#12151a"
PANEL = "#1a1f27"
CARD = "#232a34"
CARD_HOVER = "#2d3642"
CARD_EMPTY = "#1a1f27"
ACCENT = "#e8a33d"          # torch amber
ACCENT_DIM = "#8a6425"
GREEN = "#7fb069"
RED = "#d9534f"
TEXT = "#e8e2d6"
TEXT_DIM = "#8b93a0"
BLUE = "#6fa8dc"

GRID_COLS = 8
GRID_ROWS = 6
PRESETS = (10, 20, 30, 50, 100, 9999)

ctk.set_appearance_mode("dark")
# note: customtkinter 6.x has no "dark" color theme file; all widget colors
# are set explicitly from the palette above, so the default theme is fine.


class SlotCard(ctk.CTkFrame):
    """One inventory cell."""

    def __init__(self, master, x: int, y: int, on_click):
        super().__init__(master, fg_color=CARD, corner_radius=10,
                         border_width=1, border_color="#2a323d")
        self.x, self.y = x, y
        self.on_click = on_click
        self.item: Item | None = None
        self.selected = False

        self.pos_lbl = ctk.CTkLabel(self, text=f"{y + 1},{x + 1}", width=30,
                                    text_color="#5b6472",
                                    font=ctk.CTkFont(size=9, weight="bold"))
        self.pos_lbl.pack(anchor="nw", padx=(8, 0), pady=(5, 0))

        self.name_lbl = ctk.CTkLabel(self, text="—", anchor="w",
                                     text_color=TEXT_DIM, wraplength=125,
                                     justify="left",
                                     font=ctk.CTkFont(size=11))
        self.name_lbl.pack(fill="x", padx=8, pady=(2, 0))

        self.qty_lbl = ctk.CTkLabel(self, text="", anchor="w",
                                    text_color=ACCENT,
                                    font=ctk.CTkFont(size=22, weight="bold"))
        self.qty_lbl.pack(fill="x", padx=8)

        self.dur_bar = ctk.CTkProgressBar(self, height=5, progress_color=BLUE,
                                          fg_color="#2a323d")
        self.dur_bar.set(0)
        self._sig: tuple | None = ("__never__",)   # force first render
        self._sel_state = False

        for w in (self, self.pos_lbl, self.name_lbl, self.qty_lbl):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._click)

    def _on_enter(self, _e=None):
        if not self.selected and self.item is not None:
            self.configure(fg_color=CARD_HOVER)

    def _on_leave(self, _e=None):
        if not self.selected and self.item is not None:
            self.configure(fg_color=CARD)

    def _click(self, _e=None):
        self.on_click(self.x, self.y)

    def set_item(self, item: Item | None):
        # cheap change-detection: skip all widget traffic when nothing changed
        sig = (None if item is None else
               (item.name, item.stack, round(item.durability, 1),
                item.is_stackable, item.max_stack))
        if sig == self._sig:
            return
        self._sig = sig
        self.item = item
        if item is None:
            self.name_lbl.configure(text="—", text_color="#4c5561")
            self.qty_lbl.configure(text="")
            self.dur_bar.pack_forget()
            self.configure(fg_color=CARD_EMPTY)
            return
        self.name_lbl.configure(text=item.display_name[:28], text_color=TEXT)
        if item.is_stackable:
            self.qty_lbl.configure(text=f"×{item.stack:,}", text_color=ACCENT)
            self.dur_bar.pack_forget()
        else:
            self.qty_lbl.configure(text=f"◆ {item.durability:.0f}", text_color=BLUE)
            self.dur_bar.pack(fill="x", padx=8, pady=(0, 8))
            mx = max(item.durability, 100.0)
            self.dur_bar.set(min(1.0, item.durability / mx))
        self.configure(fg_color=CARD)

    def set_selected(self, sel: bool):
        if sel == self._sel_state:
            return
        self._sel_state = sel
        self.selected = sel
        self.configure(border_color=ACCENT if sel else "#2a323d",
                       border_width=2 if sel else 1)


class App(ctk.CTk):
    def __init__(self):
        super().__init__(fg_color=BG)
        self.title("Valheim · Inventory Editor")
        self.geometry("1360x960")
        self.minsize(1100, 800)

        self.inv: Inventory | None = None
        self.selected: Item | None = None
        self.cards: dict[tuple[int, int], SlotCard] = {}
        self.msg_q: queue.Queue = queue.Queue()
        self.conn_state = "disconnected"   # disconnected | scanning | connected
        # note: never name an attribute `state` - it shadows Tk's state() method
        self.pid: int | None = None
        self.scanning = False

        self._build_header()
        self._build_body()
        self._build_footer()

        self.after(200, self._poll_queue)
        self.after(800, self._tick)

    # ---------------- UI ----------------
    def _build_header(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=64)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="VALHEIM", text_color=ACCENT,
                     font=ctk.CTkFont(size=20, weight="bold")
                     ).pack(side="left", padx=(20, 4), pady=12)
        ctk.CTkLabel(bar, text="INVENTORY EDITOR", text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=12, weight="bold")
                     ).pack(side="left", pady=12)

        self.proc_pill = ctk.CTkLabel(
            bar, text="  ⬤ searching for valheim.exe…  ",
            text_color=TEXT_DIM, fg_color="#20262e", corner_radius=12,
            font=ctk.CTkFont(size=12))
        self.proc_pill.pack(side="right", padx=(8, 20), pady=16)

        self.rescan_btn = ctk.CTkButton(
            bar, text="Rescan", width=92, height=32, fg_color=ACCENT,
            text_color="#1a1206", hover_color="#f2b45a",
            font=ctk.CTkFont(size=13, weight="bold"), command=self._rescan)
        self.rescan_btn.pack(side="right", padx=8, pady=16)

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=BG)
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # editor (fixed width, right column) - lay out BEFORE the grid so the
        # expanding grid cannot steal its space
        self.editor = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=14,
                                   width=330, height=600)
        self.editor.grid(row=0, column=1, sticky="ns", padx=(12, 0))
        self.editor.grid_propagate(False)
        self._build_editor()

        # grid (left column)
        grid_wrap = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=14)
        grid_wrap.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(grid_wrap, text="INVENTORY  ·  8 × 6",
                     text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=11, weight="bold")
                     ).pack(anchor="w", padx=14, pady=(12, 4))

        grid = ctk.CTkFrame(grid_wrap, fg_color=PANEL)
        grid.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        for c in range(GRID_COLS):
            grid.columnconfigure(c, weight=1, uniform="col")
        for r in range(GRID_ROWS):
            grid.rowconfigure(r, weight=1, uniform="row")
        for r in range(GRID_ROWS):
            for c in range(GRID_COLS):
                card = SlotCard(grid, c, r, self._select_slot)
                card.grid(row=r, column=c, padx=4, pady=4, sticky="nsew")
                self.cards[(c, r)] = card

        # --- identification pattern (which array is YOUR inventory) ---
        pat = ctk.CTkFrame(grid_wrap, fg_color="#20262e", corner_radius=10)
        pat.pack(fill="x", padx=10, pady=(2, 12))
        ctk.CTkLabel(pat, text="IDENTIFY MY INVENTORY — last 2 items:",
                     text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=10, weight="bold")
                     ).pack(side="left", padx=(12, 8), pady=8)
        self.pat_name = []
        self.pat_qty = []
        for i in range(2):
            n = ctk.CTkEntry(pat, width=150, height=28, fg_color="#2a323d",
                             border_color="#39434f", corner_radius=6,
                             placeholder_text=f"item {i + 1} name")
            n.pack(side="left", padx=(6, 2), pady=8)
            q = ctk.CTkEntry(pat, width=56, height=28, fg_color="#2a323d",
                             border_color="#39434f", corner_radius=6,
                             placeholder_text="qty")
            q.pack(side="left", padx=(0, 8), pady=8)
            n.insert(0, DEFAULT_ANCHORS[i].pattern)
            q.insert(0, str(DEFAULT_ANCHORS[i].qty))
            self.pat_name.append(n)
            self.pat_qty.append(q)
        ctk.CTkButton(pat, text="Apply & Rescan", width=110, height=28,
                      fg_color=ACCENT, text_color="#1a1206",
                      hover_color="#f2b45a",
                      font=ctk.CTkFont(size=11, weight="bold"),
                      command=self._rescan).pack(side="left", padx=8, pady=8)

    def _build_editor(self):
        e = self.editor
        ctk.CTkLabel(e, text="SELECTED ITEM", text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=11, weight="bold")
                     ).pack(anchor="w", padx=18, pady=(16, 2))

        self.ed_name = ctk.CTkLabel(e, text="— pick a slot —", text_color=TEXT,
                                    font=ctk.CTkFont(size=19, weight="bold"),
                                    wraplength=290, justify="left")
        self.ed_name.pack(anchor="w", padx=18)

        self.ed_meta = ctk.CTkLabel(e, text="", text_color=TEXT_DIM,
                                    font=ctk.CTkFont(size=11))
        self.ed_meta.pack(anchor="w", padx=18, pady=(2, 10))

        self.ed_value = ctk.CTkLabel(e, text="", text_color=ACCENT,
                                     font=ctk.CTkFont(size=44, weight="bold"))
        self.ed_value.pack(anchor="w", padx=18)

        # nudge row
        self.nudge = ctk.CTkFrame(e, fg_color="transparent")
        self.nudge.pack(fill="x", padx=18, pady=10)
        for txt, delta in (("-100", -100), ("-10", -10), ("-1", -1),
                           ("+1", 1), ("+10", 10), ("+100", 100)):
            ctk.CTkButton(self.nudge, text=txt, width=46, height=32,
                          fg_color="#2a323d", hover_color="#39434f",
                          text_color=TEXT, corner_radius=8,
                          font=ctk.CTkFont(size=12, weight="bold"),
                          command=lambda d=delta: self._nudge(d)
                          ).pack(side="left", expand=True, fill="x", padx=2)

        # custom set
        row = ctk.CTkFrame(e, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(4, 10))
        self.ed_entry = ctk.CTkEntry(row, placeholder_text="set exact value…",
                                     height=34, fg_color="#20262e",
                                     border_color="#39434f", corner_radius=8)
        self.ed_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.ed_entry.bind("<Return>", lambda _e: self._set_custom())
        ctk.CTkButton(row, text="Set", width=60, height=34, fg_color=ACCENT,
                      text_color="#1a1206", hover_color="#f2b45a",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._set_custom).pack(side="left")

        # presets
        ctk.CTkLabel(e, text="QUANTITY PRESETS", text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=10, weight="bold")
                     ).pack(anchor="w", padx=18)
        pre = ctk.CTkFrame(e, fg_color="transparent")
        pre.pack(fill="x", padx=18, pady=(4, 6))
        for i, v in enumerate(PRESETS):
            b = ctk.CTkButton(
                pre, text=str(v), height=32, fg_color="#2a323d",
                hover_color="#39434f", text_color=TEXT, corner_radius=8,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda v=v: self._set_value(v))
            b.grid(row=i // 3, column=i % 3, padx=3, pady=3, sticky="ew")
        for i in range(3):
            pre.columnconfigure(i, weight=1)

        # max buttons
        self.max_row = ctk.CTkFrame(e, fg_color="transparent")
        self.max_row.pack(fill="x", padx=18, pady=(2, 6))
        self.btn_max = ctk.CTkButton(
            self.max_row, text="⬆ SET TO MAX", height=42, fg_color=ACCENT,
            text_color="#1a1206", hover_color="#f2b45a", corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"), command=self._set_max)
        self.btn_max.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.btn_9999 = ctk.CTkButton(
            self.max_row, text="9999", width=84, height=42, fg_color="#3a2f1c",
            hover_color="#584222", text_color=ACCENT, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self._set_value(9999))
        self.btn_9999.pack(side="left")

        # durability (hidden unless item is gear)
        self.dur_frame = ctk.CTkFrame(e, fg_color="transparent")
        self.dur_label = ctk.CTkLabel(self.dur_frame, text="DURABILITY",
                                      text_color=TEXT_DIM,
                                      font=ctk.CTkFont(size=10, weight="bold"))
        self.dur_label.pack(anchor="w")
        drow = ctk.CTkFrame(self.dur_frame, fg_color="transparent")
        drow.pack(fill="x", pady=(4, 0))
        self.dur_entry = ctk.CTkEntry(drow, placeholder_text="durability…",
                                      height=32, fg_color="#20262e",
                                      border_color="#39434f", corner_radius=8)
        self.dur_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(drow, text="Set", width=56, height=32, fg_color=BLUE,
                      text_color="#0d1520", hover_color="#8bc0ea",
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=self._set_dur).pack(side="left")
        ctk.CTkButton(drow, text="+25", width=56, height=32, fg_color="#2a323d",
                      hover_color="#39434f", text_color=TEXT,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: self._nudge_dur(25)).pack(side="left",
                                                                padx=(6, 0))

    def _build_footer(self):
        foot = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=38)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)
        self.status = ctk.CTkLabel(foot, text="starting…", text_color=TEXT_DIM,
                                   font=ctk.CTkFont(size=11))
        self.status.pack(side="left", padx=16)

    # ---------------- state ----------------
    def _set_status(self, text: str, color: str = TEXT_DIM):
        self.status.configure(text=text, text_color=color)

    def _set_pill(self, text: str, color: str):
        self.proc_pill.configure(text=f"  ⬤ {text}  ", text_color=color)

    def _log(self, msg: str, color: str = TEXT_DIM):
        self._set_status(f"{time.strftime('%H:%M:%S')}  ·  {msg}", color)

    # ---------------- background: scan / reconnect ----------------
    def _tick(self):
        try:
            if self.conn_state == "connected":
                self.inv.refresh()
                self._refresh_cards()
                pids = find_processes("valheim.exe")
                if not pids or pids[0] != self.pid:
                    self._log("valheim.exe lost — waiting for the game…", RED)
                    self._disconnect()
            elif self.conn_state == "disconnected" and not self.scanning:
                pids = find_processes("valheim.exe")
                if pids:
                    self._start_scan(pids[0])
        except Exception as exc:                      # keep the GUI alive
            self._log(f"error: {exc}", RED)
        self.after(1500, self._tick)

    def _disconnect(self):
        self.conn_state = "disconnected"
        self.inv = None
        self.selected = None
        self._set_pill("waiting for valheim.exe…", TEXT_DIM)
        self._clear_cards()
        self._reset_editor()

    def _rescan(self):
        if self.scanning:
            return
        pids = find_processes("valheim.exe")
        if not pids:
            self._log("valheim.exe is not running", RED)
            self._disconnect()
            return
        self._start_scan(pids[0])

    def _read_anchors(self) -> list[Anchor]:
        """Build search criteria from the pattern bar (2 items, name + qty)."""
        out: list[Anchor] = []
        for n_entry, q_entry in zip(self.pat_name, self.pat_qty):
            name = n_entry.get().strip()
            if not name:
                continue
            raw = q_entry.get().strip()
            try:
                qty = int(raw) if raw else 0
            except ValueError:
                qty = 0
            out.append(Anchor(name, qty))
        return out or list(DEFAULT_ANCHORS)

    def _start_scan(self, pid: int):
        self.scanning = True
        self.conn_state = "scanning"
        self.pid = pid
        self._set_pill(f"scanning valheim.exe (PID 0x{pid:X})…", ACCENT)
        self._log("scanning game memory — this takes a few seconds…", ACCENT)
        anchors = self._read_anchors()

        def work():
            try:
                mem = ProcessMemory(pid)
                lay, sources = discover(
                    mem, anchors,
                    log=lambda m: self.msg_q.put(("log", m)))
                best = max(sources,
                           key=lambda s: (s.match_score, s.anchor_count,
                                          s.item_count))
                inv = Inventory(mem, lay, best, sources)
                self.msg_q.put(("ok", inv))
            except DiscoveryError as exc:
                self.msg_q.put(("err", str(exc)))
            except Exception as exc:
                self.msg_q.put(("err", f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "err":
                    self.scanning = False
                    self.conn_state = "disconnected"
                    self._set_pill("scan failed", RED)
                    self._log(f"scan failed: {payload}", RED)
                elif kind == "ok":
                    self.scanning = False
                    self.conn_state = "connected"
                    self.inv = payload
                    self.selected = None      # old Items point at dead memory
                    self._reset_editor()
                    lay = self.inv.layout
                    self._set_pill(
                        f"valheim.exe · PID 0x{self.pid:X} · "
                        f"{len(self.inv.items)} items", GREEN)
                    max_txt = (f"+0x{lay.max_off:X}" if lay.max_off else "?")
                    self._log(
                        f"connected — layout stack +0x{lay.stack_off:X}, "
                        f"grid +0x{lay.grid_off:X}, max {max_txt}",
                        GREEN)
                    self._refresh_cards()
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    # ---------------- cards / editor ----------------
    def _clear_cards(self):
        for card in self.cards.values():
            card.set_selected(False)
            card.set_item(None)

    def _refresh_cards(self):
        if not self.inv:
            return
        grid = {(i.grid_x, i.grid_y): i for i in self.inv.items}
        for key, card in self.cards.items():
            card.set_item(grid.get(key))
            card.set_selected(self.selected is not None and
                              grid.get(key) is self.selected)

    def _select_slot(self, x: int, y: int):
        if not self.inv:
            return
        self.selected = self.inv.at(x, y)
        self._refresh_cards()
        self._update_editor()

    def _reset_editor(self):
        self.selected = None
        self.ed_name.configure(text="— pick a slot —")
        self.ed_meta.configure(text="")
        self.ed_value.configure(text="")
        self.dur_frame.pack_forget()

    def _update_editor(self):
        it = self.selected
        if it is None:
            self._reset_editor()
            return
        self.ed_name.configure(text=it.display_name)
        self.ed_meta.configure(
            text=f"{it.name}   ·   slot {it.grid_x + 1},{it.grid_y + 1}   ·   "
                 f"max {it.max_stack if it.max_stack else '?'}")
        if it.is_stackable:
            self.ed_value.configure(text=f"{it.stack:,}")
            self.dur_frame.pack_forget()
            self.btn_max.configure(text=f"⬆ SET TO MAX ({it.max_stack or '?'})")
        else:
            self.ed_value.configure(text=f"{it.durability:.0f}")
            self.dur_frame.pack(fill="x", padx=18, pady=(2, 10))
            self.btn_max.configure(text="⬆ SET TO MAX")

    # ---------------- edit ops ----------------
    def _edit(self, fn, label: str):
        if not self.inv or not self.selected:
            return
        if fn(self.selected):
            self._refresh_cards()
            self._update_editor()
            self._log(label, GREEN)
        else:
            self._log("write failed — is the game still running?", RED)

    def _nudge(self, delta: int):
        self._edit(lambda i: self.inv.add_stack(i, delta),
                   f"{self.selected.display_name}: {self.selected.stack} → "
                   f"{self.selected.stack + delta}")

    def _set_value(self, value: int):
        self._edit(lambda i: self.inv.set_stack(i, value),
                   f"{self.selected.display_name}: set to {value:,}")

    def _set_max(self):
        it = self.selected
        if not it:
            return
        target = it.max_stack or 9999
        self._edit(lambda i: self.inv.set_stack(i, target),
                   f"{it.display_name}: set to max ({target:,})")

    def _set_custom(self):
        raw = self.ed_entry.get().strip().replace(",", "").replace(" ", "")
        if not raw:
            return
        try:
            value = int(raw)
        except ValueError:
            self._log("enter a whole number", RED)
            return
        self.ed_entry.delete(0, "end")
        self._set_value(value)

    def _set_dur(self):
        raw = self.dur_entry.get().strip().replace(",", ".")
        if not raw:
            return
        try:
            value = float(raw)
        except ValueError:
            self._log("enter a number", RED)
            return
        self.dur_entry.delete(0, "end")
        self._edit(lambda i: self.inv.set_durability(i, value),
                   f"{self.selected.display_name}: durability → {value:.0f}")

    def _nudge_dur(self, delta: float):
        it = self.selected
        if not it:
            return
        self._edit(lambda i: self.inv.set_durability(i, i.durability + delta),
                   f"{it.display_name}: durability → {it.durability + delta:.0f}")


def run():
    app = App()
    app.mainloop()
