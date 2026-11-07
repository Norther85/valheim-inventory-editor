// Live reconnaissance scanner for valheim.exe (read-only).
// Pass A: find managed item-name strings (UTF-16) on the heap
// Pass B: find pointers to those string objects  -> ItemData.m_name fields
// Pass C: find the object headers, then locate the Inventory List._items array
//         and dump every item's raw fields for offset analysis.
// NOTE: C# 5 compatible (compiled with the in-box .NET Framework csc).
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class Recon1
{
    // ---------------- Win32 ----------------
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, uint len);

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    const int PROCESS_VM_READ = 0x0010;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_PRIVATE = 0x20000;
    const uint MEM_MAPPED = 0x40000;
    const uint MEM_IMAGE = 0x1000000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    class Region
    {
        public ulong Base;
        public ulong Size;
        public uint Type;
        public uint Protect;
    }

    static IntPtr _h;
    static TextWriter _log;
    static List<Region> _scan = new List<Region>();   // readable private/mapped
    static List<Region> _all = new List<Region>();    // every region (for image checks)

    // ---------------- entry ----------------
    public static void Run(int pid, string outPath)
    {
        _log = new StreamWriter(outPath, false, Encoding.UTF8);
        try
        {
            _h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
            if (_h == IntPtr.Zero)
            {
                _log.WriteLine("OpenProcess failed, win32=" + Marshal.GetLastWin32Error());
                return;
            }
            EnumRegions();

            // ---- Pass A: strings ----
            string[] names = new string[] { "FireArrows", "ArrowFire", "FireArrow", "$item_arrow_fire", "ArrowWood", "Wood" };
            _log.WriteLine("=== PASS A: managed name strings ===");
            Dictionary<long, string> strBases = new Dictionary<long, string>();
            foreach (KeyValuePair<long, string> kv in FindStrings(names))
            {
                strBases[kv.Key] = kv.Value;
                _log.WriteLine(string.Format("  string obj at 0x{0:X}  name='{1}'", kv.Key, kv.Value));
            }
            if (strBases.Count == 0)
            {
                _log.WriteLine("  NO name strings found -- cannot continue.");
                return;
            }

            // ---- Pass B: pointers to the string objects ----
            _log.WriteLine();
            _log.WriteLine("=== PASS B: pointers to string objects (ItemData.m_name fields) ===");
            HashSet<long> sset = new HashSet<long>(strBases.Keys);
            List<long> nameFieldHits = FindPointers(sset);
            _log.WriteLine("  hits: " + nameFieldHits.Count);

            // For each hit, derive the object base (find the vtable just before it)
            Dictionary<long, string> objBases = new Dictionary<long, string>(); // base -> name
            foreach (long a in nameFieldHits)
            {
                _log.WriteLine();
                _log.WriteLine("--- name field @ 0x" + a.ToString("X") + " ---");
                DumpWindow(a - 0x40, 0x130, a);

                // vtable search: look backwards from the field for a pointer into an image
                List<long> bases = FindObjectBases(a);
                foreach (long b in bases)
                {
                    string nm;
                    if (!objBases.TryGetValue(b, out nm))
                    {
                        nm = ReadNameString(b);
                        objBases[b] = nm;
                    }
                    _log.WriteLine("    candidate object base 0x" + b.ToString("X") + "  (name ptr at +" + (a - b).ToString("X") + ")  name='" + nm + "'");
                }
            }

            // ---- Pass C: pointers to object bases -> Inventory List._items ----
            _log.WriteLine();
            _log.WriteLine("=== PASS C: pointers to item objects (list search) ===");
            HashSet<long> bset = new HashSet<long>(objBases.Keys);
            List<long> objPtrHits = FindPointers(bset);
            _log.WriteLine("  hits: " + objPtrHits.Count);
            foreach (long h in objPtrHits)
            {
                int score = ScoreArray(h);
                _log.WriteLine(string.Format("  ptr hit @ 0x{0:X}  array-likeness score={1}", h, score));
            }

            // dump the best-scoring window(s) in full
            List<long> sorted = new List<long>(objPtrHits);
            sorted.Sort(delegate(long x, long y) { return ScoreArray(y).CompareTo(ScoreArray(x)); });
            int shown = 0;
            foreach (long h in sorted)
            {
                if (shown >= 4) break;
                if (ScoreArray(h) < 3) break;
                shown++;
                _log.WriteLine();
                _log.WriteLine("--- possible List._items slot @ 0x" + h.ToString("X") + " (score " + ScoreArray(h) + ") ---");
                DumpItems(h);
            }

            // ---- final: full raw dump of every distinct item object found ----
            _log.WriteLine();
            _log.WriteLine("=== ITEM OBJECTS (raw field windows) ===");
            foreach (KeyValuePair<long, string> kv in objBases)
            {
                _log.WriteLine();
                _log.WriteLine("--- item object 0x" + kv.Key.ToString("X") + "  name='" + kv.Value + "' ---");
                DumpWindow(kv.Key, 0x100, -1);
            }
        }
        catch (Exception ex)
        {
            _log.WriteLine("EXCEPTION: " + ex.ToString());
        }
        finally
        {
            if (_h != IntPtr.Zero) CloseHandle(_h);
            _log.Close();
        }
    }

    // ---------------- regions ----------------
    static void EnumRegions()
    {
        long addr = 0;
        while (addr < 0x7FFF00000000)
        {
            MBI mbi;
            int r = VirtualQueryEx(_h, new IntPtr(addr), out mbi, (uint)Marshal.SizeOf(typeof(MBI)));
            if (r == 0) break;
            ulong end = mbi.BaseAddress + mbi.RegionSize;
            Region reg = new Region();
            reg.Base = mbi.BaseAddress;
            reg.Size = mbi.RegionSize;
            reg.Type = mbi.Type;
            reg.Protect = mbi.Protect;
            _all.Add(reg);
            bool readable = (mbi.State == MEM_COMMIT) &&
                            ((mbi.Protect & PAGE_GUARD) == 0) &&
                            ((mbi.Protect & 0xFF) != PAGE_NOACCESS) &&
                            ((mbi.Protect & 0x02) != 0 || (mbi.Protect & 0x04) != 0 || (mbi.Protect & 0x08) != 0 ||
                             (mbi.Protect & 0x20) != 0 || (mbi.Protect & 0x40) != 0 || (mbi.Protect & 0x80) != 0);
            if (readable && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED))
                _scan.Add(reg);
            if (end <= (ulong)addr) break;
            addr = (long)end;
        }
        ulong total = 0;
        for (int i = 0; i < _scan.Count; i++) total += _scan[i].Size;
        _log.WriteLine(string.Format("regions: total={0}  scannable={1}  scannable bytes={2:F1} MB", _all.Count, _scan.Count, total / 1048576.0));
    }

    static bool IsImageAddr(long v)
    {
        if (v < 0x10000) return false;
        for (int i = 0; i < _all.Count; i++)
        {
            Region r = _all[i];
            if ((ulong)v >= r.Base && (ulong)v < r.Base + r.Size)
                return r.Type == MEM_IMAGE;
        }
        return false;
    }

    static bool IsHeapAddr(long v)
    {
        if (v < 0x10000) return false;
        for (int i = 0; i < _scan.Count; i++)
        {
            Region r = _scan[i];
            if ((ulong)v >= r.Base && (ulong)v < r.Base + r.Size)
                return true;
        }
        return false;
    }

    // ---------------- raw read ----------------
    static byte[] Read(long addr, int size)
    {
        byte[] buf = new byte[size];
        IntPtr got;
        if (!ReadProcessMemory(_h, new IntPtr(addr), buf, size, out got)) return null;
        if ((int)got != size) return null;
        return buf;
    }

    static ulong ReadU64(long addr)
    {
        byte[] b = Read(addr, 8);
        if (b == null) return 0;
        return BitConverter.ToUInt64(b, 0);
    }

    static int ReadI32(long addr)
    {
        byte[] b = Read(addr, 4);
        if (b == null) return int.MinValue;
        return BitConverter.ToInt32(b, 0);
    }

    static float ReadF32(long addr)
    {
        byte[] b = Read(addr, 4);
        if (b == null) return float.NaN;
        return BitConverter.ToSingle(b, 0);
    }

    // ---------------- Pass A: strings ----------------
    static Dictionary<long, string> FindStrings(string[] names)
    {
        Dictionary<long, string> found = new Dictionary<long, string>();
        // map first-char -> (name, pattern bytes)
        Dictionary<byte, List<KeyValuePair<string, byte[]>>> byFirst = new Dictionary<byte, List<KeyValuePair<string, byte[]>>>();
        for (int i = 0; i < names.Length; i++)
        {
            byte[] pat = Encoding.Unicode.GetBytes(names[i]);
            if (!byFirst.ContainsKey(pat[0])) byFirst[pat[0]] = new List<KeyValuePair<string, byte[]>>();
            byFirst[pat[0]].Add(new KeyValuePair<string, byte[]>(names[i], pat));
        }

        const int CHUNK = 1 << 20;
        byte[] buf = new byte[CHUNK + 64];
        for (int ri = 0; ri < _scan.Count; ri++)
        {
            Region reg = _scan[ri];
            long pos = (long)reg.Base;
            long end = (long)(reg.Base + reg.Size);
            while (pos < end)
            {
                int want = (int)Math.Min((long)CHUNK, end - pos);
                IntPtr got;
                if (!ReadProcessMemory(_h, new IntPtr(pos), buf, want, out got)) { pos += want; continue; }
                int n = (int)got;
                for (int i = 0; i + 4 < n; i += 2) // UTF-16 aligned to string start (2-byte aligned)
                {
                    if (buf[i + 1] != 0) continue;
                    List<KeyValuePair<string, byte[]>> pats;
                    if (!byFirst.TryGetValue(buf[i], out pats)) continue;
                    for (int p = 0; p < pats.Count; p++)
                    {
                        byte[] pat = pats[p].Value;
                        if (i + pat.Length > n) continue;
                        bool ok = true;
                        for (int k = 0; k < pat.Length; k++) { if (buf[i + k] != pat[k]) { ok = false; break; } }
                        if (!ok) continue;
                        long hit = pos + i;
                        long sMono = hit - 0x14;
                        long sClr = hit - 0x0C;
                        string full;
                        if (ValidateString(sMono, 0x10, out full))
                        {
                            if (!found.ContainsKey(sMono)) found[sMono] = full;
                        }
                        else if (ValidateString(sClr, 0x08, out full))
                        {
                            if (!found.ContainsKey(sClr)) found[sClr] = full;
                        }
                        else
                        {
                            string key = "?? raw hit at 0x" + hit.ToString("X") + " pattern='" + pats[p].Key + "'";
                            if (!found.ContainsKey(hit)) found[hit] = key;
                        }
                    }
                }
                pos += want;
            }
        }
        return found;
    }

    static bool ValidateString(long sBase, int lenOffset, out string full)
    {
        full = null;
        int len = ReadI32(sBase + lenOffset);
        if (len < 1 || len > 64) return false;
        byte[] chars = Read(sBase + lenOffset + 4, len * 2);
        if (chars == null) return false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++)
        {
            char c = (char)BitConverter.ToUInt16(chars, i * 2);
            if (c < 32 || c > 126) return false;
            sb.Append(c);
        }
        full = sb.ToString();
        return true;
    }

    // ---------------- Pass B/C: pointer search ----------------
    static List<long> FindPointers(HashSet<long> values)
    {
        List<long> hits = new List<long>();
        const int CHUNK = 1 << 20;
        byte[] buf = new byte[CHUNK + 8];
        for (int ri = 0; ri < _scan.Count; ri++)
        {
            Region reg = _scan[ri];
            long pos = (long)reg.Base;
            long end = (long)(reg.Base + reg.Size);
            while (pos < end)
            {
                int want = (int)Math.Min((long)CHUNK, end - pos);
                IntPtr got;
                if (!ReadProcessMemory(_h, new IntPtr(pos), buf, want, out got)) { pos += want; continue; }
                int n = (int)got;
                // 8-byte aligned scan (Mono pointers are 8-aligned); keep address alignment == buffer alignment
                int startOff = (int)((8 - (pos & 7)) & 7);
                for (int i = startOff; i + 8 <= n; i += 8)
                {
                    long v = (long)BitConverter.ToUInt64(buf, i);
                    if (values.Contains(v)) hits.Add(pos + i);
                }
                pos += want;
            }
        }
        return hits;
    }

    // ---------------- object analysis ----------------
    static List<long> FindObjectBases(long nameFieldAddr)
    {
        // scan backwards up to 0x120 bytes for a vtable (pointer into an image)
        List<long> res = new List<long>();
        for (long back = 0x08; back <= 0x120; back += 8)
        {
            long cand = nameFieldAddr - back;
            ulong v = ReadU64(cand);
            if (IsImageAddr((long)v))
            {
                long monitor = (long)ReadU64(cand + 8);
                if (monitor == 0 || IsHeapAddr(monitor))
                    res.Add(cand);
            }
        }
        return res;
    }

    static string ReadNameString(long objBase)
    {
        long namePtr = (long)ReadU64(objBase + 0x10);
        if (!IsHeapAddr(namePtr)) return null;
        string s;
        if (ValidateString(namePtr, 0x10, out s)) return s;
        if (ValidateString(namePtr, 0x08, out s)) return s;
        return null;
    }

    static bool ItemDataLike(long x)
    {
        if (x == 0 || (x & 7) != 0) return false;
        if (!IsHeapAddr(x)) return false;
        ulong v = ReadU64(x);
        if (!IsImageAddr((long)v)) return false;
        return ReadNameString(x) != null;
    }

    static int ScoreArray(long h)
    {
        // how many neighbours (both directions, 8-byte slots) look like item objects?
        int score = 0;
        for (int i = -40; i <= 40; i++)
        {
            if (i == 0) continue;
            long v = (long)ReadU64(h + (long)i * 8);
            if (v == 0) continue;
            if (ItemDataLike(v)) score++;
        }
        return score;
    }

    static void DumpItems(long h)
    {
        for (int i = -40; i <= 40; i++)
        {
            long slotAddr = h + (long)i * 8;
            long v = (long)ReadU64(slotAddr);
            if (v == 0) continue;
            string name = ReadNameString(v);
            string tag = (name != null) ? "OK" : "not-item";
            _log.WriteLine(string.Format("  [{0,3}] 0x{1:X} -> 0x{2:X}  {3} '{4}'", i, slotAddr, v, tag, name));
        }
    }

    // ---------------- dumping ----------------
    static void DumpWindow(long addr, int size, long markAddr)
    {
        byte[] b = Read(addr, size);
        if (b == null) { _log.WriteLine("  (unreadable 0x" + addr.ToString("X") + ")"); return; }
        for (int i = 0; i + 8 <= size; i += 8)
        {
            long a = addr + i;
            ulong u = BitConverter.ToUInt64(b, i);
            int i0 = BitConverter.ToInt32(b, i);
            int i1 = BitConverter.ToInt32(b, i + 4);
            float f0 = BitConverter.ToSingle(b, i);
            float f1 = BitConverter.ToSingle(b, i + 4);
            string mark = (markAddr >= 0 && a == markAddr) ? "   <== m_name field" : "";
            string ptrTag = "";
            if (IsImageAddr((long)u)) ptrTag = " img";
            else if (IsHeapAddr((long)u)) ptrTag = " heap";
            _log.WriteLine(string.Format("  0x{0:X}  {1,18:X16}  i32[{2},{3}]  f32[{4:G6},{5:G6}]{6}{7}",
                a, u, i0, i1, f0, f1, ptrTag, mark));
        }
    }
}
