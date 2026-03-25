# Royal IP Scanner — v10.0.0 Patch Notes
**Branch:** `feat/v10.0.0` &nbsp;|&nbsp; **Previous:** `UI_Scan` &nbsp;|&nbsp; **Date:** 2026-03-25

---

## What's New

- **Renamed** to **Royal IP Scanner** (formerly "IP Processing Tool")
- **Full UI redesign** — consistent color scheme, cleaner layout, better spacing across all windows
- **Sortable columns** — click any column header to sort results
- **Search / filter bar** — live filtering of scan results as you type
- **Progress bar** now shows `X / Y (Z%)` text so you know exactly where the scan is at
- **Stop and Clear buttons** are now hidden until a scan is running — less clutter
- **Settings are now saved** between sessions (see storage locations below)
- **Floor mappings editor** built into the Settings dialog — no more editing files by hand

---

## Wake-on-LAN

- Button now has a **tooltip** explaining exactly how to use it and what to expect
- Clicking it with nothing selected shows a **step-by-step guide** instead of a vague error
- After sending, you get a **per-machine result list** — ✓ sent, — skipped (no MAC), ✗ error
- Status bar updates with a summary (e.g. "3 sent, 1 skipped")
- No credentials are required — WoL magic packets are UDP broadcasts on the local network

---

## Selection

- **Click a cell** → selects that cell (same as before)
- **Click the grey strip on the left edge of a row** → selects the entire row
- **Ctrl / Shift + click** → multi-select rows or cells
- Works like Excel

---

## Scrolling

- **Shift + scroll wheel** → scrolls the results grid horizontally
- **Touchpad two-finger horizontal swipe** → also scrolls horizontally

---

## Bug Fixes

- Last logged-on user now reads correctly from registry (was returning blank in some cases)
- Windows version now reports the correct build string (e.g. `23H2`) on Windows 11 23H2 machines
- MAC address detection no longer picks up Microsoft virtual adapters (Hyper-V, VPN tunnels, etc.)
- Microsoft Office detection now checks both 64-bit and 32-bit install paths
- Machine model reverted to `Win32_ComputerSystemProduct.Version` (previous behaviour)
- EC firmware version now shows `N/A (Virtual)` on virtual machines instead of `255.255`
- Progress bar correctly resets to zero when a scan is stopped mid-way
- Placeholder text in input fields now displays properly

---

## Performance

- Hostname resolution now runs in parallel across all IPs (faster scan start)
- BIOS-related WMI queries merged from 3 separate calls into 1

---

## Storage Locations

> These are relevant for compliance, auditing, and IT support.

| What | Where |
|------|-------|
| **User settings** | `%APPDATA%\IPProcessingTool\settings.json` |
| **Floor mappings** | `floor_mappings.json` — same folder as the `.exe` |
| **Audit log** | `app.log` — same folder as the `.exe` |

### About the audit log

Every action the tool takes is written to `app.log`. Each entry includes:

```
2026-03-25 14:32:01 [INFO] RunAs: OAK\admin | LoggedOn: OAK\artguz | Context: WakeOnLAN, Message: ...
```

- **RunAs** — the Windows account the app was launched under (e.g. a shared admin account)
- **LoggedOn** — the person physically logged into that Windows session at the time
- This means even when running with shared admin credentials, the log still identifies who was at the machine

---

## Notes

- The `.exe` folder needs write permission for `app.log` and `floor_mappings.json` to work
- Settings in `%APPDATA%` are per-user — each Windows account gets its own column/settings preferences
- WoL requires the target machine to have Wake-on-LAN enabled in BIOS — the tool cannot enable it remotely
