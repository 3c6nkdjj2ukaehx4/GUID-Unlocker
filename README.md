# MX Bikes GUID bypass

Patches all GUID comparisons used by the MX Bikes `.pkz` loader so archives
(tracks, bikes, etc.) load regardless of which GUID they were locked to.

## Files

```
bin\x64\Release\Loader.exe     injector
bin\x64\Release\version.dll    bypass DLL
```

## Usage

1. Launch MX Bikes first.
2. Run `Loader.exe` while the game is open.
3. It injects `version.dll`, then closes after 3 seconds.

If MX Bikes is not open, `Loader.exe` closes immediately.

There is no proxy, no game-file modification, and no separate installer.
The loader never launches or waits for the game.

After injection the bypass DLL re-runs the game's track-list loader, so tracks
that were previously rejected because of the GUID appear without restarting.
Press **F9** in the game to force a track refresh.

## What is patched

### `sub_7FF7FC3C7920` - archive header (5 sites)

```
RVA 0x158018   cmp rdx, [r14+0x396770]
RVA 0x158025   cmp rdx, [r14+0x396778]
RVA 0x158402   cmp rdx, [r14+0x396770]
RVA 0x15840F   cmp rdx, [r14+0x396778]
RVA 0x1583EA   cmp dword_7FF7FC60676C, r13d
```

### `sub_7FF7FC3C9A40` - entry reader used by tracks (6 sites)

```
RVA 0x159DD0   cmp rdx, [rax]              ; qword_7FF7FC606770
RVA 0x159DD9   cmp rdx, [rax+8]            ; FF marker
RVA 0x15A1F8   cmp rdx, [rax]              ; old header copy
RVA 0x15A201   cmp rdx, [rax+8]            ; old header copy
RVA 0x15A1E2   jnz after sub_7FF7FC3C9660() ; reason gate
RVA 0x159A7D   jnz after sub_7FF7FC3C9640() ; GUID-present gate
```

Eleven patch points total. These are the only functions that read the GUID
value (directly or through `sub_7FF7FC3C9650`).

The DLL starts polling immediately with a cheap probe every 10 ms and patches
as soon as the packed code is decrypted. It verifies every original byte
before writing and refuses to patch if the live build does not match the
analysed dump.

## Loading tracks without restarting

After patching, the DLL waits for the game's initial track scan, then re-runs
the game's own track-list loader (`sub_7FF7FC272460`, RVA `0x2460`) on the
window/render thread. This is the same technique FrostMod uses for its track
refresh. Tracks that were already rejected because of the GUID now appear
without restarting the game.

Press **F9** at any time to force a track refresh (for example after dropping
a new `.pkz` into `mods/tracks`).

## Log

```
%LOCALAPPDATA%\MxBikesGuidBypass\MxBikesGuidBypass.log
```

Expected:

```
verified: sub_7FF7FC3C7920 GUID checks patched
verified: sub_7FF7FC3C9A40 GUID checks patched
ready: sub_7FF7FC3C7920 and sub_7FF7FC3C9A40 are patched
track list: waiting for the game's initial scan...
track list: reload requested
track list: reloading from disk (count before = N)...
track list: reloaded (count after = M)
```

## Build

Requirements: Visual Studio with the C++ workload (project uses the `v145`
toolset; change `PlatformToolset` to `v143` on VS 2022).

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

## Notes

- x64 only.
- Addresses are RVAs from `mxbikes_dump.exe` (`imagebase 0x7FF7FC270000`).
- The on-disk `mxbikes.exe` is packed; the DLL waits for the unpacked code.
- `version.dll` is a normal standalone DLL. It is injected by `Loader.exe`;
  it is not installed into the game folder.
