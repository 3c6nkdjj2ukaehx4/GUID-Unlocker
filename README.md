# MX Bikes GUID bypass

Patches all GUID comparisons used by the MX Bikes `.pkz` loader so archives
(tracks, bikes, etc.) load regardless of which GUID they were locked to.

## Files

```
bin\x64\Release\Loader\Loader.exe       injector
bin\x64\Release\Loader\version.dll      bypass DLL
bin\x64\Release\PkzUnpacker\PkzUnpacker.exe  .pkz decryptor/extractor
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

## PkzUnpacker

`PkzUnpacker.exe` decrypts and extracts `.pkz` archives that carry a GUID
lock. The lock is reported but never enforced, so a locked archive can be
opened on any machine.

### Interactive menu

Run the executable with no arguments (or double-click it):

```powershell
.\PkzUnpacker.exe
```

It finds the MX Bikes mods folder automatically and lists only `.pkz` files
that carry a non-zero GUID lock, across every category (`tracks`, `bikes`,
`rider`/clothing, `tyres`, `misc`, ...):

```
Found 7 GUID-locked .pkz files
  tracks       7
```

Menu options:

```
1) Decrypt ONE GUID-locked archive -> keep in game mods folder
2) Decrypt ONE GUID-locked archive -> output folder next to this app
3) Decrypt ALL GUID-locked archives -> keep in game mods folder
4) Decrypt ALL GUID-locked archives -> output folder next to this app
5) Show found archives
0) Exit
```

- **Keep in game mods folder** extracts the archive next to the original
  `.pkz`, so the game sees the unpacked mod folder.
- **Output folder next to this app** writes to `output\<category>\` beside
  `PkzUnpacker.exe`.
- Options 1/2 let you filter the archive list by name before picking one.
- Existing files are skipped unless you answer `y` to the overwrite prompt.
- After a successful decrypt, the 16-byte GUID is cleared from the source
  `.pkz` trailer, so the archive is permanently unlocked.
- Plain ZIPs and encrypted archives whose GUID is all zero are not shown in
  the menu; they can still be handled with the command line if needed.

The mods folder is detected from the known Documents folder, `%OneDrive%`,
and the Steam install. Set the `MXBIKES_MODS` environment variable to a mods
folder to override the automatic detection.

### Command line

```powershell
# extract next to the archive (creates .\<archive-name>\)
PkzUnpacker.exe "C:\path\to\track.pkz"

# extract to a specific folder
PkzUnpacker.exe "C:\path\to\track.pkz" -o D:\extracted

# list contents without extracting
PkzUnpacker.exe "C:\path\to\track.pkz" --list

# process every .pkz in a folder (add -r for subfolders)
PkzUnpacker.exe "C:\path\to\mods\tracks" -o D:\tracks -r

# also clear the GUID lock in the source archive after extracting it
PkzUnpacker.exe "C:\path\to\track.pkz" -o D:\extracted --remove-guid
```

GUID-locked archives are standard ZIPs whose central directory and local
headers/file names are wrapped in RC4, with the key and 16-byte GUID stored in
a trailer at the end of the file. File data is ordinary ZIP `stored` or
`deflate`. Both trailer layouts are supported:

| Magic | Trailer | Layout |
| --- | --- | --- |
| `LOCK` | 62 bytes | current mod-tool output |
| `LCK3` | 56 bytes | legacy |

Plain, unencrypted `.pkz` files (the stock game archives) are also accepted.
Every extracted file is CRC-checked and removed again if the check fails.

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
