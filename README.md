# Roblox Offset Dumper

## Supported platforms

- Windows
- macOS

## Usage

- Ensure Roblox is running.
- Run `python main.py`.

## Notes

- On macOS, the tool uses `pgrep -x Roblox` to find the Roblox process and reads logs from the standard `~/Library/Logs/Roblox` location.
- On Windows, it uses the Roblox window handle and `LOCALAPPDATA` log directory.

