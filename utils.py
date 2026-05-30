import os
import re
import platform


def _get_default_log_paths():
    system = platform.system()

    if system == "Windows":
        localappdata = os.getenv("LOCALAPPDATA")
        if localappdata:
            return [os.path.join(localappdata, "Roblox", "logs")]

    if system == "Darwin":
        return [
            os.path.expanduser("~/Library/Logs/Roblox"),
            os.path.expanduser("~/Library/Application Support/Roblox/logs"),
        ]

    return [os.path.expanduser("~/Library/Logs/Roblox")]


def _find_existing_path(paths):
    for path in paths:
        if os.path.isdir(path):
            return path
    return paths[0]


RBXPath = _find_existing_path(_get_default_log_paths())


def find_rizz(directory):
    if not os.path.isdir(directory):
        raise ValueError(f"{directory} is not valid directory")

    files = [os.path.join(directory, file) for file in os.listdir(directory)]
    files = [file for file in files if os.path.isfile(file)]

    if not files:
        return None

    latest_file = max(files, key=os.path.getmtime)
    return latest_file


def get_rizz_level(file_path, pattern):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    matches = re.findall(pattern, content)
    return matches


def GetRenderViewFromLog():
    latest_log = find_rizz(RBXPath)
    if latest_log:
        try:
            skibidi = r"SurfaceController\[_:1\]::initialize view\((.*?)\)"
            sigmas_remaining = get_rizz_level(latest_log, skibidi)
            if sigmas_remaining:
                for sigma_remained in sigmas_remaining:
                    RenderView = int(sigma_remained, 16)
                    print("[~] RenderView: " + hex(RenderView))
                    return RenderView
        except FileNotFoundError:
            return 0
        except Exception:
            return 0

    return 0
