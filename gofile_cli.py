import os
import sys
import re
import time
import locale
import hashlib
import json
import argparse
import threading
import signal
import shutil
import mimetypes
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
from rich.tree import Tree
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
console = Console()
stop_event = threading.Event()
prompt_lock = threading.Lock()
proxies = None

VERSION = "v1.2.0"
USER_AGENT = "Mozilla/5.0"
LOCALE_HDR = "en-US"
TOKEN_WINDOW_SEC = 14400
AUTH_FILE = os.path.join(os.path.expanduser("~"), ".gofile_auth.json")

COMMON_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Encoding": "gzip",
    "Accept": "*/*",
    "Connection": "keep-alive",
}

EXTENDED_HEADERS = {
    **COMMON_HEADERS,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
}

# Accept-Encoding: identity for file downloads so Range bytes match exactly
DOWNLOAD_HEADERS_BASE = {
    "User-Agent": USER_AGENT,
    "Accept-Encoding": "identity",
    "Accept": "*/*",
    "Connection": "keep-alive",
}

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
_ctrl_c_count = 0

def signal_handler(sig, frame):
    global _ctrl_c_count
    _ctrl_c_count += 1
    stop_event.set()
    if _ctrl_c_count >= 2:
        os._exit(130)

signal.signal(signal.SIGINT, signal_handler)

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------
I18N = {}
lang = "en"
LOCALES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")

def get_system_lang():
    try:
        code = locale.getlocale()[0]
        if code:
            return code.replace("_", "-")
    except Exception:
        pass
    return "en"

def load_language(target_lang):
    global I18N, lang
    candidates = [target_lang]
    if "-" in target_lang:
        candidates.append(target_lang.split("-")[0])
    candidates.append("en")
    for cand in candidates:
        filepath = os.path.join(LOCALES_DIR, f"{cand}.json")
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    I18N = json.load(f)
                    lang = cand
                    return
            except Exception:
                pass
    # Minimal fallback so keys don't print raw
    I18N = {"dl_task": "Downloading..."}

def init_locale(arg_lang=None):
    load_language(arg_lang if arg_lang else get_system_lang())

def t(key, **kwargs):
    text = I18N.get(key, key)
    try:
        return text.format(**kwargs)
    except Exception:
        return text

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_error(msg):
    try:
        safe = re.sub(r'Bearer\s+[a-zA-Z0-9_\-]+', 'Bearer [REDACTED]', msg)
        safe = re.sub(r'accountToken=[a-zA-Z0-9_\-]+', 'accountToken=[REDACTED]', safe)
        with open("gofile_errors.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {safe}\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# AuthManager  (thread-safe)
# ---------------------------------------------------------------------------
class AuthManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.accounts = []
        self.passwords = {}
        self.load()

    def load(self):
        if os.path.exists(AUTH_FILE):
            try:
                with open(AUTH_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.accounts = data.get("accounts", [])
                    self.passwords = data.get("passwords", {})
            except Exception:
                pass

    def _save_locked(self):
        """Must be called while holding self._lock."""
        tmp = AUTH_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"accounts": self.accounts, "passwords": self.passwords}, f)
            os.replace(tmp, AUTH_FILE)
            if os.name == "posix":
                os.chmod(AUTH_FILE, 0o600)
        except Exception:
            pass

    def save(self):
        with self._lock:
            self._save_locked()

    def add_account(self, token):
        with self._lock:
            if token in self.accounts:
                self.accounts.remove(token)
            self.accounts.insert(0, token)
            self._save_locked()

    def remove_account(self, token):
        with self._lock:
            if token in self.accounts:
                self.accounts.remove(token)
                self._save_locked()

    def add_password(self, content_id, pwd_hash):
        with self._lock:
            self.passwords[content_id] = pwd_hash
            self._save_locked()

    def get_password(self, content_id):
        with self._lock:
            return self.passwords.get(content_id)

auth_manager = AuthManager()

# ---------------------------------------------------------------------------
# Guest token cache (one per execution, never persisted)
# ---------------------------------------------------------------------------
_guest_token_cache = None
_guest_token_lock = threading.Lock()

def get_guest_token():
    global _guest_token_cache
    with _guest_token_lock:
        if _guest_token_cache:
            return _guest_token_cache
        try:
            r = requests.post(
                "https://api.gofile.io/accounts",
                headers=COMMON_HEADERS,
                proxies=proxies,
                timeout=(10, 30),
            )
            if r.status_code == 200:
                _guest_token_cache = r.json().get("data", {}).get("token")
                return _guest_token_cache
        except Exception:
            pass
        return None

# ---------------------------------------------------------------------------
# Website token (X-Website-Token header)
# ---------------------------------------------------------------------------
_cached_token_secret = None

def get_token_secret():
    global _cached_token_secret
    if _cached_token_secret:
        return _cached_token_secret
    fallback = "12af056dacea0b"
    try:
        r = requests.get("https://gofile.io/dist/js/alljs.js", timeout=10)
        if r.status_code == 200:
            match = re.search(r'="([a-zA-Z0-9]{12,20})"', r.text)
            if match:
                candidate = match.group(1)
                # Basic sanity check: should look like a hex-ish or alphanumeric secret
                if len(candidate) >= 12:
                    _cached_token_secret = candidate
                    return _cached_token_secret
    except Exception:
        pass
    log_error("Using fallback token secret – Gofile JS may have changed")
    _cached_token_secret = fallback
    return fallback

def generate_website_token(account_token: str) -> str:
    time_window = str(int(time.time()) // TOKEN_WINDOW_SEC)
    secret = get_token_secret()
    seed = f"{USER_AGENT}::{LOCALE_HDR}::{account_token}::{time_window}::{secret}"
    return hashlib.sha256(seed.encode()).hexdigest()

# ---------------------------------------------------------------------------
# Path sanitization (security: prevent path traversal)
# ---------------------------------------------------------------------------
def sanitize_path_component(name: str) -> str:
    """Remove path separators, leading dots, and Windows-illegal characters."""
    name = re.sub(r'[/\\]', '_', name)
    name = re.sub(r'^\.+', '', name)
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', name)
    name = name.strip('. ')
    return name or "unnamed"

def safe_join(base: str, *parts) -> str:
    """Join path components, ensuring the result stays inside base."""
    clean_parts = [sanitize_path_component(p) for p in parts if p]
    result = os.path.realpath(os.path.join(base, *clean_parts))
    base_real = os.path.realpath(base)
    if not result.startswith(base_real + os.sep) and result != base_real:
        raise ValueError(f"Path traversal detected: {result}")
    return result

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
def fetch_folder(content_id, pwd_hash=None, folder_name=None, interactive=True):
    base_url = f"https://api.gofile.io/contents/{content_id}?cache=true"
    attempts = 0

    while True:
        if stop_event.is_set():
            return None, None
        url = base_url + (f"&password={pwd_hash}" if pwd_hash else "")

        tokens_to_try = auth_manager.accounts.copy()
        guest = get_guest_token()
        if guest and guest not in tokens_to_try:
            tokens_to_try.append(guest)

        if not tokens_to_try:
            console.print(t("err_auth"))
            stop_event.set()
            return None, None

        retry_password = False
        for token in tokens_to_try:
            if stop_event.is_set():
                break
            headers = EXTENDED_HEADERS.copy()
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Website-Token"] = generate_website_token(token)
            headers["X-BL"] = LOCALE_HDR

            try:
                r = requests.get(url, headers=headers, proxies=proxies, timeout=(10, 30))
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "ok":
                        pwd_status = data.get("data", {}).get("passwordStatus")
                        if pwd_status in ["passwordRequired", "passwordWrong"]:
                            if not interactive:
                                return "passwordRequired", token
                            with prompt_lock:
                                attempts += 1
                                display_name = folder_name if folder_name else content_id
                                if attempts >= 4:
                                    skip = Prompt.ask(t("pwd_skip_warn", name=display_name), default="s")
                                    if skip.lower() == "s":
                                        return None, None
                                    attempts = 1
                                if pwd_status == "passwordWrong":
                                    console.print(t("pwd_wrong", name=display_name))
                                else:
                                    console.print(t("pwd_req", name=display_name))
                                pwd = Prompt.ask(t("pwd_ask"))
                                if not pwd.strip():
                                    console.print(t("pwd_skipped", name=display_name))
                                    return None, None
                                pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
                                auth_manager.add_password(content_id, pwd_hash)
                                retry_password = True
                                break

                        # Only persist non-guest tokens
                        if token != _guest_token_cache:
                            auth_manager.add_account(token)

                        folder_data = data["data"]
                        if "children" in folder_data and isinstance(folder_data["children"], dict):
                            items = list(folder_data["children"].values())
                            items.sort(key=lambda x: (x.get("type") != "folder", x.get("name", "").lower()))
                            folder_data["children"] = {item["id"]: item for item in items}

                        return folder_data, token

                    elif "error" in data.get("status", ""):
                        if "auth" in data["status"] or "token" in data["status"]:
                            auth_manager.remove_account(token)
                            continue

                elif r.status_code in [401, 403]:
                    auth_manager.remove_account(token)
                    continue
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 5))
                    console.print(t("rate_limit"))
                    for _ in range(retry_after):
                        if stop_event.is_set():
                            break
                        time.sleep(1)

            except Exception as e:
                log_error(f"fetch_folder {content_id}: {e}")

        if not retry_password:
            return None, None

def find_unloaded_subfolders(node):
    unloaded = []
    if node.get("type") == "folder":
        if "children" in node and node["children"]:
            for child_node in node["children"].values():
                if child_node.get("type") == "folder" and not child_node.get("children"):
                    unloaded.append(child_node)
                elif child_node.get("type") == "folder":
                    unloaded.extend(find_unloaded_subfolders(child_node))
        elif "children" not in node and node.get("id"):
            unloaded.append(node)
    return unloaded

def process_queue(queue, max_workers):
    locked_folders = []
    with console.status(t("concurrent_scan")):
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            while queue:
                if stop_event.is_set():
                    break
                futures = {}
                for sub in queue:
                    sub_id = sub["id"]
                    sub_name = sub.get("name", sub_id)
                    pwd_hash = auth_manager.get_password(sub_id)
                    futures[pool.submit(fetch_folder, sub_id, pwd_hash, sub_name, False)] = sub
                queue.clear()
                for f in as_completed(futures):
                    sub = futures[f]
                    try:
                        sub_data, _ = f.result()
                        if sub_data == "passwordRequired":
                            locked_folders.append(sub)
                        elif sub_data and isinstance(sub_data, dict) and sub_data.get("type") == "folder":
                            sub["children"] = sub_data.get("children", {})
                            new_unloaded = find_unloaded_subfolders(sub)
                            if new_unloaded:
                                queue.extend(new_unloaded)
                    except Exception as e:
                        log_error(f"process_queue: {e}")
    return locked_folders

def load_all_subfolders(node, max_workers):
    unloaded = find_unloaded_subfolders(node)
    if not unloaded:
        return

    console.print(t("subfolders_found", count=len(unloaded)))
    for i, sub in enumerate(unloaded, 1):
        console.print(f"  {i}. {sub.get('name', sub.get('id'))}")

    choice = Prompt.ask(t("subfolder_ask"), default="todas")

    if choice.lower().strip() == "n":
        return

    if choice.lower().strip() not in ("todas", "all", ""):
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(",")]
            selected = [unloaded[i] for i in indices if 0 <= i < len(unloaded)]
            if selected:
                unloaded = selected
            else:
                console.print(t("subfolder_invalid"))
        except Exception:
            console.print(t("subfolder_invalid"))

    queue = unloaded.copy()
    while queue:
        locked_folders = process_queue(queue, max_workers)
        queue = []
        for sub in locked_folders:
            sub_id = sub["id"]
            sub_name = sub.get("name", sub_id)
            sub_data, _ = fetch_folder(sub_id, None, sub_name, interactive=True)
            if sub_data and isinstance(sub_data, dict) and sub_data.get("type") == "folder":
                sub["children"] = sub_data.get("children", {})
                new_unloaded = find_unloaded_subfolders(sub)
                queue.extend(new_unloaded)

# ---------------------------------------------------------------------------
# File utilities
# ---------------------------------------------------------------------------
def verify_md5(file_path, expected_md5):
    if not expected_md5:
        return True
    h = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest() == expected_md5
    except Exception:
        return False

def fix_extensions(node):
    if node.get("type") == "folder":
        for child_node in node.get("children", {}).values():
            fix_extensions(child_node)
    else:
        name = node.get("name", "")
        _, existing_ext = os.path.splitext(name)
        if not existing_ext:
            mtype = node.get("mimetype")
            if mtype:
                override = {"video/quicktime": ".mov", "video/mp4": ".mp4", "audio/mpeg": ".mp3"}
                ext = override.get(mtype) or mimetypes.guess_extension(mtype)
                if ext:
                    node["name"] = name + ext

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"

def generate_file_list(node, current_path="", seen_paths=None):
    if seen_paths is None:
        seen_paths = {}
    if node.get("type") == "folder":
        folder_name = sanitize_path_component(node.get("name", "unnamed"))
        next_path = os.path.join(current_path, folder_name) if current_path else folder_name
        for child_node in node.get("children", {}).values():
            yield from generate_file_list(child_node, next_path, seen_paths)
    else:
        node["rel_path"] = current_path
        safe_name = sanitize_path_component(node.get("name", "unnamed"))
        node["name"] = safe_name
        full_key = os.path.join(current_path, safe_name)
        if full_key in seen_paths:
            base, ext = os.path.splitext(safe_name)
            short_id = node.get("id", "dup")[:6]
            safe_name = f"{base}_{short_id}{ext}"
            node["name"] = safe_name
            full_key = os.path.join(current_path, safe_name)
        seen_paths[full_key] = True
        yield node

# ---------------------------------------------------------------------------
# Download engine
# ---------------------------------------------------------------------------
def download_file(file_info, dest_folder, progress, token, overall_task):
    if stop_event.is_set():
        return ("skipped", "", 0, file_info)

    filename = file_info["name"]
    link = file_info["link"]
    size = file_info.get("size", 0)
    expected_md5 = file_info.get("md5")
    rel_path = file_info.get("rel_path", "")

    try:
        final_dir = safe_join(dest_folder, *rel_path.split(os.sep)) if rel_path else dest_folder
    except ValueError as e:
        log_error(f"Path traversal blocked: {e}")
        return ("failed", "", 0, file_info)

    os.makedirs(final_dir, exist_ok=True)
    final_path = os.path.join(final_dir, filename)
    part_path = final_path + ".part"

    display_name = (os.path.join(rel_path, filename) if rel_path else filename).replace("\\", "/")
    short_disp = display_name if len(display_name) <= 30 else "..." + display_name[-27:]

    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    task_id = progress.add_task(t("dl_task"), display_name=t("waiting", name=short_disp), total=size)

    for attempt in range(3):
        if stop_event.is_set():
            progress.update(task_id, visible=False)
            return ("skipped", ext, 0, file_info)

        # Reset headers each attempt – never carry over Range from previous attempt
        headers = DOWNLOAD_HEADERS_BASE.copy()
        if token:
            headers["Cookie"] = f"accountToken={token}"
        headers["Referer"] = link
        headers["Origin"] = link

        mode = "wb"
        downloaded = 0

        if os.path.exists(part_path):
            downloaded = os.path.getsize(part_path)
            if size > 0 and 0 < downloaded < size:
                headers["Range"] = f"bytes={downloaded}-"
                mode = "ab"

        progress.update(task_id, completed=downloaded, display_name=f"[cyan]⬇ {short_disp}[/cyan]")

        try:
            with requests.get(link, headers=headers, stream=True, proxies=proxies, timeout=(10, 30)) as r:
                # Detect CDN HTML block (token/IP issue)
                if "text/html" in r.headers.get("Content-Type", "") and size > 1024 * 1024:
                    auth_manager.remove_account(token)
                    raise Exception("Token expired or IP blocked by CDN")

                # If we asked for Range but server returned 200 (ignored Range), start fresh
                if mode == "ab" and r.status_code == 200:
                    mode = "wb"
                    downloaded = 0

                r.raise_for_status()

                with open(part_path, mode) as f:
                    for chunk in r.iter_content(chunk_size=1024 * 256):
                        if stop_event.is_set():
                            progress.update(task_id, visible=False)
                            return ("skipped", ext, 0, file_info)
                        if chunk:
                            f.write(chunk)
                            progress.update(task_id, advance=len(chunk))

            # Verify MD5 before committing
            if size > 0:
                progress.update(task_id, display_name=f"[yellow]⏳ MD5... {short_disp}[/yellow]")
                if not verify_md5(part_path, expected_md5):
                    os.remove(part_path)
                    raise Exception("MD5 Hash Mismatch – retrying")

            # Atomic rename on success
            if os.path.exists(final_path):
                os.remove(final_path)
            os.rename(part_path, final_path)

            progress.update(task_id, visible=False)
            progress.update(overall_task, advance=size)
            return ("success", ext, size, file_info)

        except Exception as e:
            err_msg = str(e)
            if attempt < 2:
                backoff = 2 ** (attempt + 1)
                progress.update(task_id, display_name=f"[yellow]⏳ Reintentando {backoff}s... {short_disp}[/yellow]")
                time.sleep(backoff)
            else:
                progress.update(task_id, visible=False)
                log_error(f"Failed: {display_name} – {err_msg}")
                progress.update(overall_task, advance=size)
                return ("failed", ext, size, file_info)

    progress.update(task_id, visible=False)
    return ("failed", ext, size, file_info)

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def print_banner():
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", style="bold cyan")
    grid.add_column(justify="right", style="dim")
    grid.add_row("Gofile Downloader CLI", VERSION)
    grid.add_row("High-performance multi-threaded client", "Cross-Platform")
    console.print(Panel(grid, border_style="blue", padding=(1, 2)))

def make_progress_bar(**kwargs):
    return Progress(
        TextColumn("{task.fields[display_name]}", justify="right"),
        BarColumn(bar_width=None, complete_style="green", finished_style="bold green"),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        console=console,
        expand=True,
        **kwargs,
    )

def run_download_phase(files, label, color, base_dest, used_token, stats, workers):
    """
    Execute one download phase and return (success_list, failed_list).
    Updates `stats` in place.
    """
    if not files:
        return [], []

    total_bytes = sum(f.get("size", 0) for f in files)
    tot = len(files)
    failed_files = []

    def header_text():
        dn = stats["success"] + len(failed_files)
        fc = len(failed_files)
        fail_txt = f" | [red]Fallidos: {fc}[/red]" if fc > 0 else ""
        return f"[bold {color}]{label}: {tot} | Descargados: {stats['success']}{fail_txt} | Restantes: {tot - dn}[/bold {color}]"

    prog = make_progress_bar()
    with prog:
        overall = prog.add_task("main", display_name=header_text(), total=total_bytes)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = []
            for f in files:
                if stop_event.is_set():
                    break
                futs.append(pool.submit(download_file, f, base_dest, prog, used_token, overall))

            for fut in as_completed(futs):
                try:
                    res = fut.result()
                    if not res:
                        continue
                    status, ext, size, f_info = res
                    if not ext:
                        ext = "unknown"
                    if status == "success":
                        stats["success"] += 1
                        stats["total_size"] += size
                        stats["types"].setdefault(ext, {"count": 0, "size": 0})
                        stats["types"][ext]["count"] += 1
                        stats["types"][ext]["size"] += size
                    elif status == "skipped":
                        stats["skipped"] += 1
                    else:
                        failed_files.append(f_info)
                    prog.update(overall, display_name=header_text())
                except Exception as e:
                    log_error(f"Future error: {e}")

    # Mark definitive failures
    stats["failed"] += len(failed_files)
    return [], failed_files

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    global proxies

    # Parse lang early for i18n in help strings
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-l", "--lang", default=None)
    pre_args, _ = pre.parse_known_args()
    init_locale(pre_args.lang)

    parser = argparse.ArgumentParser(description=t("help_desc"), add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("url", nargs="?", default=None, help=t("help_url"))
    parser.add_argument("-p", "--password", default=None, help=t("help_pwd"))
    parser.add_argument("-t", "--token", default=None, help=t("help_token"))
    parser.add_argument("-d", "--dest", default=os.getcwd(), help=t("help_dest"))
    parser.add_argument("-w", "--workers", type=int, default=2, help=t("help_workers"))
    parser.add_argument("-l", "--lang", default=None, help=t("help_lang"))
    parser.add_argument("-e", "--ext", default=None, help=t("help_ext"))
    parser.add_argument("-z", "--zip", action="store_true", help=t("help_zip"))
    parser.add_argument("--proxy", default=None, help=t("help_proxy"))
    parser.add_argument("--export", default=None, help=t("help_export"))
    parser.add_argument("--show-token", action="store_true", help="Show saved tokens (masked)")
    args = parser.parse_args()

    # --show-token
    if args.show_token:
        print_banner()
        tokens = auth_manager.accounts
        if tokens:
            console.print("[bold cyan]Saved tokens:[/bold cyan]")
            for i, tkn in enumerate(tokens, 1):
                masked = tkn[:4] + "..." + tkn[-4:] if len(tkn) > 8 else "****"
                console.print(f"  {i}. {masked}")
        else:
            console.print("[yellow]No tokens saved.[/yellow]")
        sys.exit(0)

    # --token: inject before anything else
    if args.token:
        auth_manager.add_account(args.token)
        console.print(f"[bold green]Token added/updated.[/bold green]")

    # --help
    if args.help:
        print_banner()
        parser.print_help()
        sys.exit(0)

    # No URL
    if not args.url:
        print_banner()
        console.print(t("help_no_url"))
        console.print(t("help_usage"))
        console.print(t("help_usage_cmd"))
        console.print(t("help_example_title"))
        console.print(t("help_example_cmd"))
        console.print(t("help_more"))
        sys.exit(1)

    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    print_banner()

    # Parse content_id safely
    parsed = urlparse(args.url)
    path_parts = parsed.path.split("/d/")
    if len(path_parts) < 2:
        console.print(t("err_url"))
        sys.exit(1)
    content_id = path_parts[1].split("/")[0].split("?")[0]

    pwd_hash = None
    if args.password:
        pwd_hash = hashlib.sha256(args.password.encode()).hexdigest()
        auth_manager.add_password(content_id, pwd_hash)
    else:
        pwd_hash = auth_manager.get_password(content_id)

    with console.status(t("fetching")):
        data, used_token = fetch_folder(content_id, pwd_hash)

    if not data:
        console.print(t("err_conn"))
        sys.exit(1)

    load_all_subfolders(data, max_workers=args.workers)
    fix_extensions(data)

    # Build file iterator
    seen = {}
    if data.get("type") == "folder":
        files_iterator = (
            f
            for child_node in data.get("children", {}).values()
            for f in generate_file_list(child_node, "", seen)
        )
    else:
        data["rel_path"] = ""
        files_iterator = iter([data])

    if args.ext:
        allowed = [e.strip().lower() for e in args.ext.split(",")]
        allowed = [e if e.startswith(".") else "." + e for e in allowed]
        files_iterator = (f for f in files_iterator if any(f["name"].lower().endswith(e) for e in allowed))

    files_to_download = list(files_iterator)

    if not files_to_download:
        console.print(t("no_files"))
        sys.exit(0)

    if args.export:
        export_data = [f["link"] for f in files_to_download]
        with open(args.export, "w", encoding="utf-8") as f:
            if args.export.endswith(".json"):
                json.dump(export_data, f, indent=4)
            else:
                f.write("\n".join(export_data))
        console.print(t("export_done", file=args.export))
        sys.exit(0)

    folder_name = sanitize_path_component(data.get("name", "Gofile_Download"))
    base_dest = os.path.join(args.dest, folder_name)

    # Conflict check
    if os.path.exists(base_dest) and os.path.isdir(base_dest):
        id_file = os.path.join(base_dest, ".gofile_id")
        conflict = False
        if os.path.exists(id_file):
            try:
                with open(id_file, "r") as f:
                    if f.read().strip() != content_id:
                        conflict = True
            except Exception:
                pass
        elif os.listdir(base_dest):
            conflict = True

        if conflict:
            console.print(t("conflict_warn", name=folder_name))
            new_name = Prompt.ask(t("conflict_ask"))
            folder_name = sanitize_path_component(new_name.strip()) if new_name.strip() else f"{folder_name}_{content_id[:6]}"
            if not new_name.strip():
                console.print(t("conflict_auto", name=folder_name))
            base_dest = os.path.join(args.dest, folder_name)

    os.makedirs(base_dest, exist_ok=True)

    # Write .gofile_id marker
    id_file = os.path.join(base_dest, ".gofile_id")
    if not os.path.exists(id_file) or open(id_file).read().strip() != content_id:
        try:
            with open(id_file, "w") as f:
                f.write(content_id)
            if os.name == "nt":
                ctypes.windll.kernel32.SetFileAttributesW(id_file, 2)
        except Exception:
            pass

    summary_stats = {"total_size": 0, "types": {}, "failed": 0, "success": 0, "skipped": 0}

    # ------------------------------------------------------------------
    # Phase 0: Pre-verification (multi-threaded MD5 check)
    # ------------------------------------------------------------------
    console.print(f"[yellow]Checking {len(files_to_download)} local files...[/yellow]")
    real_files = []

    def verify_local_file(f):
        fn = f["name"]
        rp = f.get("rel_path", "")
        try:
            fd = safe_join(base_dest, *rp.split(os.sep)) if rp else base_dest
        except ValueError:
            return ("download", f)
        fp = os.path.join(fd, fn)
        sz = f.get("size", 0)
        if os.path.exists(fp):
            if os.path.getsize(fp) == sz and sz > 0 and verify_md5(fp, f.get("md5")):
                return ("skipped", f)
            elif os.path.exists(fp):
                os.remove(fp)
        # Also clean stale .part file if it's corrupted beyond resume
        part = fp + ".part"
        if os.path.exists(part) and sz > 0:
            if os.path.getsize(part) >= sz:
                os.remove(part)
        return ("download", f)

    with Progress(
        TextColumn("[bold yellow]Verifying local files...[/bold yellow]"),
        BarColumn(complete_style="yellow"),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        TextColumn("{task.completed}/{task.total} files"),
        console=console,
        transient=True,
    ) as vp:
        vtask = vp.add_task("verify", total=len(files_to_download))
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = [pool.submit(verify_local_file, f) for f in files_to_download]
            for fut in as_completed(futs):
                try:
                    status, f = fut.result()
                    if status == "skipped":
                        summary_stats["skipped"] += 1
                    else:
                        real_files.append(f)
                except Exception as e:
                    log_error(f"verify_local_file error: {e}")
                vp.update(vtask, advance=1)

    files_to_download = real_files

    # ------------------------------------------------------------------
    # Phase 0.5: Build compact tree of files to download
    # ------------------------------------------------------------------
    if files_to_download:
        tree = Tree(t("tree_root") if "tree_root" in I18N else "[bold]Files to download[/bold]")
        folder_counts: dict = {}

        def add_to_tree(node, parent, parts, path=""):
            if not parts:
                folder_counts[path] = folder_counts.get(path, 0) + 1
                n = folder_counts[path]
                if n <= 5:
                    parent.add(f"[green]{node['name']}[/green] ({format_size(node.get('size', 0))})")
                elif n == 6:
                    parent.add("[dim]... (and more files)[/dim]")
                return
            part = parts[0]
            key = os.path.join(path, part)
            branch = next(
                (c for c in parent.children if getattr(c, "label", "") == f"[bold blue]{part}[/bold blue]"),
                None,
            )
            if not branch:
                branch = parent.add(f"[bold blue]{part}[/bold blue]")
            add_to_tree(node, branch, parts[1:], key)

        for f in files_to_download:
            rp = f.get("rel_path", "")
            parts = [p for p in rp.split(os.sep) if p] if rp else []
            add_to_tree(f, tree, parts)

        console.print(tree)
        console.print("")

    if not files_to_download:
        console.print("[bold green]All files already downloaded and verified![/bold green]")
        sys.exit(0)

    console.print(t("start_dl", count=len(files_to_download), dest=base_dest))
    global_start_time = time.time()

    # ------------------------------------------------------------------
    # Phase 1: Main download
    # ------------------------------------------------------------------
    _, failed_files = run_download_phase(
        files_to_download, "Files", "yellow", base_dest, used_token, summary_stats, args.workers
    )

    # ------------------------------------------------------------------
    # Phase 2: Retry failed files once
    # ------------------------------------------------------------------
    if failed_files and not stop_event.is_set():
        console.print(f"\n[yellow]Retrying {len(failed_files)} failed files in 3 seconds...[/yellow]")
        time.sleep(3)
        # Remove from failed count (they'll be re-counted in run_download_phase)
        summary_stats["failed"] -= len(failed_files)
        _, still_failed = run_download_phase(
            failed_files, "Retry", "yellow", base_dest, used_token, summary_stats, args.workers
        )
        if still_failed:
            console.print(f"\n[bold red]Could not download {len(still_failed)} files:[/bold red]")
            for f in still_failed:
                console.print(f"  [red]✗[/red] {f.get('name', '?')}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    if not stop_event.is_set():
        if args.zip and summary_stats["failed"] == 0:
            console.print(t("zipping", dest=base_dest))
            shutil.make_archive(base_dest, "zip", base_dest)
            shutil.rmtree(base_dest)
            console.print(t("zip_done"))

        console.print(t("summary_title"))
        console.print(t("sum_success", count=summary_stats["success"]))
        console.print(t("sum_skipped", count=summary_stats["skipped"]))
        if summary_stats["failed"] > 0:
            console.print(f"[red]{t('sum_failed', count=summary_stats['failed'])}[/red]")

        elapsed = time.time() - global_start_time
        avg_speed = (
            format_size(summary_stats["total_size"] / elapsed) + "/s" if elapsed > 0 else "0 B/s"
        )
        console.print(t("sum_total", size=format_size(summary_stats["total_size"])))
        console.print(f"  [cyan]Total time:[/cyan] {elapsed:.1f}s  (avg {avg_speed})\n")

        if summary_stats["types"]:
            table = Table(show_header=True, header_style="bold yellow", box=None)
            table.add_column(t("table_qty"), justify="right")
            table.add_column(t("table_type"))
            table.add_column(t("table_size"), justify="right")
            for ext, d in sorted(summary_stats["types"].items(), key=lambda x: x[1]["size"], reverse=True):
                table.add_row(str(d["count"]), ext, format_size(d["size"]))
            console.print(table)

        exit_code = 1 if summary_stats["failed"] > 0 else 0
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
