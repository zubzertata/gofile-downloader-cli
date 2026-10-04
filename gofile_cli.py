import os
import sys
import time
import hashlib
import json
import argparse
import threading
import signal
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
from rich.tree import Tree
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
stop_event = threading.Event()
prompt_lock = threading.Lock()
proxies = None

import locale

def get_system_lang():
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=DeprecationWarning)
            lang_code, _ = locale.getdefaultlocale()
            if lang_code:
                return lang_code.replace('_', '-')
    except: pass
    return "en"

I18N = {}
lang = "en"
LOCALES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")

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
            except: pass
            
    # Fallback if somehow nothing exists
    I18N = {"dl_task": "Downloading..."}

def init_locale(arg_lang=None):
    if arg_lang:
        load_language(arg_lang)
    else:
        load_language(get_system_lang())

def t(key, **kwargs):
    text = I18N.get(key, key)
    return text.format(**kwargs)

USER_AGENT = "Mozilla/5.0"
LOCALE = "en-US"
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

def signal_handler(sig, frame):
    console.print(t("exit_msg"))
    stop_event.set()
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def log_error(msg):
    try:
        import re
        safe_msg = re.sub(r'Bearer\s+[a-zA-Z0-9_-]+', 'Bearer [REDACTED]', msg)
        safe_msg = re.sub(r'accountToken=[a-zA-Z0-9_-]+', 'accountToken=[REDACTED]', safe_msg)
        with open("gofile_errors.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {safe_msg}\n")
    except: pass

class AuthManager:
    def __init__(self):
        self.accounts = []
        self.passwords = {}
        self.load()

    def load(self):
        if os.path.exists(AUTH_FILE):
            try:
                with open(AUTH_FILE, "r") as f:
                    data = json.load(f)
                    self.accounts = data.get("accounts", [])
                    self.passwords = data.get("passwords", {})
            except: pass

    def save(self):
        try:
            if os.name == 'nt' and os.path.exists(AUTH_FILE):
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(AUTH_FILE, 128) # Unhide
            with open(AUTH_FILE, "w") as f:
                json.dump({"accounts": self.accounts, "passwords": self.passwords}, f)
            if os.name == 'posix':
                os.chmod(AUTH_FILE, 0o600)
            elif os.name == 'nt':
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(AUTH_FILE, 2) # Hide
        except Exception:
            pass

    def add_account(self, token):
        if token in self.accounts:
            self.accounts.remove(token)
        self.accounts.insert(0, token)
        self.save()

    def remove_account(self, token):
        if token in self.accounts:
            self.accounts.remove(token)
            self.save()

    def add_password(self, content_id, pwd_hash):
        self.passwords[content_id] = pwd_hash
        self.save()

    def get_password(self, content_id):
        return self.passwords.get(content_id)

auth_manager = AuthManager()

_cached_token_secret = None

def get_token_secret():
    global _cached_token_secret
    if _cached_token_secret:
        return _cached_token_secret
        
    fallback = "12af056dacea0b"
    try:
        r = requests.get("https://gofile.io/dist/js/alljs.js", timeout=10)
        if r.status_code == 200:
            import re
            match = re.search(r'="([a-zA-Z0-9]{12,20})"', r.text)
            if match:
                _cached_token_secret = match.group(1)
                return _cached_token_secret
    except: pass
    _cached_token_secret = fallback
    return fallback

def generate_website_token(account_token: str) -> str:
    time_window = str(int(time.time()) // TOKEN_WINDOW_SEC)
    secret = get_token_secret()
    token_seed = f"{USER_AGENT}::{LOCALE}::{account_token}::{time_window}::{secret}"
    return hashlib.sha256(token_seed.encode()).hexdigest()

def get_guest_token():
    try:
        r = requests.post("https://api.gofile.io/accounts", headers=COMMON_HEADERS, proxies=proxies, timeout=(10, 30))
        if r.status_code == 200:
            return r.json().get("data", {}).get("token")
    except: pass
    return None

def fetch_folder(content_id, pwd_hash=None, folder_name=None, interactive=True):
    base_url = f"https://api.gofile.io/contents/{content_id}?cache=true"
    attempts = 0
    
    while True:
        if stop_event.is_set(): return None, None
        url = base_url
        if pwd_hash:
            url += f"&password={pwd_hash}"
        
        tokens_to_try = auth_manager.accounts.copy()
        guest = get_guest_token()
        if guest and guest not in tokens_to_try:
            tokens_to_try.append(guest)
            
        if not tokens_to_try:
            console.print(t("err_auth"))
            os._exit(1)
            
        retry_password = False
        for token in tokens_to_try:
            if stop_event.is_set(): break
            headers = EXTENDED_HEADERS.copy()
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Website-Token"] = generate_website_token(token)
            headers["X-BL"] = LOCALE
            
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
                                    if skip.lower() == 's':
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
                    console.print(t("rate_limit"))
                    for _ in range(5):
                        if stop_event.is_set(): break
                        time.sleep(1)
            except Exception: pass
            
        if not retry_password:
            return None, None

def find_unloaded_subfolders(node):
    unloaded = []
    if node.get("type") == "folder":
        if "children" in node and node["children"]:
            for child_id, child_node in node["children"].items():
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
                if stop_event.is_set(): break
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
                    except Exception:
                        pass
    return locked_folders

def load_all_subfolders(node, max_workers):
    unloaded = find_unloaded_subfolders(node)
    if not unloaded:
        return
        
    console.print(t("subfolders_found", count=len(unloaded)))
    for i, sub in enumerate(unloaded, 1):
        console.print(f"  {i}. {sub.get('name', sub.get('id'))}")
        
    choice = Prompt.ask(t("subfolder_ask"), default="todas")
    
    if choice.lower().strip() == 'n':
        return
        
    if choice.lower().strip() != 'todas':
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            unloaded = [unloaded[i] for i in indices if 0 <= i < len(unloaded)]
        except Exception:
            console.print(t("subfolder_invalid"))

    queue = unloaded.copy()
    
    while queue:
        locked_folders = process_queue(queue, max_workers)
        
        for sub in locked_folders:
            sub_id = sub["id"]
            sub_name = sub.get("name", sub_id)
            sub_data, _ = fetch_folder(sub_id, None, sub_name, interactive=True)
            if sub_data and isinstance(sub_data, dict) and sub_data.get("type") == "folder":
                sub["children"] = sub_data.get("children", {})
                new_unloaded = find_unloaded_subfolders(sub)
                if new_unloaded:
                    queue.extend(new_unloaded)

def verify_md5(file_path, expected_md5):
    if not expected_md5:
        return True
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest() == expected_md5
    except Exception:
        return False

def fix_extensions(node):
    import mimetypes
    if node.get("type") == "folder":
        for child_id, child_node in node.get("children", {}).items():
            fix_extensions(child_node)
    else:
        name = node.get("name", "")
        if "." not in name[-10:]:
            mtype = node.get("mimetype")
            if mtype:
                ext = mimetypes.guess_extension(mtype)
                if mtype == "video/quicktime": ext = ".mov"
                if mtype == "video/mp4": ext = ".mp4"
                if mtype == "audio/mpeg": ext = ".mp3"
                if ext:
                    node["name"] = name + ext

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/1024**2:.2f} MB"
    else:
        return f"{size_bytes/1024**3:.2f} GB"

def build_tree_ui(node, tree):
    if node.get("type") == "folder":
        branch = tree.add(f"[bold blue]📁 {node['name']}[/bold blue]")
        file_count = 0
        MAX_FILES = 15
        children = list(node.get("children", {}).values())
        for child in children:
            if child.get("type") == "folder":
                build_tree_ui(child, branch)
            else:
                file_count += 1
                if file_count <= MAX_FILES:
                    size_str = format_size(child.get('size', 0))
                    branch.add(f"[green]📄 {child['name']}[/green] ({size_str})")
        if file_count > MAX_FILES:
            branch.add(t("more_files", count=file_count - MAX_FILES))
    else:
        size_str = format_size(node.get('size', 0))
        tree.add(f"[green]📄 {node['name']}[/green] ({size_str})")

def generate_file_list(node, current_path=""):
    if node.get("type") == "folder":
        for child_id, child_node in node.get("children", {}).items():
            yield from generate_file_list(child_node, os.path.join(current_path, node["name"]))
    else:
        node["rel_path"] = current_path
        yield node

def download_file(file_info, dest_folder, progress, token, overall_task):
    if stop_event.is_set(): return ("skipped", "", 0, file_info)
    
    filename = file_info["name"]
    link = file_info["link"]
    size = file_info.get("size", 0)
    expected_md5 = file_info.get("md5")
    
    rel_path = file_info.get("rel_path", "")
    final_dir = os.path.join(dest_folder, rel_path)
    os.makedirs(final_dir, exist_ok=True)
    
    final_path = os.path.join(final_dir, filename)
    display_name = os.path.join(rel_path, filename).replace("\\", "/")
    short_disp = display_name if len(display_name) <= 30 else "..." + display_name[-27:]
    task_id = progress.add_task(t("dl_task"), display_name=t("waiting", name=short_disp), total=size)
    
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    
    headers = EXTENDED_HEADERS.copy()
    if token:
        headers["Cookie"] = f"accountToken={token}"
    headers["Referer"] = link
    headers["Origin"] = link
    
    for attempt in range(3):
        if stop_event.is_set(): return ("skipped", "", 0, file_info)
        
        mode = "wb"
        downloaded = 0
        if os.path.exists(final_path):
            downloaded = os.path.getsize(final_path)
            if size > 0 and downloaded < size:
                headers["Range"] = f"bytes={downloaded}-"
                mode = "ab"
            elif size > 0 and downloaded >= size:
                os.remove(final_path)
                downloaded = 0
                mode = "wb"

        progress.update(task_id, completed=downloaded, display_name=f"[cyan]⬇ {short_disp}[/cyan]")
        
        try:
            with requests.get(link, headers=headers, stream=True, proxies=proxies, timeout=(10, 30)) as r:
                if "text/html" in r.headers.get("Content-Type", "") and size > 1024 * 1024:
                    auth_manager.remove_account(token)
                    raise Exception("Token expired or IP blocked by CDN")
                    
                r.raise_for_status()
                with open(final_path, mode) as f:
                    for chunk in r.iter_content(chunk_size=1024*256):
                        if stop_event.is_set():
                            return ("skipped", ext, 0)
                        if chunk:
                            f.write(chunk)
                            progress.update(task_id, advance=len(chunk))
            
            if size > 0:
                progress.update(task_id, display_name=f"[yellow]⏳ Verificando MD5... {display_name}[/yellow]")
                if not verify_md5(final_path, expected_md5):
                    raise Exception("MD5 Hash Mismatch (Corrupt file)")
                
            progress.update(task_id, visible=False)
            progress.update(overall_task, advance=size)
            return ("success", ext, size, file_info)
            
        except Exception as e:
            if attempt < 2:
                backoff = 2 ** (attempt + 1)
                progress.update(task_id, display_name=f"[yellow]⏳ Reintentando en {backoff}s... {short_disp}[/yellow]")
                time.sleep(backoff)
            else:
                progress.update(task_id, visible=False)
                err_msg = str(e)
                
                log_error(f"Failed to download {display_name}: {err_msg}")
                progress.update(overall_task, advance=size)
                return ("failed", ext, size, file_info)
                
    return ("failed", ext, size, file_info)

def print_banner():
    from rich.table import Table
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", style="bold cyan")
    grid.add_column(justify="right", style="dim")
    grid.add_row("Gofile Downloader CLI", "v1")
    grid.add_row("High-performance multi-threaded client", "Cross-Platform")
    console.print(Panel(grid, border_style="blue", padding=(1, 2)))

def main():
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    global proxies
    
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument("-l", "--lang", default=None)
    temp_args, _ = temp_parser.parse_known_args()
    init_locale(temp_args.lang)

    parser = argparse.ArgumentParser(description=t("help_desc"), add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("url", nargs='?', help=t("help_url"), default=None)
    parser.add_argument("-p", "--password", help=t("help_pwd"), default=None)
    parser.add_argument("-t", "--token", help=t("help_token"), default=None)
    parser.add_argument("-d", "--dest", help=t("help_dest"), default=os.getcwd())
    parser.add_argument("-w", "--workers", help=t("help_workers"), type=int, default=2)
    parser.add_argument("-l", "--lang", help=t("help_lang"), default=None)
    parser.add_argument("-e", "--ext", help=t("help_ext"), default=None)
    parser.add_argument("-z", "--zip", help=t("help_zip"), action="store_true")
    parser.add_argument("--proxy", help=t("help_proxy"), default=None)
    parser.add_argument("--export", help=t("help_export"), default=None)
    parser.add_argument("--show-token", help="Show saved tokens", action="store_true")
    
    args = parser.parse_args()
    
    if args.show_token:
        print_banner()
        tokens = auth_manager.accounts
        if tokens:
            console.print("[bold cyan]Tokens guardados actualmente:[/bold cyan]")
            for i, tkn in enumerate(tokens, 1):
                console.print(f"  {i}. {tkn}")
        else:
            console.print("[yellow]No hay tokens guardados.[/yellow]")
        sys.exit(0)
        
    if args.token:
        auth_manager.add_account(args.token)
        console.print(f"[bold green]Token manual añadido/actualizado exitosamente:[/bold green] {args.token}")
    
    if args.help:
        print_banner()
        parser.print_help()
        sys.exit(0)
        
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
    
    if "/d/" not in args.url:
        console.print(t("err_url"))
        os._exit(1)
        
    content_id = args.url.split("/d/")[-1].split("/")[0]
    pwd_hash = None
    
    if args.password:
        pwd_hash = hashlib.sha256(args.password.encode()).hexdigest()
        auth_manager.add_password(content_id, pwd_hash)
    else:
        pwd_hash = auth_manager.get_password(content_id)
        
    if args.token:
        auth_manager.add_account(args.token)
        
    with console.status(t("fetching")):
        data, used_token = fetch_folder(content_id, pwd_hash)
        
    if not data:
        console.print(t("err_conn"))
        os._exit(1)
        
    load_all_subfolders(data, max_workers=args.workers)
    fix_extensions(data)
        
    files_iterator = []
    if data.get("type") == "folder":
        def yield_children():
            for child_id, child_node in data.get("children", {}).items():
                yield from generate_file_list(child_node, "")
        files_iterator = yield_children()
    else:
        data["rel_path"] = ""
        files_iterator = [data]
    
    if args.ext:
        allowed = [e.strip().lower() for e in args.ext.split(",")]
        allowed = [e if e.startswith(".") else "." + e for e in allowed]
        files_iterator = (f for f in files_iterator if any(f["name"].lower().endswith(ext) for ext in allowed))
        
    files_to_download = list(files_iterator)
        
    if not files_to_download:
        console.print(t("no_files"))
        os._exit(0)
        
    if args.export:
        export_data = [f["link"] for f in files_to_download]
        with open(args.export, "w") as f:
            if args.export.endswith(".json"):
                json.dump(export_data, f, indent=4)
            else:
                f.write("\n".join(export_data))
        console.print(t("export_done", file=args.export))
        os._exit(0)
    
    folder_name = data.get("name", "Gofile_Download")
    base_dest = os.path.join(args.dest, folder_name)
    
    if os.path.exists(base_dest) and os.path.isdir(base_dest):
        id_file = os.path.join(base_dest, ".gofile_id")
        conflict = False
        if os.path.exists(id_file):
            try:
                with open(id_file, "r") as f:
                    if f.read().strip() != content_id:
                        conflict = True
            except: pass
        else:
            if os.listdir(base_dest):
                conflict = True
                
        if conflict:
            console.print(t("conflict_warn", name=folder_name))
            new_name = Prompt.ask(t("conflict_ask"))
            if new_name.strip():
                folder_name = new_name.strip()
            else:
                folder_name = f"{folder_name}_{content_id[:6]}"
                console.print(t("conflict_auto", name=folder_name))
            base_dest = os.path.join(args.dest, folder_name)

    os.makedirs(base_dest, exist_ok=True)
    
    id_file = os.path.join(base_dest, ".gofile_id")
    write_needed = True
    if os.path.exists(id_file):
        try:
            with open(id_file, "r") as f:
                if f.read().strip() == content_id:
                    write_needed = False
        except: pass

    if write_needed:
        if os.name == 'nt' and os.path.exists(id_file):
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(id_file, 128)
            
        with open(id_file, "w") as f:
            f.write(content_id)
            
        if os.name == 'nt':
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(id_file, 2)
        
    summary_stats = {"total_size": 0, "types": {}, "failed": 0, "success": 0, "skipped": 0}

    # --- FASE DE VERIFICACION ---
    real_files_to_download = []
    
    def verify_local_file(f):
        filename = f["name"]
        rel_path = f.get("rel_path", "")
        final_dir = os.path.join(base_dest, rel_path)
        final_path = os.path.join(final_dir, filename)
        size = f.get("size", 0)
        expected_md5 = f.get("md5")
        
        if os.path.exists(final_path):
            local_size = os.path.getsize(final_path)
            if local_size == size and size > 0:
                if verify_md5(final_path, expected_md5):
                    return ("skipped", f)
                else:
                    os.remove(final_path)
        return ("download", f)
        
    with Progress(
        TextColumn("[bold yellow]⏳ Verificando archivos locales...[/bold yellow]"),
        BarColumn(complete_style="yellow"),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        TextColumn("{task.completed}/{task.total} archivos"),
        console=console,
        transient=True
    ) as verify_prog:
        v_task = verify_prog.add_task("Verificando", total=len(files_to_download))
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(verify_local_file, f) for f in files_to_download]
            for future in as_completed(futures):
                status, f = future.result()
                if status == "skipped":
                    summary_stats["skipped"] += 1
                else:
                    real_files_to_download.append(f)
                verify_prog.update(v_task, advance=1)
                
    files_to_download = real_files_to_download
    
    # Rebuild tree with only missing files
    tree = Tree(t("tree_root"))
    folder_counts = {}
    def add_to_tree(node, tree_parent, path_parts, current_path=""):
        if not path_parts:
            # We are at the file level
            folder_counts[current_path] = folder_counts.get(current_path, 0) + 1
            if folder_counts[current_path] <= 5:
                tree_parent.add(f"[green]📄 {node['name']}[/green] ({format_size(node.get('size', 0))})")
            elif folder_counts[current_path] == 6:
                tree_parent.add(f"[dim]... (y más archivos)[/dim]")
            return
        
        part = path_parts[0]
        next_path = os.path.join(current_path, part)
        
        # find or create branch
        branch = next((child for child in tree_parent.children if getattr(child, "label", "") == f"[bold blue]📁 {part}[/bold blue]"), None)
        if not branch:
            branch = tree_parent.add(f"[bold blue]📁 {part}[/bold blue]")
            
        add_to_tree(node, branch, path_parts[1:], next_path)
        
    for f in files_to_download:
        rel = f.get("rel_path", "")
        parts = rel.split(os.sep) if rel else []
        parts = [p for p in parts if p]
        add_to_tree(f, tree, parts)
        
    console.print(tree)
    console.print("")
    
    if not files_to_download:
        console.print("[bold green]¡Todos los archivos ya están descargados y verificados![/bold green]")
        os._exit(0)

    console.print(t("start_dl", count=len(files_to_download), dest=base_dest))
    
    global_start_time = time.time()
    
    total_bytes_to_download = sum(f.get("size", 0) for f in files_to_download)
    
    progress = Progress(
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
        expand=True
    )
    
    with progress:
        tot_files = len(files_to_download)
        init_text = f"[bold yellow]Archivos: {tot_files} | Descargados: 0 | Restantes: {tot_files}[/bold yellow]"
        overall_task = progress.add_task(t("dl_task"), display_name=init_text, total=total_bytes_to_download)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = []
            def queue_downloads(files):
                futs = []
                for f in files:
                    if stop_event.is_set(): break
                    futs.append(pool.submit(download_file, f, base_dest, progress, used_token, overall_task))
                return futs
                
            futures = queue_downloads(files_to_download)
            failed_files = []
            
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        status, ext, size, f_info = res
                        if not ext: ext = "Desconocido"
                        if status == "success":
                            summary_stats["success"] += 1
                            summary_stats["total_size"] += size
                            if ext not in summary_stats["types"]:
                                summary_stats["types"][ext] = {"count": 0, "size": 0}
                            summary_stats["types"][ext]["count"] += 1
                            summary_stats["types"][ext]["size"] += size
                        elif status == "skipped":
                            summary_stats["skipped"] += 1
                        else:
                            failed_files.append(f_info)
                            
                        dn = summary_stats["success"] + len(failed_files)
                        tot_files = len(files_to_download)
                        new_text = f"[bold yellow]Archivos: {tot_files} | Descargados: {dn} | Restantes: {tot_files - dn}[/bold yellow]"
                        progress.update(overall_task, display_name=new_text)
                except: pass
                
    if failed_files and not stop_event.is_set():
        console.print(f"\n[yellow]⏳ Reintentando {len(failed_files)} archivos fallidos en 2 segundos...[/yellow]")
        time.sleep(2)
        
        retry_bytes = sum(f.get("size", 0) for f in failed_files)
        
        progress_retry = Progress(
            TextColumn("{task.fields[display_name]}", justify="right"),
            BarColumn(bar_width=None, complete_style="yellow", finished_style="bold green"),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
            console=console,
            expand=True
        )
        
        with progress_retry:
            tot_retry = len(failed_files)
            retry_task = progress_retry.add_task(
                "Retry", 
                display_name=f"[bold yellow]Reintentos: {tot_retry} | Éxito: 0 | Restantes: {tot_retry}[/bold yellow]", 
                total=retry_bytes
            )
            
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                retry_futs = []
                for f in failed_files:
                    if stop_event.is_set(): break
                    retry_futs.append(pool.submit(download_file, f, base_dest, progress_retry, used_token, retry_task))
                    
                retry_success = 0
                for future in as_completed(retry_futs):
                    try:
                        res = future.result()
                        if res:
                            status, ext, size, f_info = res
                            if not ext: ext = "Desconocido"
                            if status == "success":
                                summary_stats["success"] += 1
                                summary_stats["failed"] -= 1 # Move from failed to success
                                summary_stats["total_size"] += size
                                if ext not in summary_stats["types"]:
                                    summary_stats["types"][ext] = {"count": 0, "size": 0}
                                summary_stats["types"][ext]["count"] += 1
                                summary_stats["types"][ext]["size"] += size
                                retry_success += 1
                            
                            dn = retry_success
                            new_text = f"[bold yellow]Reintentos: {tot_retry} | Éxito: {dn} | Restantes: {tot_retry - dn}[/bold yellow]"
                            progress_retry.update(retry_task, display_name=new_text)
                    except: pass
                
    if not stop_event.is_set():
        if args.zip:
            console.print(t("zipping", dest=base_dest))
            shutil.make_archive(base_dest, 'zip', base_dest)
            shutil.rmtree(base_dest)
            console.print(t("zip_done"))
            
        console.print(t("summary_title"))
        console.print(t("sum_success", count=summary_stats['success']))
        console.print(t("sum_skipped", count=summary_stats['skipped']))
        if summary_stats['failed'] > 0:
            console.print(t("sum_failed", count=summary_stats['failed']))
        
        total_new_size = format_size(summary_stats['total_size'])
        elapsed = time.time() - global_start_time
        avg_speed = format_size(summary_stats['total_size'] / elapsed) + "/s" if elapsed > 0 else "0 B/s"
        console.print(t("sum_total", size=total_new_size))
        console.print(f"  • [cyan]Tiempo total:[/cyan] {elapsed:.1f}s (Promedio: {avg_speed})\n")
        
        if summary_stats['types']:
            from rich.table import Table
            table = Table(show_header=True, header_style="bold yellow", box=None)
            table.add_column(t("table_qty"), justify="right")
            table.add_column(t("table_type"))
            table.add_column(t("table_size"), justify="right")
            
            for ext, data in sorted(summary_stats['types'].items(), key=lambda x: x[1]["size"], reverse=True):
                table.add_row(str(data["count"]), ext, format_size(data["size"]))
                
            console.print(table)
                
        os._exit(0)

if __name__ == "__main__":
    main()
