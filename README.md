# Gofile Downloader CLI

A powerful command-line downloader for Gofile, designed to be fast, resilient, and user-friendly. Especially useful for downloading massive folders, handling passwords, and automating backups from terminals on any operating system.

## ✨ Features

- 🚀 **Multi-threading**: Download multiple files simultaneously for maximum speed.
- ⚡ **Concurrent Exploration**: Reads the entire folder and subfolder structure instantly.
- 🎨 **Modern Interface**: Dynamic progress bars, directory trees with formatted sizes (KB/MB/GB), and smart color-coded status (Downloading, Completed, Skipped).
- 🔒 **Password Support**: Enter the password interactively in the console or pass it as an argument. Fully supports nested folders with different passwords.
- 🛡️ **Resilience**: Auto-retry in case of network cuts and integrity verification using MD5 hashing. Automatically resumes partial downloads perfectly.
- 🗂️ **Filters and Identity**: Filter by extension (`--ext mp4`) and avoid overwrite conflicts if two different links share the same name (creates `.gofile_id` markers).
- 📦 **Auto-Packaging**: Compress everything into a `.zip` when finished and clean up loose files (`--zip`).
- 🔗 **Export**: Extract all direct links to `.txt` or `.json` without downloading anything (`--export`).
- 🌐 **Proxy Support**: Bypass regional blocks or IP limits by injecting proxies (`--proxy`).
- 📊 **Technical Summary**: Detailed post-download breakdown including total weight, file counts, and extension breakdown.

## 🛠️ Installation

Make sure you have Python 3.7 or higher installed.

1. Clone or download the repository.
2. Install the necessary dependencies:

```bash
pip install requests rich
```

## 📖 Basic Usage

To download a link directly into your current folder:

```bash
python gofile_cli.py https://gofile.io/d/XXXXXX
```

### Advanced Options

| Parameter | Description | Example |
| :--- | :--- | :--- |
| `-p`, `--password` | Main folder password | `-p mySecretKey` |
| `-d`, `--dest` | Destination folder | `-d C:\Downloads` |
| `-w`, `--workers` | Download threads (default: 2) | `-w 4` |
| `-e`, `--ext` | Filter by file extension | `-e mp4,jpg` |
| `-z`, `--zip` | Package the result into a `.zip` | `-z` |
| `--export` | Save direct links to a file | `--export links.json` |
| `--proxy` | Configure an HTTP/HTTPS proxy | `--proxy http://127.0.0.1:8080` |
| `-l`, `--lang` | UI Language (es, en, zh) | `-l en` |

## 💡 Practical Examples

**Download only videos using 4 threads:**
```bash
python gofile_cli.py https://gofile.io/d/XXXXXX -w 4 -e mp4,mov,avi
```

**Create an automatic ZIP of a protected album:**
```bash
python gofile_cli.py https://gofile.io/d/XXXXXX -p secret123 --zip
```

**Extract download links to a text file to use in other managers:**
```bash
python gofile_cli.py https://gofile.io/d/XXXXXX --export links.txt
```

## 🧠 Troubleshooting

- **IP Rate Limit**: If you download a huge amount of files, Gofile might temporarily pause you. The script includes smart pauses and guest account handling to bypass this, but if you still have issues, use `--proxy`.
- **My terminal closed halfway through**: Run the exact same command again. The script will verify MD5s and automatically resume where it left off without re-downloading what you already have.
- **Corrupted files**: The script verifies the MD5 of every downloaded file against the server. If it fails, it deletes it and retries automatically. Check `gofile_errors.log` if a file consistently fails.


## ?? Multi-language Support

The CLI natively supports multiple languages. It auto-detects your system language (fallback to English), but you can manually force it via the -l flag (e.g., -l es for Spanish or -l zh for Chinese). To add a new language, simply create a new JSON file in the locales/ folder.
