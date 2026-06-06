<div align="center">

```
██╗  ██╗███████╗███████╗███╗   ███╗ ██████╗ 
██║ ██╔╝██╔════╝╚══███╔╝████╗ ████║██╔═══██╗
█████╔╝ █████╗    ███╔╝ ██╔████╔██║██║   ██║
██╔═██╗ ██╔══╝   ███╔╝  ██║╚██╔╝██║██║   ██║
██║  ██╗███████╗███████╗██║ ╚═╝ ██║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝
```

**Forensic · Steganography · CTF Analysis Toolkit**

*Built for Kali Linux — Zero pip dependencies*

[![PyPI](https://img.shields.io/pypi/v/kezmo?color=blue&label=pip%20install%20kezmo)](https://pypi.org/project/kezmo/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Kali](https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg)](https://www.kali.org/)

</div>

---

## 👋 What is KEZMO?

Hey there! If you've ever spent hours during a CTF challenge manually running `exiftool`, then `binwalk`, then `strings`, then piping things into `grep` and `base64 -d` hoping to find a hidden flag — **KEZMO does all of that in one command.**

I built KEZMO because I was tired of the repetitive workflow in digital forensics and CTF competitions. Every time you get a suspicious file on platforms like **TryHackMe**, **HackTheBox**, **picoCTF**, or any DFIR investigation, you end up running the same 10+ tools manually, in the same order, every single time.

KEZMO automates that entire process. Give it any file — an image, audio, archive, PDF, binary, whatever — and it will:

- 🔍 Identify the file type and check entropy for hidden data
- 📋 Extract and analyze all metadata (EXIF, GPS, suspicious comments)
- 📦 Find and extract embedded files (binwalk + foremost)
- 🔓 Crack password-protected archives and hashes automatically
- 🎵 Generate spectrograms for audio steganography
- 🚩 Hunt for CTF flags in every format (`flag{}`, `ctf{}`, `thm{}`, `HTB{}`, `picoCTF{}`, etc.)
- 🧠 Smart-decode chained encodings (Base64→Gzip, Base64→Zlib, ROT13, hex, etc.)
- 🕵️ Run steganography analysis (steghide + zsteg)

All output is organized in a single `<filename>_output/` directory. No clutter.

Whether you're a beginner learning forensics or a seasoned CTF player who wants to automate the boring parts — KEZMO is built for you.

---

## 🎬 Demo

![KEZMO Demo](text_example.gif)

btw the password was 12345
---

## 📦 Installation

### Option 1: pip install (Easiest)

```bash
pip install kezmo
```

That's it. Now just type `kezmo` from anywhere.

### Option 2: Clone & Install

```bash
git clone https://github.com/seko2077/KEZMO.git
cd KEZMO
pip install .
```

### Option 3: One-Line Kali Setup (installs all dependencies too)

```bash
git clone https://github.com/seko2077/KEZMO.git
cd KEZMO
chmod +x install.sh && ./install.sh
```

### Option 4: Run directly (no install)

```bash
git clone https://github.com/seko2077/KEZMO.git
cd KEZMO
python3 kezmo.py <file>
```

> **After installing (Options 1-3)**, you can use `kezmo` from anywhere — no `python3`, no path needed:
> ```bash
> kezmo challenge.jpg -y
> ```

---

## ⚡ Usage

```bash
kezmo <file> [-y] [-no]
```

```bash
# Basic scan (interactive — asks before each extraction)
kezmo suspicious_image.jpg

# Auto-yes mode (fully unattended — says 'y' to everything)
kezmo challenge.jpg -y

# Auto-yes + no output files (terminal only, keeps disk clean)
kezmo challenge.jpg -y -no

# Direct run without installing
python3 kezmo.py challenge.jpg -y
```

### Flags

| Flag | Description |
|------|-------------|
| `-y` | Auto-answer "yes" to all interactive prompts (unattended mode) |
| `-no` | Skip creating output files (keeps disk clean) |

---

## 🔬 Analysis Modules (Execution Order)

KEZMO runs **11 modules** in sequence, each building on the previous:

| # | Module | What It Does |
|---|--------|-------------|
| 1 | **File Type Check** | `file` command + MIME detection + Shannon entropy + hexdump preview + MD5/SHA256 integrity hash |
| 2 | **EXIF Analysis** | Full metadata extraction via `exiftool` — highlights GPS coordinates, suspicious comments, hidden software tags |
| 3 | **Binwalk** | Scans for embedded files, firmware, compressed data — extracts and recursively analyzes (depth limit: 3) |
| 4 | **Archive Cracking** | Cracks password-protected ZIP/RAR/PDF/Office files using `john` with rockyou.txt |
| 5 | **Audio Spectrogram** | Generates visual spectrograms via `sox` — reveals hidden messages painted in audio frequencies |
| 6 | **Strings Extraction** | Extracts all printable strings — highlights keywords like `password`, `secret`, `flag`, `key` |
| 7 | **Flag Detection** | Regex-hunts for `flag{}`, `ctf{}`, `thm{}`, `picoCTF{}`, `HTB{}`, `tryhackme{}` + generic patterns — with false-positive filtering |
| 8 | **Hash Detection + Cracking** | Finds MD5/SHA1/SHA256/SHA512 hashes in output — offers to crack them with `john` |
| 9 | **Smart Auto Decoding** | Chained decode: Base64→Gzip, Base64→Zlib, Base64, Base32, Base85, Hex, ROT13, URL — strips noise, re-scans for flags |
| 10 | **Steganography** | `steghide` for JPEG/BMP/WAV + `zsteg` for PNG LSB analysis |
| 11 | **Final Summary** | Aggregated findings table + JSON report export |

**Bonus:** Foremost file carving, entropy analysis, hexdump preview

---

## 🧠 Smart Decoding Engine

KEZMO doesn't just try simple Base64. It handles **chained encodings** that are common in CTFs:

| Chain | Real-World Example |
|-------|---------|
| **Base64 → Gzip → Plaintext** | A gzip-compressed secret message hidden in an EXIF Comment field |
| **Base64 → Zlib → Plaintext** | Zlib-compressed data embedded in metadata |
| **Noise Stripping** | Strips `.` dots, spaces, newlines injected to break decoders |
| **EXIF + Strings scanning** | Feeds both metadata AND strings output into the decoder |

The decoder automatically:
- Re-runs flag detection on every successfully decoded result
- Detects embedded ZIP archives inside Base64
- Filters garbage (rejects non-printable output, Unicode replacement chars)

---

## 📂 Supported File Types

KEZMO runs **all modules** on any file. Certain modules activate special behavior based on extension:

| Category | Extensions | Special Modules |
|----------|-----------|-----------------|
| **Images** | `jpg`, `jpeg`, `png`, `bmp`, `gif`, `tiff`, `tif`, `webp` | EXIF metadata, Steghide (jpg/jpeg/bmp), Zsteg (png) |
| **Audio** | `wav`, `mp3`, `flac`, `ogg`, `aac`, `m4a` | Spectrogram generation, Steghide (wav) |
| **Archives** | `zip`, `rar`, `7z`, `tar`, `gz`, `bz2`, `xz` | Password cracking with john |
| **Documents** | `pdf`, `docx`, `xlsx`, `pptx`, `doc`, `xls` | Password cracking, metadata extraction |
| **Text** | `txt`, `csv`, `log`, `xml`, `html`, `json` | Strings, flag/hash detection, auto decoding |
| **Binary** | Any other file | Full analysis — binwalk, strings, entropy, hexdump, flags, hashes, decoding |

> Modules like Binwalk, Strings, Flag Detection, Hash Detection, and Auto Decoding run on **every file** regardless of extension.

---

## 📂 Output Structure

All output goes into a single organized directory — no scattered files:

```
kezmo challenge.jpg
```

```
challenge.jpg_output/
├── strings_output.txt       # All extracted strings
├── kezmo_report.json        # Complete JSON findings report
├── spectrogram_*.png        # Audio spectrograms (if audio file)
├── binwalk_extracted/       # Binwalk-extracted files
├── foremost/                # Foremost-carved files
└── steghide_extracted_*     # Steghide-extracted data
```

Use `-no` to skip all file creation:

```bash
kezmo challenge.jpg -y -no
```

---

## 🛠️ Prerequisites

All tools come pre-installed on Kali Linux. The `install.sh` script handles everything automatically.

Manual install if needed:

```bash
sudo apt update
sudo apt install -y exiftool binwalk steghide sox foremost john
gem install zsteg  # Optional — PNG LSB steganography
```

| Tool | Used For | Required |
|------|---------|----------|
| `exiftool` | EXIF/Metadata Analysis | ✅ Yes |
| `binwalk` | Embedded File Detection | ✅ Yes |
| `steghide` | JPEG/BMP/WAV Steganography | ✅ Yes |
| `sox` | Audio Spectrogram Generation | ✅ Yes |
| `john` | Password & Hash Cracking | ✅ Yes |
| `foremost` | File Carving | ✅ Yes |
| `zsteg` | PNG LSB Steganography | ⚠️ Optional |
| `file` | File Type Detection | ✅ Pre-installed |
| `strings` | String Extraction | ✅ Pre-installed |

---

## 🎯 Features

- **Zero pip dependencies** — uses only Python 3 standard library
- **One command install** — `pip install kezmo` and you're done
- **System-wide CLI** — type `kezmo` from anywhere after installing
- **Smart chained decoding** — Base64→Gzip, Base64→Zlib, noise stripping
- **Hash cracking** — auto-cracks detected MD5/SHA hashes with `john` + rockyou.txt
- **Auto-yes mode (`-y`)** — fully unattended scanning
- **Recursive analysis** — extracted files are automatically re-scanned
- **Entropy analysis** — Shannon entropy detects encrypted/compressed regions
- **Hexdump preview** — first 256 bytes for quick manual inspection
- **File integrity hashing** — MD5/SHA256 of the input file
- **Organized output** — everything in `<filename>_output/`
- **No-output mode (`-no`)** — skip all file creation
- **False-positive filtering** — flag regex validated against printable ASCII
- **Beautiful terminal output** — colored, structured display with progress tracking

---

## 📜 License

MIT License — use freely for CTF, forensics, and educational purposes.

---

<div align="center">

**Built by SAIF** — for the CTF and DFIR community 🛡️

*If KEZMO helped you capture a flag, give it a ⭐!*

</div>
