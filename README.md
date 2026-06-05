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

</div>

---

## ⚡ Quick Start

```bash
python3 kezmo.py <file> [-y] [-no]
```

```bash
# Examples
python3 kezmo.py suspicious_image.jpg
python3 kezmo.py encrypted.zip
python3 kezmo.py hidden_audio.wav
python3 kezmo.py challenge.pdf

# Auto-yes mode (answers 'y' to all prompts — fully unattended)
python3 kezmo.py suspicious_image.jpg -y

# Combo: auto-yes + no output files
python3 kezmo.py suspicious_image.jpg -y -no
```

![[video test.mp4]]
### Flags

| Flag | Description |
|------|-------------|
| `-y` | Auto-answer "yes" to all interactive prompts (unattended mode) |
| `-no` | Skip creating output files (keeps disk clean) |

---

## 🔬 Analysis Modules (Execution Order)

| # | Module | Description |
|---|--------|-------------|
| 1 | **File Type Check** | `file` command + MIME detection + Shannon entropy analysis + hexdump preview + file integrity hashing (MD5/SHA256) |
| 2 | **EXIF Analysis** | Full metadata extraction via `exiftool` with suspicious field highlighting (GPS, comments, software, embedded data) |
| 3 | **Binwalk** | Embedded file detection + extraction + recursive scanning (depth-limited to 3 levels) |
| 4 | **Archive Cracking** | Password cracking for ZIP/RAR/PDF/Office via `john` with wordlist support |
| 5 | **Audio Spectrogram** | Generates spectrograms via `sox` for hidden visual messages in audio files |
| 6 | **Strings** | Full strings extraction + keyword highlighting (password, secret, flag, key, etc.) |
| 7 | **Flag Detection** | Regex matching for `flag{}`, `ctf{}`, `thm{}`, `picoCTF{}`, `HTB{}`, `tryhackme{}`, and generic patterns — with false-positive filtering |
| 8 | **Hash Detection + Cracking** | Detects MD5, SHA1, SHA224, SHA256, SHA384, SHA512 hashes — then offers to crack them with `john` + wordlist |
| 9 | **Smart Auto Decoding** | Chained decoding: Base64→Gzip, Base64→Zlib, Base64, Base32, Base85, Hex, ROT13, URL — with noise stripping and automatic flag re-scan on decoded content |
| 10 | **Steganography** | `steghide` extraction (with auto passphrase bypass) + `zsteg` for PNG LSB analysis |
| 11 | **Final Summary** | Aggregated findings with colored table + JSON report export |

**Bonus Modules:** Foremost file carving, Zsteg LSB analysis, Entropy analysis

---

## 🧠 Smart Decoding Engine

KEZMO doesn't just try simple Base64. It handles **chained encodings** that are common in CTFs:

| Chain | Example |
|-------|---------|
| **Base64 → Gzip → Plaintext** | EXIF comment containing gzip-compressed secret messages |
| **Base64 → Zlib → Plaintext** | Zlib-compressed data hidden in metadata fields |
| **Noise Stripping** | Strips `.` dots, spaces, newlines from encoded strings before decoding |
| **EXIF + Strings** | Scans both EXIF metadata AND strings output for encoded content |

The decoder also automatically:
- Re-runs flag detection on every decoded result
- Detects embedded ZIP archives inside Base64
- Filters garbage decodes (rejects non-printable output)

---

## 🛠️ Prerequisites

All tools come pre-installed on Kali Linux. If any are missing:

```bash
sudo apt update
sudo apt install -y exiftool binwalk steghide sox foremost john
gem install zsteg  # Optional — PNG LSB steganography
```

---

## 📂 Supported File Types

| Category | Extensions |
|----------|-----------|
| **Images** | jpg, jpeg, png, bmp, gif, tiff, webp |
| **Audio** | wav, mp3, flac, ogg, aac, m4a |
| **Archives** | zip, rar, 7z, tar, gz, bz2 |
| **Documents** | pdf, docx, xlsx, pptx, doc, xls |
| **Other** | txt, any binary file |

---

## 🎯 Features

- **Zero pip dependencies** — uses only Python 3 standard library
- **Smart chained decoding** — Base64→Gzip, Base64→Zlib, noise stripping
- **Hash cracking** — auto-cracks detected MD5/SHA hashes with `john` + rockyou.txt
- **Auto-yes mode (`-y`)** — fully unattended scanning, answers "yes" to all prompts
- **Interactive prompts** — Y/N choices for extraction and cracking
- **Recursive analysis** — extracted files are re-scanned automatically
- **Entropy analysis** — Shannon entropy detects encrypted/compressed regions
- **Hexdump preview** — first 256 bytes for quick manual inspection
- **File integrity hashing** — MD5/SHA256 of the input file
- **Organized output** — all files saved to `<filename>_output/` directory
- **No-output mode (`-no`)** — skip all file creation
- **Zip-bomb protection** — recursive depth limit (default: 3)
- **False-positive filtering** — flag regex validated against printable ASCII, hash cracking avoids binary noise
- **Beautiful output** — colored, structured terminal display with progress tracking

---

## 📂 Output Structure

All output goes into a single organized directory:

```
python3 kezmo.py sky.jpg
```

```
sky.jpg_output/
├── strings_output.txt       # All extracted strings
├── kezmo_report.json        # Complete JSON findings report
├── spectrogram_*.png        # Audio spectrograms (if audio)
├── binwalk_extracted/       # Binwalk-extracted files
├── foremost/                # Foremost-carved files
└── steghide_extracted_*     # Steghide-extracted data
```

Use `-no` flag to skip creating any output files:

```bash
python3 kezmo.py sky.jpg -no
```

---

## 📜 License

MIT License — use freely for CTF, forensics, and educational purposes.

---

<div align="center">
<i>Built by SAIF</i>
</div>
