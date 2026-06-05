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
python3 kezmo.py <file>
```

```bash
# Examples
python3 kezmo.py suspicious_image.jpg
python3 kezmo.py encrypted.zip
python3 kezmo.py hidden_audio.wav
python3 kezmo.py challenge.pdf
```

---

## 🔬 Analysis Modules (Execution Order)

| # | Module | Description |
|---|--------|-------------|
| 1 | **File Type Check** | `file` command + MIME detection + entropy analysis + hexdump preview |
| 2 | **EXIF Analysis** | Full metadata extraction via `exiftool` with suspicious field highlighting |
| 3 | **Binwalk** | Embedded file detection + extraction + recursive scanning |
| 4 | **Archive Cracking** | Password cracking for ZIP/RAR/PDF/Office via `john` |
| 5 | **Audio Spectrogram** | Generates spectrograms via `sox` for hidden visual messages |
| 6 | **Strings** | Full strings extraction + keyword highlighting + file export |
| 7 | **Flag Detection** | Regex matching for `flag{}`, `ctf{}`, `thm{}`, `picoCTF{}`, `HTB{}`, and more |
| 8 | **Hash Detection** | MD5, SHA1, SHA224, SHA256, SHA384, SHA512 identification |
| 9 | **Auto Decoding** | Base64, Base32, Base85, Hex, ROT13, URL decoding with flag re-scan |
| 10 | **Steganography** | `steghide` extraction + `zsteg` for PNG LSB analysis |
| 11 | **Final Summary** | Aggregated findings + JSON report export |

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
- **Interactive prompts** — Y/N choices for extraction and cracking
- **Recursive analysis** — extracted files are re-scanned automatically
- **Entropy analysis** — detects encrypted/compressed regions
- **Hexdump preview** — first 256 bytes for quick manual inspection
- **File integrity hashing** — MD5/SHA256 of the input file
- **JSON report export** — all findings saved to `kezmo_report.json`
- **Zip-bomb protection** — recursive depth limit (default: 3)
- **Beautiful output** — colored, structured terminal display

---

## 📋 Output Files

| File | Description |
|------|-------------|
| `strings_output.txt` | All extracted strings |
| `kezmo_report.json` | Complete JSON findings report |
| `spectrogram_*.png` | Audio spectrograms |
| `extracted/` | Binwalk-extracted files |
| `foremost_output/` | Foremost-carved files |

---

## 📜 License

MIT License — use freely for CTF, forensics, and educational purposes.

---

<div align="center">
<i>Built by SAIF</i>
</div>
