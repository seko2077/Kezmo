#!/usr/bin/env python3
# ============================================================================
#  KEZMO — Forensic / Steganography / CTF Analysis Toolkit
#  Author : SAIF
#  Usage  : python3 kezmo.py <file>
#  Target : Kali Linux (relies on pre-installed CLI tools)
# ============================================================================

import subprocess
import sys
import os
import re
import shutil
import base64
import codecs
import urllib.parse
import json
import math
import hashlib
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ============================================================================
#                          ANSI COLOR CONSTANTS
# ============================================================================

class C:
    """Raw ANSI escape codes — zero pip dependencies."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    ULINE   = "\033[4m"
    BLINK   = "\033[5m"

    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN    = "\033[46m"

    # Bright variants
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"


# ============================================================================
#                          GLOBAL RESULTS COLLECTOR
# ============================================================================

results = {
    "flags": [],               # (source, pattern_name, matched_text)
    "hashes": defaultdict(list),  # {hash_type: [(source, value)]}
    "decoded": [],             # (encoding, original, decoded)
    "extracted_files": [],     # file paths
    "cracked_passwords": [],   # (archive, password)
    "spectrograms": [],        # file paths
    "suspicious_metadata": [], # (field, value)
    "file_hashes": {},         # {algo: digest} of the input file
}

# When True, skip writing output files (strings_output.txt, kezmo_report.json)
NO_OUTPUT = False

# Global output directory — set in main() to <filename>_output/
OUTPUT_DIR = "."


# ============================================================================
#                          BANNER & OUTPUT HELPERS
# ============================================================================

def print_banner():
    """Large colored ASCII-art KEZMO banner."""
    banner = f"""
{C.BRIGHT_RED}{C.BOLD}
██╗  ██╗███████╗███████╗███╗   ███╗ ██████╗ 
██║ ██╔╝██╔════╝╚══███╔╝████╗ ████║██╔═══██╗
█████╔╝ █████╗    ███╔╝ ██╔████╔██║██║   ██║
██╔═██╗ ██╔══╝   ███╔╝  ██║╚██╔╝██║██║   ██║
██║  ██╗███████╗███████╗██║ ╚═╝ ██║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝ {C.RESET}
{C.CYAN}{C.BOLD}     ╔══════════════════════════════════════╗
     ║  {C.BRIGHT_WHITE}Forensic · Stego · CTF Toolkit{C.CYAN}      ║
     ║  {C.DIM}{C.WHITE}v1.0  —  Built for Kali Linux{C.RESET}{C.CYAN}{C.BOLD}       ║
     ╚══════════════════════════════════════╝{C.RESET}
{C.DIM}{C.WHITE}     Author: SAIF  |  github.com/SAIF{C.RESET}
"""
    print(banner)


def print_section(title, icon="▶"):
    """Standardized module header with box-drawing characters."""
    width = 60
    top    = f"╔{'═' * (width - 2)}╗"
    bottom = f"╚{'═' * (width - 2)}╝"
    padded = f"║ {icon}  {title}".ljust(width - 1) + "║"
    print(f"\n{C.BRIGHT_CYAN}{C.BOLD}{top}")
    print(padded)
    print(f"{bottom}{C.RESET}\n")


def print_subsection(title):
    """Smaller sub-header."""
    print(f"\n  {C.BRIGHT_MAGENTA}{C.BOLD}┌─ {title}{C.RESET}")
    print(f"  {C.BRIGHT_MAGENTA}{'─' * 50}{C.RESET}")


def print_result(label, value, color=C.WHITE):
    """Formatted key-value output line."""
    print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BOLD}{label}:{C.RESET} {color}{value}{C.RESET}")


def print_warning(msg):
    """Yellow warning line."""
    print(f"  {C.BRIGHT_YELLOW}⚠  {msg}{C.RESET}")


def print_error(msg):
    """Red error line."""
    print(f"  {C.BRIGHT_RED}✖  {msg}{C.RESET}")


def print_success(msg):
    """Green success line."""
    print(f"  {C.BRIGHT_GREEN}✔  {msg}{C.RESET}")


def print_highlight(msg):
    """Cyan highlighted finding — used for flags/secrets."""
    print(f"  {C.BG_MAGENTA}{C.BRIGHT_WHITE}{C.BOLD} ★ {msg} {C.RESET}")


def print_flag_found(source, pattern, match):
    """Specially formatted flag discovery."""
    print(f"  {C.BG_RED}{C.BRIGHT_WHITE}{C.BOLD}  🚩 FLAG FOUND  {C.RESET} "
          f"{C.BRIGHT_YELLOW}[{pattern}]{C.RESET} "
          f"{C.BRIGHT_GREEN}{C.BOLD}{match}{C.RESET} "
          f"{C.DIM}(from {source}){C.RESET}")


def print_progress(current, total, module_name):
    """Progress indicator between modules."""
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = int(100 * current / total)
    print(f"\n{C.DIM}{C.WHITE}  [{bar}] {pct}%  ─  {module_name}{C.RESET}")


# ============================================================================
#                          UTILITY FUNCTIONS
# ============================================================================

def ask_yes_no(prompt):
    """Interactive Y/N prompt → bool."""
    while True:
        try:
            ans = input(f"\n  {C.BRIGHT_YELLOW}?  {prompt} (y/n): {C.RESET}").strip().lower()
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            print_warning("Please enter 'y' or 'n'.")
        except (EOFError, KeyboardInterrupt):
            print()
            return False


def run_cmd(cmd, timeout=120):
    """
    Execute a shell command and return stdout as string.
    Returns empty string on error. Logs stderr as warning.
    """
    try:
        proc = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=timeout
        )
        if proc.stderr and proc.returncode != 0:
            print_warning(f"stderr: {proc.stderr.strip()[:200]}")
        return proc.stdout
    except subprocess.TimeoutExpired:
        print_error(f"Command timed out ({timeout}s): {cmd[:80]}")
        return ""
    except Exception as e:
        print_error(f"Command failed: {e}")
        return ""


def ensure_tool(name):
    """Check if a CLI tool exists on PATH. Warn if missing, return bool."""
    if shutil.which(name):
        return True
    print_warning(f"Tool '{name}' not found on PATH. Skipping this check.")
    return False


def get_file_extension(filepath):
    """Return lowercase extension without dot."""
    return Path(filepath).suffix.lower().lstrip(".")


def is_image(ext):
    return ext in ("jpg", "jpeg", "png", "bmp", "gif", "tiff", "tif", "webp")


def is_audio(ext):
    return ext in ("wav", "mp3", "flac", "ogg", "aac", "m4a")


def is_archive(ext):
    return ext in ("zip", "rar", "7z", "tar", "gz", "bz2", "xz")


def is_document(ext):
    return ext in ("pdf", "docx", "xlsx", "pptx", "doc", "xls")


def is_steghide_supported(ext):
    return ext in ("jpg", "jpeg", "bmp", "wav", "au")


# ============================================================================
#       BONUS: FILE HASHING (compute MD5/SHA256 of input for integrity)
# ============================================================================

def compute_file_hashes(filepath):
    """Compute MD5 and SHA256 of the input file for evidence integrity."""
    hash_algos = {
        "MD5": hashlib.md5(),
        "SHA256": hashlib.sha256(),
    }
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                for h in hash_algos.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hash_algos.items()}
    except Exception as e:
        print_error(f"Could not hash file: {e}")
        return {}


# ============================================================================
#       BONUS: ENTROPY ANALYSIS (detect encrypted/compressed regions)
# ============================================================================

def calculate_entropy(filepath, block_size=256):
    """
    Calculate Shannon entropy of the file.
    High entropy (>7.5) suggests encryption/compression.
    Returns (overall_entropy, [block_entropies]).
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print_error(f"Entropy read failed: {e}")
        return 0.0, []

    if not data:
        return 0.0, []

    # Overall entropy
    overall = _shannon_entropy(data)

    # Block-level entropy for visualization
    block_entropies = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        block_entropies.append(_shannon_entropy(block))

    return overall, block_entropies


def _shannon_entropy(data):
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def display_entropy(filepath):
    """Display entropy analysis with visual bar and anomaly detection."""
    print_subsection("Entropy Analysis")
    overall, blocks = calculate_entropy(filepath)

    # Visual entropy bar
    bar_len = 40
    filled = int(bar_len * overall / 8.0)
    filled = min(filled, bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    # Color based on entropy level
    if overall > 7.5:
        ent_color = C.BRIGHT_RED
        verdict = "HIGH — likely encrypted or compressed"
    elif overall > 6.0:
        ent_color = C.BRIGHT_YELLOW
        verdict = "MODERATE — possibly compressed data"
    else:
        ent_color = C.BRIGHT_GREEN
        verdict = "LOW — plaintext or structured data"

    print_result("Overall Entropy", f"{overall:.4f} / 8.0", ent_color)
    print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.DIM}[{bar}]{C.RESET}")
    print_result("Verdict", verdict, ent_color)

    # Detect high-entropy regions (anomalies)
    if blocks:
        anomalies = []
        for i, ent in enumerate(blocks):
            if ent > 7.5:
                offset = i * 256
                anomalies.append((offset, ent))
        if anomalies:
            print_warning(f"Found {len(anomalies)} high-entropy block(s) — possible embedded encrypted data:")
            for offset, ent in anomalies[:10]:  # Show max 10
                print(f"    {C.BRIGHT_RED}Offset 0x{offset:08X}  →  entropy {ent:.4f}{C.RESET}")
            if len(anomalies) > 10:
                print(f"    {C.DIM}... and {len(anomalies) - 10} more{C.RESET}")


# ============================================================================
#       BONUS: HEXDUMP PREVIEW (first 256 bytes)
# ============================================================================

def display_hexdump(filepath, num_bytes=256):
    """Show first N bytes in hex+ASCII format for quick manual inspection."""
    print_subsection("Hexdump Preview (first 256 bytes)")
    try:
        with open(filepath, "rb") as f:
            data = f.read(num_bytes)
    except Exception as e:
        print_error(f"Could not read file for hexdump: {e}")
        return

    if not data:
        print_warning("File is empty.")
        return

    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        # Pad hex part to fixed width
        hex_part = hex_part.ljust(48)
        print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BRIGHT_BLUE}{i:08x}{C.RESET}  "
              f"{C.WHITE}{hex_part}{C.RESET}  {C.BRIGHT_GREEN}|{ascii_part}|{C.RESET}")


# ============================================================================
#  MODULE 1: FILE TYPE CHECK
# ============================================================================

def module_file_type(filepath):
    """Run 'file' command and display MIME/type info."""
    print_section("MODULE 1: FILE TYPE IDENTIFICATION", "🔍")

    if not ensure_tool("file"):
        return ""

    # Standard file output
    output = run_cmd(f'file "{filepath}"')
    if output:
        # Split off the filename prefix
        parts = output.strip().split(":", 1)
        file_type = parts[1].strip() if len(parts) > 1 else output.strip()
        print_result("File Type", file_type, C.BRIGHT_GREEN)

    # MIME type
    mime_output = run_cmd(f'file --mime-type "{filepath}"')
    if mime_output:
        parts = mime_output.strip().split(":", 1)
        mime = parts[1].strip() if len(parts) > 1 else mime_output.strip()
        print_result("MIME Type", mime, C.BRIGHT_CYAN)

    # File size
    try:
        size = os.path.getsize(filepath)
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"
        print_result("File Size", size_str, C.WHITE)
    except OSError:
        pass

    # File hashes for evidence integrity
    print_subsection("Input File Integrity Hashes")
    file_hashes = compute_file_hashes(filepath)
    for algo, digest in file_hashes.items():
        print_result(algo, digest, C.BRIGHT_YELLOW)
        results["file_hashes"][algo] = digest

    # Entropy analysis
    display_entropy(filepath)

    # Hexdump preview
    display_hexdump(filepath)

    return output


# ============================================================================
#  MODULE 2: EXIF / METADATA ANALYSIS
# ============================================================================

# Metadata fields that are suspicious or worth highlighting
SUSPICIOUS_EXIF_FIELDS = {
    "gps", "latitude", "longitude", "comment", "user comment",
    "artist", "author", "software", "create date", "modify date",
    "make", "model", "serial", "thumbnail", "icc profile",
    "xmp", "iptc", "photoshop", "history", "creator tool",
}


def module_exif_analysis(filepath):
    """Run exiftool, parse and display all metadata, highlight suspicious fields."""
    print_section("MODULE 2: EXIF / METADATA ANALYSIS", "📋")

    if not ensure_tool("exiftool"):
        return ""

    output = run_cmd(f'exiftool "{filepath}"')
    if not output or not output.strip():
        print_warning("No EXIF data found or exiftool returned empty output.")
        return ""

    suspicious_found = []

    for line in output.strip().split("\n"):
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()

        # Check if this field is suspicious
        key_lower = key.lower()
        is_suspicious = any(s in key_lower for s in SUSPICIOUS_EXIF_FIELDS)

        if is_suspicious and val and val not in ("", "-", "0", "Unknown"):
            print(f"  {C.BG_YELLOW}{C.BLACK}{C.BOLD} ⚠ {key} {C.RESET}"
                  f"  {C.BRIGHT_YELLOW}{val}{C.RESET}")
            suspicious_found.append((key, val))
            results["suspicious_metadata"].append((key, val))
        else:
            print_result(key, val, C.WHITE)

    if suspicious_found:
        print(f"\n  {C.BRIGHT_YELLOW}{C.BOLD}  → {len(suspicious_found)} suspicious metadata field(s) highlighted above{C.RESET}")

    return output


# ============================================================================
#  MODULE 3: BINWALK ANALYSIS
# ============================================================================

MAX_RECURSIVE_DEPTH = 3  # Zip-bomb protection


def module_binwalk_analysis(filepath, depth=0):
    """Run binwalk, display findings, offer extraction."""
    print_section("MODULE 3: BINWALK — EMBEDDED FILE ANALYSIS", "📦")

    if not ensure_tool("binwalk"):
        return

    output = run_cmd(f'binwalk "{filepath}"')
    if output:
        print(f"{C.WHITE}{output}{C.RESET}")
    else:
        print_warning("binwalk returned no output.")
        return

    # Check if there are embedded files (lines beyond the header)
    lines = [l for l in output.strip().split("\n") if l.strip() and not l.startswith("DECIMAL")]
    # Filter out the separator line
    data_lines = [l for l in lines if not l.startswith("-")]

    if len(data_lines) > 1:  # More than just the file itself
        print_success(f"Binwalk detected {len(data_lines) - 1} embedded signature(s).")

        if depth >= MAX_RECURSIVE_DEPTH:
            print_warning(f"Recursive depth limit ({MAX_RECURSIVE_DEPTH}) reached. Skipping extraction.")
            return

        if ask_yes_no("Extract embedded files?"):
            binwalk_extract(filepath, depth)
    else:
        print_result("Result", "No embedded files detected.", C.DIM)


def binwalk_extract(filepath, depth=0):
    """Run binwalk -e to extract embedded files into 'extracted/' directory."""
    extract_dir = os.path.join(OUTPUT_DIR, "binwalk_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    output = run_cmd(f'binwalk -e -C "{extract_dir}" "{filepath}"')
    if output:
        print_success(f"Extraction complete. Output directory: {extract_dir}")
        print(f"{C.DIM}{output}{C.RESET}")
    else:
        print_success(f"Extraction attempted. Check: {extract_dir}")

    # List extracted files
    extracted = []
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            extracted.append(fpath)
            results["extracted_files"].append(fpath)

    if extracted:
        print_subsection("Extracted Files")
        for f in extracted:
            print_result("File", f, C.BRIGHT_GREEN)

        # Recursive scan
        if ask_yes_no("Recursively analyze extracted files?"):
            for fpath in extracted:
                print(f"\n  {C.BRIGHT_CYAN}{'═' * 50}")
                print(f"  Recursive scan: {os.path.basename(fpath)}")
                print(f"  {'═' * 50}{C.RESET}")
                recursive_scan_extracted(fpath, depth + 1)


def recursive_scan_extracted(filepath, depth):
    """Run key modules on an extracted file (limited set to avoid infinite loops)."""
    if depth >= MAX_RECURSIVE_DEPTH:
        print_warning("Max recursive depth reached.")
        return

    ext = get_file_extension(filepath)

    # Run a subset of modules on the extracted file
    module_file_type(filepath)

    # Strings + flag + hash detection
    strings_output = module_strings_analysis(filepath)
    if strings_output:
        module_flag_detection(strings_output, f"extracted:{os.path.basename(filepath)}")
        module_hash_detection(strings_output, f"extracted:{os.path.basename(filepath)}")

    # If it's another archive, try binwalk again
    module_binwalk_analysis(filepath, depth)


# ============================================================================
#  MODULE 4: ARCHIVE / PASSWORD CRACKING
# ============================================================================

def module_archive_analysis(filepath, ext):
    """Detect archive/doc type, offer password cracking with john."""
    print_section("MODULE 4: ARCHIVE / PASSWORD ANALYSIS", "🔐")

    crackable = False
    john_tool = None
    file_type_label = ""

    if ext in ("zip",):
        john_tool = "zip2john"
        file_type_label = "ZIP archive"
        crackable = True
    elif ext in ("rar",):
        john_tool = "rar2john"
        file_type_label = "RAR archive"
        crackable = True
    elif ext in ("pdf",):
        john_tool = "pdf2john"
        file_type_label = "PDF document"
        crackable = True
    elif ext in ("docx", "xlsx", "pptx", "doc", "xls"):
        john_tool = "office2john"
        file_type_label = "Office document"
        crackable = True

    if not crackable:
        print_result("Status", "File is not a crackable archive/document type.", C.DIM)
        return

    print_result("Detected Type", file_type_label, C.BRIGHT_YELLOW)

    if not ask_yes_no(f"Attempt password cracking on this {file_type_label}?"):
        print_result("Skipped", "User declined password cracking.", C.DIM)
        return

    if not ensure_tool(john_tool):
        return
    if not ensure_tool("john"):
        return

    # Extract hash
    hash_file = f"/tmp/kezmo_hash_{os.getpid()}.txt"
    print_result("Extracting hash", f"Running {john_tool}...", C.CYAN)

    hash_output = run_cmd(f'{john_tool} "{filepath}"')
    if not hash_output or not hash_output.strip():
        print_error(f"{john_tool} could not extract a hash. File may not be password-protected.")
        return

    try:
        with open(hash_file, "w") as f:
            f.write(hash_output)
        print_success(f"Hash extracted to {hash_file}")
    except Exception as e:
        print_error(f"Could not write hash file: {e}")
        return

    # Get wordlist
    wordlist = get_wordlist()
    if not wordlist:
        return

    # Crack with john
    crack_with_john(hash_file, wordlist, filepath)

    # Cleanup
    try:
        os.remove(hash_file)
    except OSError:
        pass


def get_wordlist():
    """Ask user for wordlist path or default to rockyou.txt."""
    default_wl = "/usr/share/wordlists/rockyou.txt"
    print_result("Default wordlist", default_wl, C.DIM)

    try:
        custom = input(f"  {C.BRIGHT_YELLOW}?  Enter wordlist path (or press Enter for default): {C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None

    wordlist = custom if custom else default_wl

    if not os.path.isfile(wordlist):
        # rockyou might be gzipped
        if wordlist == default_wl and os.path.isfile(default_wl + ".gz"):
            print_warning("rockyou.txt is gzipped. Decompressing...")
            run_cmd(f'gzip -dk "{default_wl}.gz"')
            if os.path.isfile(wordlist):
                print_success("Decompressed successfully.")
            else:
                print_error("Decompression failed.")
                return None
        else:
            print_error(f"Wordlist not found: {wordlist}")
            return None

    print_success(f"Using wordlist: {wordlist}")
    return wordlist


def crack_with_john(hash_file, wordlist, original_file):
    """Run john the ripper with the given hash and wordlist."""
    print_result("Cracking", "Running John the Ripper...", C.BRIGHT_CYAN)

    output = run_cmd(f'john --wordlist="{wordlist}" "{hash_file}"', timeout=300)
    if output:
        print(f"{C.WHITE}{output}{C.RESET}")

    # Show cracked passwords
    show_output = run_cmd(f'john --show "{hash_file}"')
    if show_output and "0 password hashes cracked" not in show_output:
        print_success("Password cracked!")
        print_highlight(show_output.strip())
        # Try to parse the password from john's output
        for line in show_output.strip().split("\n"):
            if ":" in line and "password hash" not in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    password = parts[1]
                    results["cracked_passwords"].append((os.path.basename(original_file), password))
    else:
        print_warning("No password cracked with the provided wordlist.")


# ============================================================================
#  MODULE 5: AUDIO ANALYSIS (SPECTROGRAM)
# ============================================================================

def module_audio_analysis(filepath, ext):
    """Generate spectrogram via sox for audio files."""
    print_section("MODULE 5: AUDIO SPECTROGRAM ANALYSIS", "🎵")

    if not is_audio(ext):
        print_result("Status", "Not an audio file. Skipping spectrogram.", C.DIM)
        return

    if not ensure_tool("sox"):
        return

    spectrogram_file = os.path.join(
        OUTPUT_DIR,
        f"spectrogram_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    )

    print_result("Generating", "Spectrogram via sox...", C.CYAN)
    output = run_cmd(f'sox "{filepath}" -n spectrogram -o "{spectrogram_file}"')

    if os.path.isfile(spectrogram_file):
        print_success(f"Spectrogram saved: {spectrogram_file}")
        print_result("Tip", "Open the spectrogram image to check for hidden messages", C.BRIGHT_YELLOW)
        results["spectrograms"].append(spectrogram_file)
    else:
        print_error("Spectrogram generation failed.")
        if output:
            print(f"  {C.DIM}{output}{C.RESET}")


# ============================================================================
#  MODULE 6: STRINGS ANALYSIS
# ============================================================================

def module_strings_analysis(filepath):
    """Run strings, display output, save to strings_output.txt."""
    print_section("MODULE 6: STRINGS ANALYSIS", "📝")

    if not ensure_tool("strings"):
        return ""

    # Run strings with minimum length of 4
    output = run_cmd(f'strings -n 4 "{filepath}"')
    if not output or not output.strip():
        print_warning("No printable strings found.")
        return ""

    lines = output.strip().split("\n")
    print_result("Total Strings", f"{len(lines)} strings found", C.BRIGHT_GREEN)

    # Display full strings output
    print_subsection("Strings Output")
    for line in lines:
        # Highlight potentially interesting strings
        line_stripped = line.strip()
        if any(kw in line_stripped.lower() for kw in [
            "flag", "ctf", "password", "secret", "key", "token",
            "admin", "root", "base64", "hidden", "steg"
        ]):
            print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BG_YELLOW}{C.BLACK}{line_stripped}{C.RESET}")
        else:
            print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.WHITE}{line_stripped}{C.RESET}")

    # Save to file (skip if -no flag is set)
    if not NO_OUTPUT:
        strings_file = os.path.join(OUTPUT_DIR, "strings_output.txt")
        try:
            with open(strings_file, "w", encoding="utf-8", errors="replace") as f:
                f.write(output)
            print_success(f"Strings saved to: {strings_file}")
        except Exception as e:
            print_error(f"Could not save strings file: {e}")

    return output


# ============================================================================
#  MODULE 7: FLAG DETECTION
# ============================================================================

# Flag patterns — case-insensitive
# NOTE: Known CTF formats use [^}\n] to prevent multi-line false positives
# from binary garbage in strings output.
FLAG_PATTERNS = [
    ("flag{}", r"flag\{[^}\n]+\}"),
    ("ctf{}", r"ctf\{[^}\n]+\}"),
    ("thm{}", r"thm\{[^}\n]+\}"),
    ("picoCTF{}", r"picoCTF\{[^}\n]+\}"),
    ("HTB{}", r"HTB\{[^}\n]+\}"),
    ("tryhackme{}", r"tryhackme\{[^}\n]+\}"),
    # Generic: requires 3+ alpha prefix, printable content inside braces,
    # max 100 chars, no newlines — avoids binary garbage false positives
    ("Generic{}", r"[A-Za-z]{3,}\{[A-Za-z0-9_\-+=/.,;:!?@ ]{2,100}\}"),
]


def _is_valid_flag(match_text):
    """
    Validate that a flag match looks legitimate (not binary garbage).
    Returns True if the match is clean printable text.
    """
    # Must be single-line
    if "\n" in match_text or "\r" in match_text:
        return False
    # Must be mostly printable ASCII
    printable = sum(1 for c in match_text if 32 <= ord(c) < 127)
    if len(match_text) == 0 or (printable / len(match_text)) < 0.90:
        return False
    # Reject if too long (real flags are rarely >150 chars)
    if len(match_text) > 200:
        return False
    return True


def find_flags(text):
    """
    Scan text for flag patterns.
    Returns list of (pattern_name, matched_text).
    Filters out false positives from binary data.
    """
    found = []
    seen = set()  # Deduplicate

    for pattern_name, regex in FLAG_PATTERNS:
        matches = re.findall(regex, text, re.IGNORECASE)
        for m in matches:
            if m not in seen and _is_valid_flag(m):
                seen.add(m)
                found.append((pattern_name, m))

    return found


def module_flag_detection(text, source_label="strings"):
    """Search text for CTF flag patterns and display highlighted."""
    print_section("MODULE 7: FLAG DETECTION", "🚩")

    if not text:
        print_warning("No text to search for flags.")
        return

    flags = find_flags(text)

    if flags:
        print_success(f"Found {len(flags)} potential flag(s)!")
        for pattern_name, match in flags:
            print_flag_found(source_label, pattern_name, match)
            results["flags"].append((source_label, pattern_name, match))
    else:
        print_result("Result", "No flags detected.", C.DIM)


# ============================================================================
#  MODULE 8: HASH DETECTION
# ============================================================================

# Hash regex patterns by length
HASH_PATTERNS = {
    "MD5":    (32, r"\b[a-fA-F0-9]{32}\b"),
    "SHA1":   (40, r"\b[a-fA-F0-9]{40}\b"),
    "SHA224": (56, r"\b[a-fA-F0-9]{56}\b"),
    "SHA256": (64, r"\b[a-fA-F0-9]{64}\b"),
    "SHA384": (96, r"\b[a-fA-F0-9]{96}\b"),
    "SHA512": (128, r"\b[a-fA-F0-9]{128}\b"),
}


def find_hashes(text):
    """
    Scan text for hex strings matching known hash lengths.
    Returns dict {hash_type: [matches]}.
    Deduplicates and avoids false positives from longer hashes.
    """
    found = defaultdict(list)
    all_hex = re.findall(r"\b[a-fA-F0-9]{32,128}\b", text)

    seen = set()
    for hex_str in all_hex:
        if hex_str in seen:
            continue
        seen.add(hex_str)

        length = len(hex_str)
        hash_type = classify_hash(length)
        if hash_type:
            found[hash_type].append(hex_str)

    return dict(found)


def classify_hash(length):
    """Classify a hex string by its length to a hash type."""
    length_map = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
    return length_map.get(length)


def module_hash_detection(text, source_label="strings"):
    """Detect hash values in text and display grouped by type."""
    print_section("MODULE 8: HASH DETECTION", "🔑")

    if not text:
        print_warning("No text to search for hashes.")
        return

    hashes = find_hashes(text)

    if hashes:
        total = sum(len(v) for v in hashes.values())
        print_success(f"Found {total} potential hash(es)!")

        # Display grouped by type, sorted by length (smallest first)
        for hash_type in ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]:
            if hash_type in hashes:
                print_subsection(f"{hash_type} ({len(hashes[hash_type])} found)")
                for h in hashes[hash_type]:
                    print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BRIGHT_YELLOW}{h}{C.RESET}")
                    results["hashes"][hash_type].append((source_label, h))

        # Offer to crack detected hashes
        if ask_yes_no("Attempt to crack detected hashes with john?"):
            crack_detected_hashes(hashes)
    else:
        print_result("Result", "No hashes detected.", C.DIM)


# ============================================================================
#  HASH CRACKING (for detected hashes)
# ============================================================================

def crack_detected_hashes(hashes_dict):
    """
    Attempt to crack detected hashes using john the ripper.
    Writes all hashes to a temp file and runs john against it.
    """
    if not ensure_tool("john"):
        return

    # Build hash file in john-compatible format
    hash_file = os.path.join(OUTPUT_DIR, "detected_hashes.txt")
    hash_lines = []

    # Map hash types to john format names
    john_formats = {
        "MD5":    "Raw-MD5",
        "SHA1":   "Raw-SHA1",
        "SHA256": "Raw-SHA256",
        "SHA512": "Raw-SHA512",
    }

    for hash_type, hash_list in hashes_dict.items():
        for h in hash_list:
            hash_lines.append((hash_type, h))

    if not hash_lines:
        return

    # Get wordlist
    wordlist = get_wordlist()
    if not wordlist:
        return

    # Try cracking each hash type separately (john needs --format)
    for hash_type in ["MD5", "SHA1", "SHA256", "SHA512"]:
        type_hashes = [h for ht, h in hash_lines if ht == hash_type]
        if not type_hashes:
            continue

        john_fmt = john_formats.get(hash_type)
        if not john_fmt:
            continue

        tmp_file = os.path.join(OUTPUT_DIR, f"hash_{hash_type}.txt")
        try:
            with open(tmp_file, "w") as f:
                for h in type_hashes:
                    f.write(h + "\n")
        except Exception as e:
            print_error(f"Could not write hash file: {e}")
            continue

        print_result("Cracking", f"{len(type_hashes)} {hash_type} hash(es)...", C.BRIGHT_CYAN)
        output = run_cmd(
            f'john --wordlist="{wordlist}" --format="{john_fmt}" "{tmp_file}"',
            timeout=120
        )
        if output:
            print(f"{C.DIM}{output}{C.RESET}")

        # Check results
        show = run_cmd(f'john --show --format="{john_fmt}" "{tmp_file}"')
        if show and "0 password hashes cracked" not in show:
            print_success(f"{hash_type} hash cracked!")
            print_highlight(show.strip())
            for line in show.strip().split("\n"):
                if ":" in line and "password hash" not in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) >= 2 and parts[1].strip():
                        results["cracked_passwords"].append((f"{hash_type} hash", parts[1].strip()))
        else:
            print_warning(f"No {hash_type} hashes cracked with this wordlist.")

        # Cleanup temp file
        try:
            os.remove(tmp_file)
        except OSError:
            pass


# ============================================================================
#  MODULE 9: AUTO DECODING
# ============================================================================

def is_printable_string(s):
    """
    Check if a string is cleanly printable ASCII (>= 90%).
    Rejects strings containing Unicode replacement characters (garbage decodes).
    """
    if not s:
        return False
    # Reject if it contains replacement character (\ufffd) — sign of bad decode
    if "\ufffd" in s:
        return False
    printable_count = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t")
    return (printable_count / len(s)) >= 0.90


def try_base64(s):
    """Attempt base64 decode. Returns decoded string or None."""
    try:
        # Must be valid base64 chars and reasonable length
        if not re.match(r'^[A-Za-z0-9+/]+=*$', s):
            return None
        if len(s) < 4:
            return None
        decoded = base64.b64decode(s).decode("utf-8", errors="replace")
        if is_printable_string(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def try_base32(s):
    """Attempt base32 decode. Returns decoded string or None."""
    try:
        if not re.match(r'^[A-Z2-7]+=*$', s.upper()):
            return None
        if len(s) < 4:
            return None
        decoded = base64.b32decode(s.upper()).decode("utf-8", errors="replace")
        if is_printable_string(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def try_base85(s):
    """Attempt base85 (ASCII85) decode. Returns decoded string or None."""
    try:
        if len(s) < 4:
            return None
        decoded = base64.b85decode(s).decode("utf-8", errors="replace")
        if is_printable_string(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def try_hex_decode(s):
    """Attempt hex decode. Returns decoded string or None."""
    try:
        if not re.match(r'^[A-Fa-f0-9]+$', s):
            return None
        if len(s) < 4 or len(s) % 2 != 0:
            return None
        decoded = bytes.fromhex(s).decode("utf-8", errors="replace")
        if is_printable_string(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def try_rot13(s):
    """Apply ROT13. Only return if result contains flag-like patterns."""
    try:
        decoded = codecs.decode(s, "rot_13")
        # Only report if the ROT13 version contains interesting patterns
        flags = find_flags(decoded)
        if flags or any(kw in decoded.lower() for kw in ["flag", "password", "secret", "key", "ctf"]):
            return decoded
    except Exception:
        pass
    return None


def try_url_decode(s):
    """Attempt URL decode. Returns decoded string if different from input."""
    try:
        decoded = urllib.parse.unquote(s)
        if decoded != s and is_printable_string(decoded):
            return decoded
    except Exception:
        pass
    return None


def module_auto_decode(text):
    """
    Attempt multiple decodings on candidate strings from the text.
    For each successful decode, re-run flag detection.
    """
    print_section("MODULE 9: AUTO DECODING", "🔓")

    if not text:
        print_warning("No text to attempt decoding on.")
        return

    # Extract candidate strings (words that look encoded)
    # Look for long alphanumeric strings, base64-like, hex-like, url-encoded
    # Cap individual string length at 500 to avoid wasting time on huge blobs
    MAX_CANDIDATE_LEN = 500
    MAX_CANDIDATES = 500  # Hard cap to keep runtime reasonable
    candidates = set()

    # Base64 candidates: long alphanumeric with possible padding
    candidates.update(s for s in re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', text) if len(s) <= MAX_CANDIDATE_LEN)
    # Hex candidates: even-length hex strings
    candidates.update(s for s in re.findall(r'\b[A-Fa-f0-9]{8,}\b', text) if len(s) <= MAX_CANDIDATE_LEN)
    # URL-encoded candidates
    candidates.update(re.findall(r'(?:%[0-9A-Fa-f]{2}){3,}', text))
    # Base32 candidates
    candidates.update(s for s in re.findall(r'[A-Z2-7]{8,}={0,6}', text) if len(s) <= MAX_CANDIDATE_LEN)
    # General long strings for ROT13
    candidates.update(s for s in re.findall(r'[A-Za-z]{12,}', text) if len(s) <= MAX_CANDIDATE_LEN)

    # Enforce hard cap
    if len(candidates) > MAX_CANDIDATES:
        print_warning(f"Too many candidates ({len(candidates)}). Capping at {MAX_CANDIDATES}.")
        candidates = set(list(candidates)[:MAX_CANDIDATES])

    if not candidates:
        print_result("Result", "No encoded candidates found.", C.DIM)
        return

    print_result("Candidates", f"Testing {len(candidates)} string(s) for encoded content", C.CYAN)

    decoders = [
        ("Base64", try_base64),
        ("Base32", try_base32),
        ("Base85", try_base85),
        ("Hex",    try_hex_decode),
        ("ROT13",  try_rot13),
        ("URL",    try_url_decode),
    ]

    decode_count = 0
    seen_decoded = set()

    for candidate in candidates:
        for enc_name, decoder_fn in decoders:
            result = decoder_fn(candidate)
            if result and result not in seen_decoded:
                seen_decoded.add(result)
                decode_count += 1

                print(f"\n  {C.BG_GREEN}{C.BLACK}{C.BOLD} {enc_name} DECODED {C.RESET}")
                print(f"  {C.DIM}Original : {candidate[:80]}{'...' if len(candidate) > 80 else ''}{C.RESET}")
                print(f"  {C.BRIGHT_GREEN}Decoded  : {result[:200]}{'...' if len(result) > 200 else ''}{C.RESET}")

                results["decoded"].append((enc_name, candidate[:80], result[:200]))

                # Re-run flag detection on decoded content
                decoded_flags = find_flags(result)
                if decoded_flags:
                    for pattern_name, match in decoded_flags:
                        print_flag_found(f"decoded:{enc_name}", pattern_name, match)
                        results["flags"].append((f"decoded:{enc_name}", pattern_name, match))

    if decode_count == 0:
        print_result("Result", "No successful decodings.", C.DIM)
    else:
        print_success(f"Successfully decoded {decode_count} string(s).")


# ============================================================================
#  MODULE 10: STEGANOGRAPHY ANALYSIS (LAST TOOL)
# ============================================================================

def module_steganography(filepath, ext):
    """
    Run steghide info for supported formats (jpg, jpeg, bmp, wav, au).
    This MUST be the final analysis module.
    """
    print_section("MODULE 10: STEGANOGRAPHY ANALYSIS", "🕵️")

    if not is_steghide_supported(ext):
        print_result("Status", f"steghide does not support .{ext} files.", C.DIM)

        # Suggest zsteg for PNG
        if ext == "png":
            print_result("Tip", "For PNG steganography, try: zsteg <file>", C.BRIGHT_YELLOW)
            if ensure_tool("zsteg"):
                if ask_yes_no("Run zsteg on this PNG file?"):
                    run_zsteg(filepath)
        return

    if not ensure_tool("steghide"):
        return

    # Run steghide info with -p "" to bypass interactive passphrase prompt
    # Without this, steghide blocks on stdin waiting for user input → timeout
    print_result("Running", "steghide info...", C.CYAN)
    output = run_cmd(f'steghide info "{filepath}" -p "" 2>&1', timeout=30)

    if output:
        print(f"\n{C.WHITE}{output}{C.RESET}")

        # Check if embedded data is indicated
        if "embedded" in output.lower() or "size:" in output.lower():
            print_success("Steghide reports possible embedded data!")

            if ask_yes_no("Attempt to extract embedded data?"):
                steghide_extract(filepath)
        else:
            print_result("Result", "No steghide-embedded data detected.", C.DIM)
    else:
        print_warning("steghide returned no output.")


def steghide_extract(filepath):
    """Run steghide extract with user-provided password."""
    try:
        password = input(f"  {C.BRIGHT_YELLOW}?  Enter password (or press Enter for empty): {C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    # Determine output filename
    extract_name = f"steghide_extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    extract_path = os.path.join(OUTPUT_DIR, extract_name)

    if password:
        cmd = f'steghide extract -sf "{filepath}" -p "{password}" -xf "{extract_path}" -f'
    else:
        cmd = f'steghide extract -sf "{filepath}" -p "" -xf "{extract_path}" -f'

    output = run_cmd(cmd)

    if os.path.isfile(extract_path):
        print_success(f"Data extracted successfully: {extract_path}")
        results["extracted_files"].append(extract_path)

        # Offer rename
        offer_rename(extract_path)

        # Show content preview
        try:
            with open(extract_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(1000)
            if content.strip():
                print_subsection("Extracted Content Preview")
                print(f"{C.BRIGHT_GREEN}{content}{C.RESET}")
                # Check for flags in extracted content
                flags = find_flags(content)
                if flags:
                    for pname, m in flags:
                        print_flag_found("steghide_extract", pname, m)
                        results["flags"].append(("steghide_extract", pname, m))
        except Exception:
            print_result("Note", "Extracted file appears to be binary.", C.DIM)
    else:
        print_error("Extraction failed. Wrong password or no embedded data.")
        if output:
            print(f"  {C.DIM}{output}{C.RESET}")


def offer_rename(extracted_file):
    """Offer to rename extracted file with timestamp and custom name."""
    if ask_yes_no("Rename the extracted file?"):
        try:
            new_name = input(f"  {C.BRIGHT_YELLOW}?  Enter new filename (with extension): {C.RESET}").strip()
            if new_name:
                new_path = os.path.join(os.path.dirname(extracted_file), new_name)
                os.rename(extracted_file, new_path)
                print_success(f"Renamed to: {new_path}")
                # Update results
                if extracted_file in results["extracted_files"]:
                    idx = results["extracted_files"].index(extracted_file)
                    results["extracted_files"][idx] = new_path
        except Exception as e:
            print_error(f"Rename failed: {e}")


def run_zsteg(filepath):
    """BONUS: Run zsteg on PNG files for LSB steganography detection."""
    print_subsection("Zsteg — LSB Steganography")

    output = run_cmd(f'zsteg "{filepath}" 2>&1')
    if output and output.strip():
        print(f"{C.WHITE}{output}{C.RESET}")

        # Check for flags in zsteg output
        flags = find_flags(output)
        if flags:
            for pname, m in flags:
                print_flag_found("zsteg", pname, m)
                results["flags"].append(("zsteg", pname, m))
    else:
        print_result("Result", "zsteg found nothing.", C.DIM)


# ============================================================================
#  BONUS: FOREMOST CARVING
# ============================================================================

def module_foremost(filepath):
    """Run foremost as a secondary file carver alongside binwalk."""
    print_subsection("Foremost — File Carving")

    if not ensure_tool("foremost"):
        return

    if not ask_yes_no("Run foremost file carver for additional extraction?"):
        return

    output_dir = os.path.join(OUTPUT_DIR, "foremost")
    # Remove if exists — foremost refuses to write to existing dir
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)

    output = run_cmd(f'foremost -i "{filepath}" -o "{output_dir}"', timeout=180)

    if output:
        print(f"{C.DIM}{output}{C.RESET}")

    # List carved files
    carved = []
    for root, dirs, files in os.walk(output_dir):
        for fname in files:
            if fname != "audit.txt":
                fpath = os.path.join(root, fname)
                carved.append(fpath)
                results["extracted_files"].append(fpath)

    if carved:
        print_success(f"Foremost carved {len(carved)} file(s):")
        for f in carved:
            print_result("Carved", f, C.BRIGHT_GREEN)
    else:
        print_result("Result", "Foremost found no additional files.", C.DIM)


# ============================================================================
#  MODULE 11: FINAL SUMMARY
# ============================================================================

def module_final_summary():
    """Aggregated display of ALL findings from the entire analysis."""
    print_section("FINAL SUMMARY — ALL FINDINGS", "📊")

    has_findings = False

    # ── Input File Hashes ──
    if results["file_hashes"]:
        print_subsection("Input File Integrity")
        for algo, digest in results["file_hashes"].items():
            print_result(algo, digest, C.BRIGHT_YELLOW)

    # ── Flags Found ──
    if results["flags"]:
        has_findings = True
        print_subsection(f"🚩 Flags Found ({len(results['flags'])})")
        for source, pattern, match in results["flags"]:
            print(f"  {C.BG_RED}{C.BRIGHT_WHITE}{C.BOLD}  FLAG  {C.RESET} "
                  f"{C.BRIGHT_GREEN}{match}{C.RESET} "
                  f"{C.DIM}[{pattern}] from {source}{C.RESET}")

    # ── Hashes Found ──
    total_hashes = sum(len(v) for v in results["hashes"].values())
    if total_hashes > 0:
        has_findings = True
        print_subsection(f"🔑 Hashes Found ({total_hashes})")
        for hash_type in ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]:
            if hash_type in results["hashes"]:
                for source, value in results["hashes"][hash_type]:
                    print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BOLD}{hash_type}{C.RESET}: "
                          f"{C.BRIGHT_YELLOW}{value}{C.RESET} "
                          f"{C.DIM}(from {source}){C.RESET}")

    # ── Decoded Secrets ──
    if results["decoded"]:
        has_findings = True
        print_subsection(f"🔓 Decoded Secrets ({len(results['decoded'])})")
        for enc, original, decoded in results["decoded"]:
            print(f"  {C.DIM}{C.CYAN}│{C.RESET} {C.BOLD}[{enc}]{C.RESET} "
                  f"{C.BRIGHT_GREEN}{decoded}{C.RESET}")

    # ── Extracted Files ──
    if results["extracted_files"]:
        has_findings = True
        print_subsection(f"📦 Extracted Files ({len(results['extracted_files'])})")
        for f in results["extracted_files"]:
            print_result("File", f, C.BRIGHT_GREEN)

    # ── Cracked Passwords ──
    if results["cracked_passwords"]:
        has_findings = True
        print_subsection(f"🔐 Cracked Passwords ({len(results['cracked_passwords'])})")
        for archive, password in results["cracked_passwords"]:
            print(f"  {C.BG_GREEN}{C.BLACK}{C.BOLD}  CRACKED  {C.RESET} "
                  f"{C.BRIGHT_GREEN}{archive}{C.RESET} → "
                  f"{C.BRIGHT_YELLOW}{C.BOLD}{password}{C.RESET}")

    # ── Spectrograms ──
    if results["spectrograms"]:
        has_findings = True
        print_subsection(f"🎵 Generated Spectrograms ({len(results['spectrograms'])})")
        for f in results["spectrograms"]:
            print_result("Spectrogram", f, C.BRIGHT_CYAN)

    # ── Suspicious Metadata ──
    if results["suspicious_metadata"]:
        has_findings = True
        print_subsection(f"⚠ Suspicious Metadata ({len(results['suspicious_metadata'])})")
        for field, value in results["suspicious_metadata"]:
            print(f"  {C.BG_YELLOW}{C.BLACK} {field} {C.RESET} → {C.BRIGHT_YELLOW}{value}{C.RESET}")

    # ── No Findings ──
    if not has_findings:
        print_result("Result", "No significant findings detected.", C.DIM)
        print_result("Tip", "Try manual analysis with specialized tools.", C.BRIGHT_YELLOW)

    # ── JSON Report Export ──
    export_json_report()

    # ── Footer ──
    print(f"\n{C.BRIGHT_CYAN}{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"{C.BRIGHT_WHITE}{C.BOLD}  KEZMO analysis complete.{C.RESET}")
    print(f"{C.DIM}  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.BRIGHT_CYAN}{C.BOLD}{'═' * 60}{C.RESET}\n")


# ============================================================================
#  BONUS: JSON REPORT EXPORT
# ============================================================================

def export_json_report():
    """Save all findings to a kezmo_report.json file."""
    print_subsection("JSON Report")

    report = {
        "tool": "KEZMO",
        "version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "target_file": sys.argv[1] if len(sys.argv) > 1 else "unknown",
        "file_hashes": results["file_hashes"],
        "flags": [
            {"source": s, "pattern": p, "match": m}
            for s, p, m in results["flags"]
        ],
        "hashes": {
            htype: [{"source": s, "value": v} for s, v in entries]
            for htype, entries in results["hashes"].items()
        },
        "decoded_secrets": [
            {"encoding": e, "original": o, "decoded": d}
            for e, o, d in results["decoded"]
        ],
        "extracted_files": results["extracted_files"],
        "cracked_passwords": [
            {"archive": a, "password": p}
            for a, p in results["cracked_passwords"]
        ],
        "spectrograms": results["spectrograms"],
        "suspicious_metadata": [
            {"field": f, "value": v}
            for f, v in results["suspicious_metadata"]
        ],
    }

    if NO_OUTPUT:
        print_result("Report", "Skipped (running with -no flag)", C.DIM)
        return

    report_path = os.path.join(OUTPUT_DIR, "kezmo_report.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print_success(f"Report exported: {report_path}")
    except Exception as e:
        print_error(f"Could not export JSON report: {e}")


# ============================================================================
#                          MAIN ORCHESTRATOR
# ============================================================================

def main():
    """Entry point — argument parsing and orchestration of all 11 modules."""

    global NO_OUTPUT

    # ── Parse -no flag ──
    args = [a for a in sys.argv[1:] if a != "-no"]
    if "-no" in sys.argv:
        NO_OUTPUT = True

    # ── Argument check ──
    if len(args) != 1:
        print_banner()
        print(f"  {C.BRIGHT_RED}Usage: python3 kezmo.py <file> [-no]{C.RESET}")
        print(f"  {C.DIM}Example: python3 kezmo.py suspicious_image.jpg{C.RESET}")
        print(f"  {C.DIM}         python3 kezmo.py file.jpg -no  (no output files){C.RESET}\n")
        sys.exit(1)

    filepath = args[0]

    # ── File existence check ──
    if not os.path.isfile(filepath):
        print_banner()
        print_error(f"File not found: {filepath}")
        sys.exit(1)

    # ── Create output directory: <filename>_output/ ──
    global OUTPUT_DIR
    OUTPUT_DIR = os.path.join(os.path.dirname(filepath) or ".", f"{os.path.basename(filepath)}_output")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Banner ──
    print_banner()
    print(f"  {C.BRIGHT_WHITE}{C.BOLD}Target:{C.RESET} {C.BRIGHT_GREEN}{filepath}{C.RESET}")
    print(f"  {C.BRIGHT_WHITE}{C.BOLD}Output:{C.RESET} {C.BRIGHT_GREEN}{OUTPUT_DIR}/{C.RESET}")
    print(f"  {C.DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  {C.BRIGHT_CYAN}{'═' * 55}{C.RESET}")

    ext = get_file_extension(filepath)
    total_modules = 11

    # ═══════════════════════════════════════════════════════
    #  MODULE 1: File Type Check + Entropy + Hexdump
    # ═══════════════════════════════════════════════════════
    print_progress(1, total_modules, "File Type Identification")
    file_type_output = module_file_type(filepath)

    # ═══════════════════════════════════════════════════════
    #  MODULE 2: EXIF / Metadata Analysis
    # ═══════════════════════════════════════════════════════
    print_progress(2, total_modules, "EXIF / Metadata Analysis")
    exif_output = module_exif_analysis(filepath)

    # ═══════════════════════════════════════════════════════
    #  MODULE 3: Binwalk Analysis
    # ═══════════════════════════════════════════════════════
    print_progress(3, total_modules, "Binwalk Embedded File Analysis")
    module_binwalk_analysis(filepath)

    # BONUS: Foremost carving (after binwalk)
    if ensure_tool("foremost"):
        module_foremost(filepath)

    # ═══════════════════════════════════════════════════════
    #  MODULE 4: Archive / Password Cracking
    # ═══════════════════════════════════════════════════════
    print_progress(4, total_modules, "Archive / Password Analysis")
    if is_archive(ext) or is_document(ext):
        module_archive_analysis(filepath, ext)
    else:
        print_section("MODULE 4: ARCHIVE / PASSWORD ANALYSIS", "🔐")
        print_result("Status", "Not an archive or document file. Skipping.", C.DIM)

    # ═══════════════════════════════════════════════════════
    #  MODULE 5: Audio Spectrogram
    # ═══════════════════════════════════════════════════════
    print_progress(5, total_modules, "Audio Spectrogram Analysis")
    module_audio_analysis(filepath, ext)

    # ═══════════════════════════════════════════════════════
    #  MODULE 6: Strings Analysis
    # ═══════════════════════════════════════════════════════
    print_progress(6, total_modules, "Strings Analysis")
    strings_output = module_strings_analysis(filepath)

    # ═══════════════════════════════════════════════════════
    #  MODULE 7: Flag Detection
    # ═══════════════════════════════════════════════════════
    print_progress(7, total_modules, "Flag Detection")
    module_flag_detection(strings_output, "strings")

    # Also scan EXIF output for flags
    if exif_output:
        hidden_flags = find_flags(exif_output)
        if hidden_flags:
            print_subsection("Flags in EXIF Metadata")
            for pattern, match in hidden_flags:
                print_flag_found("exif_metadata", pattern, match)
                results["flags"].append(("exif_metadata", pattern, match))

    # ═══════════════════════════════════════════════════════
    #  MODULE 8: Hash Detection
    # ═══════════════════════════════════════════════════════
    print_progress(8, total_modules, "Hash Detection")
    module_hash_detection(strings_output, "strings")

    # Also scan EXIF output for hashes
    if exif_output:
        exif_hashes = find_hashes(exif_output)
        if exif_hashes:
            for htype, values in exif_hashes.items():
                for v in values:
                    results["hashes"][htype].append(("exif_metadata", v))

    # ═══════════════════════════════════════════════════════
    #  MODULE 9: Auto Decoding
    # ═══════════════════════════════════════════════════════
    print_progress(9, total_modules, "Auto Decoding")
    module_auto_decode(strings_output)

    # ═══════════════════════════════════════════════════════
    #  MODULE 10: Steganography (LAST analysis module)
    # ═══════════════════════════════════════════════════════
    print_progress(10, total_modules, "Steganography Analysis")
    module_steganography(filepath, ext)

    # ═══════════════════════════════════════════════════════
    #  MODULE 11: Final Summary
    # ═══════════════════════════════════════════════════════
    print_progress(11, total_modules, "Final Summary")
    module_final_summary()


# ============================================================================
#  ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.BRIGHT_RED}{C.BOLD}[!] Interrupted by user. Exiting KEZMO.{C.RESET}\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n  {C.BRIGHT_RED}{C.BOLD}[FATAL] Unhandled error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
