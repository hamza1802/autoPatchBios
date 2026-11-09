#!/usr/bin/env python3
"""
================================================================================
                    BIOS PATCHING FOR BEGINNERS - MASTER TOOL
================================================================================
A unified, easy-to-use BIOS unlocking tool designed for beginners.
Supports:
  1. ThinkPad (Lenovo up to 8th Gen - DXE Injection + NVRAM Replace)
  2. HP (EliteBook, ProBook, Pavilion - NVRAM Password Invalidation)
  3. Dell (Latitude, OptiPlex, Precision - NVRAM Password Invalidation)
  4. Other / Simple (Fujitsu, Acer, Asus, Phoenix, Insyde, AMI - Direct NVRAM Defusal)
  5. Auto-Detect (Scan dump and automatically apply the best method)
================================================================================
"""

import os
import sys
import shutil
import glob
import subprocess
import binascii
import uuid
import re

# GUI File Dialog
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(SCRIPT_DIR, "tools")
THINKPAD_DIR = os.path.join(SCRIPT_DIR, "thinkpad")
DELL_DIR = os.path.join(SCRIPT_DIR, "dell")
HP_DIR = os.path.join(SCRIPT_DIR, "hp")

PASSWORD_VARS_SIMPLE = [
    # Phoenix / Insyde / Fujitsu
    "SystemSupervisorPw",
    "SystemUserPw",
    "SupervisorPw",
    "UserPw",
    # Generic UEFI / HP / Dell
    "AdminPassword",
    "SetupPassword",
    "PowerOnPassword",
    "SystemPassword",
    "HddPassword",
    # Lenovo NVRAM Config
    "LenovoSecurityConfig",
    "LenovoSystemConfig",
    "IsSvpSet",
    "IsPopSet",
    "IsUpSet",
    "SvpData",
    "PopData",
    "PwdData",
]


def print_banner():
    banner = r"""
===============================================================================
               ____  _____ ____  _____   ____       _       _               
              | __ )|_   _/ ___||  ___| |  _ \ __ _| |_ ___| |__            
              |  _ \  | | \___ \| |_    | |_) / _` | __/ __| '_ \           
              | |_) | | |  ___) |  _|   |  __/ (_| | || (__| | | |          
              |____/  |_| |____/|_|     |_|   \__,_|\__\___|_| |_|          
                         PATCHING FOR BEGINNERS                             
===============================================================================
"""
    print(banner)


def choose_file_gui():
    """Pop up a native file picker dialog for the user to select the BIOS dump."""
    if not TKINTER_AVAILABLE:
        print("[!] GUI File Dialog not available. Please enter path manually.")
        return input("Enter full path to BIOS dump: ").strip().strip('"')

    print("[*] Opening file selection window... Please choose your BIOS dump.")
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    root.focus_force()

    initial_dir = SCRIPT_DIR
    file_path = filedialog.askopenfilename(
        parent=root,
        title="Select BIOS Dump File (.bin / .rom)",
        initialdir=initial_dir,
        filetypes=[
            ("BIOS Dump Files", "*.bin;*.rom;*.bak"),
            ("Binary Files", "*.bin"),
            ("ROM Files", "*.rom"),
            ("All Files", "*.*")
        ]
    )
    root.destroy()

    if not file_path:
        print("[-] File selection cancelled.")
        return None

    return os.path.normpath(file_path)


def create_safety_backup(source_file):
    """Creates a safety backup before any operation."""
    base, ext = os.path.splitext(source_file)
    backup_path = f"{base}_ORIGINAL_BACKUP{ext}"
    if not os.path.exists(backup_path):
        shutil.copy2(source_file, backup_path)
        print(f"[+] Safety backup created: {os.path.basename(backup_path)}")
    return backup_path


# ------------------------------------------------------------------------------
# ENGINE 1: SIMPLE / OTHER (Fujitsu, Acer, Asus, Clevo, Phoenix, Insyde, AMI)
# ------------------------------------------------------------------------------
def patch_simple_nvram(source_file):
    print("\n" + "="*70)
    print(" >>> ENGINE: OTHER / SIMPLE (NVRAM Password Defusal)")
    print("="*70)
    print("[*] Target: Phoenix, Insyde, AMI, Fujitsu, Acer, Asus, Clevo, etc.")
    print("[*] Method: Locate active NVRAM password entries, mark as VAR_DELETED,")
    print("            defuse lookup identifiers, and clear password data blocks.")

    create_safety_backup(source_file)

    with open(source_file, "rb") as f:
        data = bytearray(f.read())

    file_size = len(data)
    patched_records = 0

    # Search for variable records (\xaa\x55)
    pos = 0
    while True:
        idx = data.find(b"\xaa\x55", pos)
        if idx == -1:
            break

        if idx + 0x3c < file_size:
            state = data[idx + 2]
            name_size = int.from_bytes(data[idx + 0x24 : idx + 0x28], "little")
            data_size = int.from_bytes(data[idx + 0x28 : idx + 0x2c], "little")

            if 4 <= name_size <= 256 and 0 <= data_size <= 65536 and idx + 0x3c + name_size + data_size <= file_size:
                name_bytes = data[idx + 0x3c : idx + 0x3c + name_size]
                try:
                    name = name_bytes.decode("utf-16le").rstrip("\x00")
                except Exception:
                    name = ""

                for target in PASSWORD_VARS_SIMPLE:
                    if name == target:
                        print(f" [+] Found '{name}' at offset 0x{idx:08X} (State: 0x{state:02X}, Size: {data_size} bytes)")
                        if state != 0x3D:
                            # 1. State -> VAR_DELETED (0x3D)
                            data[idx + 2] = 0x3D
                            # 2. Defuse name in NVRAM ('S'/'A'/etc -> '_')
                            data[idx + 0x3c] = ord("_")
                            data[idx + 0x3c + 1] = 0x00
                            # 3. Wipe payload
                            payload_offset = idx + 0x3c + name_size
                            for i in range(data_size):
                                data[payload_offset + i] = 0x00

                            patched_records += 1
                            print(f"     -> Neutralized '{name}' successfully.")
                        else:
                            print(f"     -> Already marked as deleted (0x3D).")

        pos = idx + 2

    # Also check generic UTF-16 strings in NVRAM for AMI SystemSupervisorPw if standard header differed
    if patched_records == 0:
        print("[*] Performing secondary deep scan for AMI/Insyde variables...")
        for target in ["SystemSupervisorPw", "SystemUserPw", "AdminPassword", "SetupPassword"]:
            pat = target.encode("utf-16le")
            match_pos = 0
            while True:
                found = data.find(pat, match_pos)
                if found == -1:
                    break
                # Only patch if within BIOS NVRAM area (upper half of flash) and not in code driver table
                if found < file_size - 0x100000:
                    data[found] = ord("_")
                    data[found + 1] = 0x00
                    patched_records += 1
                    print(f" [+] Defused '{target}' variable name at 0x{found:08X}")
                match_pos = found + 2

    if patched_records == 0:
        print("[!] No active password variables found in this dump.")
        print("    The dump might already be unlocked or uses a non-standard store.")
        return False

    base, ext = os.path.splitext(source_file)
    out_file = f"{base}_PATCHED{ext}"
    with open(out_file, "wb") as f:
        f.write(data)

    print("\n" + "-"*70)
    print(f"[SUCCESS] Patched BIOS created: {out_file}")
    print(f"          Total records neutralized: {patched_records}")
    print("-"*70)
    print("\n[HOW TO USE THIS PATCH]")
    print("STEP 1: Flash the patched file back onto the motherboard SPI chip.")
    print("STEP 2: Power on the computer and press F2 / Del / F10 to enter BIOS Setup.")
    print("STEP 3: The password prompt will be gone!")
    print("STEP 4: Press F9 to Load Setup Defaults, then F10 to Save & Exit.")
    print("        This makes the motherboard regenerate a clean default NVRAM.")
    return True


# ------------------------------------------------------------------------------
# ENGINE 2: THINKPAD (Lenovo up to 8th Gen)
# ------------------------------------------------------------------------------
def hex_to_guid(hex_str):
    h = binascii.unhexlify(hex_str)
    data1 = h[0:4][::-1]
    data2 = h[4:6][::-1]
    data3 = h[6:8][::-1]
    data4a = h[8:10]
    data4b = h[10:16]
    components = [data1, data2, data3, data4a, data4b]
    hex_bytes = [binascii.hexlify(d) for d in components]
    return '-'.join(bytes.decode(b) for b in hex_bytes)


def file_guid(filepath):
    with open(filepath, 'rb') as f:
        data = f.read(16)
    return hex_to_guid(binascii.hexlify(data))


def patch_thinkpad(source_file):
    print("\n" + "="*70)
    print(" >>> ENGINE: THINKPAD (Lenovo AutoPatch)")
    print("="*70)
    print("[*] Target: ThinkPads up to 8th Gen (T440-T480, X240-X280, X380, X1, etc.)")
    print("[*] Method: Inject custom DXE drivers with UEFIReplace + clean NVRAM volume.")

    uefireplace_exe = os.path.join(TOOLS_DIR, "UEFIReplace.exe")
    if not os.path.exists(uefireplace_exe):
        # Fallback to parent dir if running from subfolder
        uefireplace_exe = os.path.join(SCRIPT_DIR, "..", "tools", "UEFIReplace.exe")
    if not os.path.exists(uefireplace_exe):
        print(f"[!] Error: UEFIReplace.exe not found at {uefireplace_exe}")
        return False

    dxe_dir = os.path.join(THINKPAD_DIR, "DXE")
    if not os.path.exists(dxe_dir):
        dxe_dir = os.path.join(SCRIPT_DIR, "..", "patch", "DXE")

    vol_dir = os.path.join(THINKPAD_DIR, "VOLUMES")
    if not os.path.exists(vol_dir):
        vol_dir = os.path.join(SCRIPT_DIR, "..", "patch", "VOLUMES")

    drivers = glob.glob(os.path.join(dxe_dir, "*.ffs"))
    if not drivers:
        print("[!] Error: No DXE drivers found in thinkpad/DXE/")
        return False

    create_safety_backup(source_file)

    base, ext = os.path.splitext(source_file)
    patched_file = f"{base}_PATCHED{ext}"
    shutil.copyfile(source_file, patched_file)

    print(f"\n[*] Injecting {len(drivers)} DXE drivers with UEFIReplace...")
    temp_bin = os.path.join(SCRIPT_DIR, "temp_step.bin")

    for i, driver in enumerate(drivers, 1):
        name = os.path.basename(driver)
        guid = file_guid(driver)
        print(f" [{i}/{len(drivers)}] Injecting {name} (GUID: {guid})")
        code = subprocess.call([
            uefireplace_exe, patched_file, guid, '07', driver, '-asis', '-all', '-o', temp_bin
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if code != 0 or not os.path.exists(temp_bin):
            print("[!] Error: UEFIReplace injection failed. File may be corrupted.")
            if os.path.exists(patched_file):
                os.remove(patched_file)
            return False

        os.remove(patched_file)
        os.rename(temp_bin, patched_file)

    # Clean / Replace NVRAM Volume
    vol_patches = glob.glob(os.path.join(vol_dir, "*.vol"))
    if vol_patches:
        print(f"\n[*] Applying clean NVRAM volume patch...")
        with open(patched_file, "rb") as f:
            content = f.read()

        for vol_file in vol_patches:
            vol_name = os.path.basename(vol_file)
            with open(vol_file, "rb") as vf:
                vol_content = vf.read()

            pattern = vol_content[:48]
            pos = content.find(pattern)
            if pos != -1:
                header = content[pos+16 : pos+72]
                target_size = int.from_bytes(header[16:19], 'little')
                vol_header = vol_content[16:72]
                vol_size = int.from_bytes(vol_header[16:19], 'little')
                if vol_size == target_size:
                    content = content[:pos] + vol_content + content[pos + vol_size:]
                    print(f" [+] Replaced NVRAM volume: {vol_name} at offset 0x{pos:08X}")
                else:
                    print(f" [-] Volume size mismatch ({vol_size} vs {target_size}). Skipped.")
            else:
                print(f" [-] Pattern for {vol_name} not found in dump. Skipped.")

        with open(patched_file, "wb") as f:
            f.write(content)

    print("\n" + "-"*70)
    print(f"[SUCCESS] Patched ThinkPad BIOS created: {patched_file}")
    print("-"*70)
    print("\n[HOW TO USE THE THINKPAD PATCH]")
    print("STEP 1: Flash the patched BIOS file to your chip.")
    print("STEP 2: Boot the machine (tape down the bottom anti-tamper switch).")
    print("STEP 3: Press Enter / F1 to enter BIOS Setup.")
    print("STEP 4: When prompted for Supervisor Password, type ANY character and press Enter.")
    print("STEP 5: Press Enter when Hardware ID is displayed.")
    print("STEP 6: Press Space bar 2x when prompted.")
    print("STEP 7: Turn off the machine.")
    print("STEP 8: Restore the ORIGINAL backup BIOS to the chip.")
    print("STEP 9: Power on, enter BIOS Setup, and load factory defaults (F9). Password is gone!")
    return True


# ------------------------------------------------------------------------------
# ENGINE 3: HP (Hewlett-Packard)
# ------------------------------------------------------------------------------
def patch_hp(source_file):
    print("\n" + "="*70)
    print(" >>> ENGINE: HP (Hewlett-Packard Unlock)")
    print("="*70)
    print("[*] Target: HP EliteBook, ProBook, Pavilion, ZBook")

    # Scan for HP password variables
    success = patch_simple_nvram(source_file)
    if success:
        print("\n[HP SPECIFIC NOTES]")
        print("* Press F10 (or Esc -> F10) on boot to enter HP BIOS Setup.")
        print("* In Security menu, verify Administrator Password is 'Not Installed'.")
        print("* Note for HP Sure Start: If the laptop has Sure Start hardware enabled,")
        print("  it may self-heal from backup ROM if a signature violation is detected.")
    return success


# ------------------------------------------------------------------------------
# ENGINE 4: DELL (Latitude, Precision, OptiPlex, Inspiron)
# ------------------------------------------------------------------------------
def patch_dell(source_file):
    print("\n" + "="*70)
    print(" >>> ENGINE: DELL (Dell BIOS Unlock)")
    print("="*70)
    print("[*] Target: Dell Latitude, OptiPlex, Precision, Inspiron")

    # If user provided a Dell .exe update package, offer extraction
    if source_file.lower().endswith(".exe"):
        print("[*] Detected Dell executable update file.")
        pfs_script = os.path.join(DELL_DIR, "Dell_PFS_Extract.py")
        if os.path.exists(pfs_script):
            print("[*] Running Dell PFS Extractor to unpack BIOS payload...")
            subprocess.call([sys.executable, pfs_script, source_file])
            print("[*] PFS Extraction complete. Check current folder for extracted .bin files.")
            return True

    success = patch_simple_nvram(source_file)
    if success:
        print("\n[DELL SPECIFIC NOTES]")
        print("* Press F2 on boot to enter Dell BIOS Setup.")
        print("* Verify Admin Password status is 'Not Set'.")
        print("* In 'Restore Settings', choose 'BIOS Defaults' and reboot.")
    return success


# ------------------------------------------------------------------------------
# ENGINE 5: AUTO-DETECT
# ------------------------------------------------------------------------------
def auto_detect_and_patch(source_file):
    print("\n" + "="*70)
    print(" >>> ENGINE: AUTO-DETECT (Deep Firmware Scanner)")
    print("="*70)
    print(f"[*] Analyzing firmware binary: {os.path.basename(source_file)}...")

    with open(source_file, "rb") as f:
        data = f.read()

    file_size = len(data)
    print(f"[*] Size: {file_size:,} bytes ({file_size // (1024*1024)} MB)")

    # Vendor signatures
    is_thinkpad = (b"LENOVO" in data or b"ThinkPad" in data) and (b"LenovoTranslateService" in data or b"TCG2_BIOS" in data)
    is_fujitsu = b"FUJITSU" in data or b"Fujitsu" in data or b"LIFEBOOK" in data
    is_hp = b"HEWLETT-PACKARD" in data or b"HPQOEM" in data or b"Hewlett-Packard" in data
    is_dell = b"DELL" in data or b"Dell Inc." in data

    # Password variables
    has_phoenix_pw = b"SystemSupervisorPw" in data
    has_generic_pw = b"AdminPassword" in data or b"SetupPassword" in data

    print("\n--- Detection Results ---")
    if is_fujitsu:
        print(" [!] Detected Vendor: Fujitsu (Lifebook / Celsius / Esprimo)")
    elif is_thinkpad:
        print(" [!] Detected Vendor: Lenovo ThinkPad")
    elif is_hp:
        print(" [!] Detected Vendor: HP (Hewlett-Packard)")
    elif is_dell:
        print(" [!] Detected Vendor: Dell")
    else:
        print(" [!] Detected Architecture: Generic UEFI / Unknown Vendor")

    if has_phoenix_pw:
        print(" [!] Found Phoenix/Insyde Password Variable: 'SystemSupervisorPw'")
    if has_generic_pw:
        print(" [!] Found Generic Password Variable: 'AdminPassword' / 'SetupPassword'")

    print("\n--- Recommendation ---")
    if is_thinkpad and not has_phoenix_pw:
        print("[*] Recommending ThinkPad DXE Injection Method.")
        return patch_thinkpad(source_file)
    else:
        print("[*] Recommending Direct NVRAM Password Defusal Method.")
        return patch_simple_nvram(source_file)


# ------------------------------------------------------------------------------
# MAIN INTERACTIVE MENU
# ------------------------------------------------------------------------------
def main():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print_banner()
        print("Please choose your laptop brand or method:\n")
        print("  [1] ThinkPad    (Lenovo up to 8th Gen: T440-T480, X240-X280, X380, X1, etc.)")
        print("  [2] HP          (EliteBook, ProBook, Pavilion, ZBook)")
        print("  [3] Dell        (Latitude, OptiPlex, Precision, Inspiron)")
        print("  [4] Other/Simple(Fujitsu, Acer, Asus, Phoenix, Insyde, AMI - Password in dump)")
        print("  [5] Auto-Detect (Scan dump file automatically and apply the best patch)")
        print("  [0] Exit\n")

        choice = input("Enter choice [0-5]: ").strip()

        if choice == "0":
            print("\nGoodbye!")
            break

        if choice not in ["1", "2", "3", "4", "5"]:
            print("[!] Invalid choice. Please select 0 to 5.")
            input("Press Enter to continue...")
            continue

        print("\n" + "-"*70)
        file_path = choose_file_gui()
        if not file_path or not os.path.exists(file_path):
            print("[-] No valid file chosen.")
            input("\nPress Enter to return to menu...")
            continue

        print(f"[+] Selected file: {file_path}")

        if choice == "1":
            patch_thinkpad(file_path)
        elif choice == "2":
            patch_hp(file_path)
        elif choice == "3":
            patch_dell(file_path)
        elif choice == "4":
            patch_simple_nvram(file_path)
        elif choice == "5":
            auto_detect_and_patch(file_path)

        print("\n" + "="*70)
        input("Patching operation complete! Press Enter to return to menu...")


if __name__ == "__main__":
    main()
