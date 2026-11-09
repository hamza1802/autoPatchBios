================================================================================
                    BIOS PATCHING FOR BEGINNERS - USER GUIDE
================================================================================

HOW TO USE:
1. Double-click "Run_Patcher.cmd".
2. Choose your laptop type from the interactive menu:
     [1] ThinkPad (Lenovo up to 8th Gen: T440-T480, X240-X280, X380, X1, etc.)
     [2] HP (EliteBook, ProBook, Pavilion, ZBook)
     [3] Dell (Latitude, OptiPlex, Precision, Inspiron)
     [4] Other / Simple (Fujitsu, Acer, Asus, Phoenix, Insyde, AMI - Password in dump)
     [5] Auto-Detect (Scan dump and automatically choose best method)
3. A file browser window will pop up automatically. Select your BIOS dump (.bin or .rom).
4. The tool creates a safety backup (<filename>_ORIGINAL_BACKUP.bin) and generates
   the flash-ready file (<filename>_PATCHED.bin).

================================================================================
HOW EACH METHOD WORKS & HOW TO USE THE PATCHED BIOS:
================================================================================

--- OPTION 1: THINKPAD (LENOVO) ---
- How it works: Uses UEFIReplace to inject custom DXE unlock drivers and replaces
  the NVRAM volume with an initialized volume.
- Flashing Steps:
    1. Flash <filename>_PATCHED.bin to your BIOS chip.
    2. Power on the laptop (keep the bottom anti-tamper switch held down with tape).
    3. Press F1 or Enter to enter BIOS Setup.
    4. Type ANY character when prompted for Supervisor Password.
    5. Press Enter at the Hardware ID prompt.
    6. Press Space bar twice when asked.
    7. Turn off laptop.
    8. Flash your ORIGINAL backup BIOS back to the chip.
    9. Power on, enter BIOS, and press F9 (Load Setup Defaults). Password is gone!

--- OPTION 4: OTHER / SIMPLE (FUJITSU, ACER, ASUS, PHOENIX, INSYDE, AMI) ---
- How it works: Locates the active password variables (SystemSupervisorPw, 
  SystemUserPw, AdminPassword, SetupPassword, etc.) inside the NVRAM store,
  marks them as VAR_DELETED (0x3D), defuses the variable names, and clears
  the password hash payload.
- Flashing Steps:
    1. Flash <filename>_PATCHED.bin directly to your BIOS chip.
    2. Power on and press F2 / Del / F10 to enter BIOS Setup.
    3. The password prompt is completely bypassed!
    4. In BIOS Setup, press F9 (Load Setup Defaults), then F10 (Save & Exit).
       The motherboard will automatically regenerate a clean default NVRAM table.

--- OPTION 2: HP ---
- Neutralizes HP password variables in NVRAM.
- Boot with F10 (or Esc -> F10) to enter BIOS Setup and clear setup password.

--- OPTION 3: DELL ---
- Neutralizes Dell admin/system password variables in NVRAM.
- Also supports extracting raw BIOS ROMs from Dell .exe update packages.
- Boot with F2 into BIOS Setup to restore BIOS defaults.

================================================================================
SAFETY NOTE:
Always keep your original, unmodified dump safe. The tool automatically saves an
untouched copy as "<filename>_ORIGINAL_BACKUP.bin" before modifying anything.
================================================================================
