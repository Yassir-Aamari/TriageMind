# TriageMind Distribution Guide

## How to build and share TriageMind

### Step 1 — Run the build script
```bat
build_exe.bat
```
This creates a `dist\TriageMind\` folder.

### Step 2 — Copy extra files into the dist folder
```bat
copy README.md dist\TriageMind\
copy setup.bat dist\TriageMind\
copy run.bat dist\TriageMind\
copy requirements.txt dist\TriageMind\
```

### Step 3 — Zip the dist folder
Right-click `dist\TriageMind\` → Send to → Compressed (zipped) folder.
Rename it `TriageMind_v1.0.zip`.

### Step 4 — Share the zip
The recipient needs to:
1. Extract the zip
2. Run `setup.bat` once (installs Playwright browser ~150MB)
3. Run `TriageMind.exe` or double-click `run.bat`

---

## Important limitation
Playwright browsers (~150MB) cannot be bundled inside the exe.
The setup.bat handles this automatically for the recipient.

---

## Alternative — No exe, just zip the source
For a demo or presentation, simply zip the entire project folder and share it with the README.md. The recipient runs `setup.bat` then `python main.py`. This is simpler and more reliable than the exe approach.
