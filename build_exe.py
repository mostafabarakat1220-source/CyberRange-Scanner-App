import PyInstaller.__main__
import os
from pathlib import Path

# --- Configuration ---
APP_NAME = "CyberRangeScanner"
SCRIPT_FILE = "cyberrange_scanner.py"
ICON_FILE = "icon.ico"
DATA_FILES = [
    ('icons', 'icons'),
    ('icon.ico', '.')
]

# --- Build Paths ---
project_root = Path(__file__).parent
script_path = project_root / SCRIPT_FILE
icon_path = project_root / ICON_FILE

# --- PyInstaller Arguments ---
pyinstaller_args = [
    '--name', APP_NAME,
    '--onefile',
    '--noconsole', # Enable this to hide the console window
    f'--icon={icon_path}',
    '--distpath', str(project_root / 'dist'), # Explicitly set output directory
]

# Add data files
for data_file, dest_folder in DATA_FILES:
    pyinstaller_args.extend(['--add-data', f'{project_root / data_file}{os.pathsep}{dest_folder}'])

# Add the main script
pyinstaller_args.append(str(script_path))

if __name__ == '__main__':
    print("Running PyInstaller with the following arguments:")
    print(pyinstaller_args)
    
    # Check if script file exists
    if not script_path.exists():
        print(f"Error: Main script '{SCRIPT_FILE}' not found in the project directory.")
        exit(1)
        
    # Check if icon file exists
    if not icon_path.exists():
        print(f"Warning: Icon file '{ICON_FILE}' not found. A default icon will be used.")
        # Find and remove the icon argument if the file doesn't exist
        try:
            icon_index = pyinstaller_args.index(f'--icon={icon_path}')
            pyinstaller_args.pop(icon_index)
            pyinstaller_args.pop(icon_index-1)
        except ValueError:
            pass # Should not happen if logic is correct

    PyInstaller.__main__.run(pyinstaller_args)

    print(f"\nBuild complete. The executable should be in the '{project_root / 'dist'}' folder.")
