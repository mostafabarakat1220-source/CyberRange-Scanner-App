# CyberRange Scanner

A professional network security scanner with a modern GUI, powered by Python, PySide6, and Nmap.

## Setup and Installation

### Prerequisites

- **Python 3.10+**
- **Nmap**: You must have Nmap installed and accessible from your system's PATH. You can download it from [nmap.org](https://nmap.org/download.html).

### Installation Steps

1.  **Clone the repository or download the source code.**

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python cyberrange_scanner.py
    ```

## Building the Executable

To build a standalone executable for Windows:

1.  Make sure you have installed the requirements, including `PyInstaller`.

2.  Run the build script:
    ```bash
    python build_exe.py
    ```

3.  The executable will be located in the `dist` folder.
