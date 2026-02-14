from __future__ import annotations

import sys, os, json, subprocess, datetime, sqlite3, csv, threading, time, shutil, re
from pathlib import Path
from typing import List, Dict, Optional

# --- Logging Setup ---
LOG_FILE = Path.cwd() / "nmap_cyberrange_data" / "cyberrange_scanner.log"

def log_message(message: str, level: str = "INFO"):
    """Writes a timestamped message to the log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{level}] {message}\n")

from PySide6.QtCore import (
    Qt, QTimer, Signal, QThread, QRect, QPropertyAnimation, QEasingCurve, 
    QObject, Property
)
from PySide6.QtGui import QPainter, QColor, QPen, QFont, QTextCursor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
        QTextEdit, QComboBox, QFileDialog, QTableWidget, QTableWidgetItem,
        QFrame, QMessageBox, QStackedWidget, QSpinBox, QGridLayout, QHeaderView,
        QSizePolicy, QGraphicsOpacityEffect, QCheckBox)
from PySide6.QtSvg import QSvgRenderer

# --- Modern Color Palette ---
C = {
    'bg': '#0a0e27',           # Main background
    'bg_light': '#10163a',     # Content background, cards
    'bg_dark': '#080c21',       # Sidebar
    'primary': '#00d4ff',      # Accent, interactive elements
    'primary_dark': '#00a4c7', # Accent hover
    'text': '#e0e0e0',         # Standard text
    'text_light': '#ffffff',   # Titles, bright text
    'text_dark': '#a0a0a0',     # Dimmed text, placeholders
    'border': '#202850',       # Borders on cards
    'success': '#28a745',
    'warning': '#ffc107',
    'error': '#dc3545',
}

# --- Global Stylesheet ---
STYLESHEET = f"""
    QWidget {{
        font-family: Inter, Roboto, Segoe UI, sans-serif;
        color: {C['text']};
        background-color: {C['bg']};
    }}
    QFrame, #StatCard, #ScanFormFrame, #TemplateGroup {{ /* Added IDs for specific frames */
        background-color: {C['bg_light']};
        border-radius: 8px;
        border: 1px solid {C['border']};
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); /* Glassmorphism shadow */
    }}
    QLabel {{
        background-color: transparent;
        border: none;
    }}
    #TitleLabel {{
        color: {C['text_light']};
        font-size: 20px;
        font-weight: bold;
    }}
    #PageTitle {{
        color: {C['text_light']};
        font-size: 24px;
        font-weight: bold;
    }}
    #Sidebar {{
        background-color: {C['bg_dark']};
        border-radius: 0px;
        border: none;
    }}
    #ContentArea {{
        background-color: {C['bg']};
        border-radius: 0px;
        border: none;
    }}
    QPushButton {{
        background-color: {C['primary']};
        color: {C['bg_dark']};
        font-size: 11px;
        font-weight: bold;
        padding: 10px;
        border: none;
        border-radius: 6px;
    }}
    QPushButton:hover {{
        background-color: {C['primary_dark']};
    }}
    QPushButton:disabled {{
        background-color: #555;
        color: #999;
    }}
    #NavButton {{
        background-color: transparent;
        color: {C['text_dark']};
        font-size: 11px;
        font-weight: bold;
        padding: 12px;
        border-radius: 6px;
        text-align: left;
    }}
    #NavButton:hover {{
        background-color: {C['bg_light']};
        color: {C['text']};
    }}
    #NavButton:checked {{
        background-color: {C['bg_light']};
        color: {C['text_light']};
    }}
    QLineEdit, QComboBox {{
        background-color: {C['bg_light']};
        color: {C['text']};
        font-size: 11px;
        padding: 10px;
        border: 1px solid {C['border']};
        border-radius: 6px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3); /* Glassmorphism shadow */
    }}
    QLineEdit:focus, QComboBox:focus {{
        border-color: {C['primary']};
    }}
    QComboBox::drop-down {{
        border: none;
    }}
    QTextEdit {{
        background-color: {C['bg_dark']}; /* Darker background for terminal-like output */
        color: {C['text']};
        border: 1px solid {C['border']};
        border-radius: 8px;
        padding: 10px;
        font-family: Consolas, Fira Code, monospace;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3); /* Glassmorphism shadow */
    }}
    QTableWidget {{
        background-color: transparent;
        border: none;
        gridline-color: {C['border']};
        alternate-background-color: {C['bg_dark']}; /* For alternating row colors */
    }}
    QHeaderView::section {{
        background-color: {C['bg_dark']};
        color: {C['text_light']};
        padding: 10px;
        border: none;
        font-weight: bold;
    }}
    QTableWidget::item {{
        padding: 10px;
        border-bottom: 1px solid {C['border']};
    }}
    QTableWidget::item:selected {{
        background-color: {C['primary']};
        color: {C['bg_dark']};
    }}
"""

# --- Database Setup ---
BASE = Path.cwd() / "nmap_cyberrange_data"
REPORTS = BASE / "reports"
DB = BASE / "cyberrange.db"
TEMPLATES_FILE = BASE / "scan_templates.json"
for d in (BASE, REPORTS): d.mkdir(parents=True, exist_ok=True)

def init_db():
    """
    Initializes the SQLite database for the CyberRange Scanner.
    Drops existing tables (scans, devices, vulnerabilities) if they exist
    to ensure a clean schema for development, then creates them.
    """
    log_message(f"Initializing database at {DB}")
    conn = sqlite3.connect(DB); cur = conn.cursor(); cur.execute("PRAGMA journal_mode=WAL;")
    
    # Drop existing tables to ensure schema is always fresh for development
    # cur.execute("DROP TABLE IF EXISTS scans")
    # cur.execute("DROP TABLE IF EXISTS devices")
    # cur.execute("DROP TABLE IF EXISTS vulnerabilities")

    cur.execute("""CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, scan_type TEXT, timestamp DATETIME, results TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, mac TEXT, vendor TEXT, os TEXT, status TEXT, last_seen DATETIME)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, port INTEGER, service TEXT, script_output TEXT, severity TEXT, timestamp DATETIME)""")
    conn.commit(); conn.close()
    log_message("Database initialization complete.")


def load_templates() -> Dict[str, List[str]]:
    """
    Loads Nmap scan templates from `scan_templates.json`.
    If the file does not exist, a set of default templates is returned.
    Returns:
        Dict[str, List[str]]: A dictionary where keys are template names and values are lists of Nmap flags.
    """

    if TEMPLATES_FILE.exists():
        with open(TEMPLATES_FILE, 'r') as f:
            return json.load(f)
    return {
        "Quick Scan": ["-T4", "-F"],
        "Intense Scan": ["-T4", "-A", "-v"],
        "Vuln Scan": ["-T4", "--script", "vuln"]
    }

def save_templates(templates: Dict[str, List[str]]):
    """
    Saves the current dictionary of Nmap scan templates to `scan_templates.json`.
    Args:
        templates (Dict[str, List[str]]): A dictionary of template names mapping to lists of Nmap flags.
    """

    with open(TEMPLATES_FILE, 'w') as f:
        json.dump(templates, f, indent=4)


# --- Nmap Scan Thread ---
class ScanThread(QThread):
    """
    QThread subclass to run Nmap scans in a separate thread, preventing the UI from freezing.
    Emits signals for scan progress, percentage complete, and final output.
    """
    progress = Signal(str)
    finished = Signal(str)
    scan_percent = Signal(int)

    def __init__(self, target: str, scan_type: str, flags: List[str]):
        super().__init__()
        self.target, self.scan_type, self.flags = target, scan_type, flags
        log_message(f"ScanThread initialized for target: {self.target}, type: {self.scan_type}, flags: {self.flags}")

    def run(self):
        log_message(f"Starting ScanThread for target: {self.target}, type: {self.scan_type}, flags: {self.flags}")
        if not shutil.which("nmap"):
            error_msg = "Nmap not found. Please install it and ensure it's in your system's PATH."
            self.finished.emit(error_msg)
            log_message(error_msg, "ERROR")
            return

        command = ['nmap', '-v', '--stats-every', '1s', self.target] + self.flags
        try:
            log_message(f"Executing Nmap command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            output = ""
            for line in iter(process.stdout.readline, ''):
                # Filter out "Unknown property" warnings from PySide6/Qt, which can clutter console output
                if "Unknown property" in line:
                    continue
                output += line; self.progress.emit(line.strip())
                if '% done' in line:
                    try:
                        percent = int(float(line.split('%')[0].split()[-1]))
                        self.scan_percent.emit(percent)
                    except (ValueError, IndexError): pass
            process.stdout.close(); process.wait()
            self.finished.emit(output)
            log_message("Nmap scan process finished.")
        except Exception as e:
            error_msg = f"An error occurred during Nmap scan: {e}"
            self.finished.emit(error_msg)
            log_message(error_msg, "ERROR")

# --- Redesigned Widgets ---
class AnimatedCircularProgress(QWidget):
    """
    A custom QWidget that displays an animated circular progress indicator.
    The progress value can be set and animated smoothly.
    """
    def __init__(self):
        super().__init__()
        self._value = 0
        self.setFixedSize(150, 150)
        self.animation = QPropertyAnimation(self, b"value", self)
        self.animation.setDuration(300)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)

    @Property(float)
    def value(self): return self._value
    @value.setter
    def value(self, new_val): self._value = new_val; self.update()

    def setValue(self, val): self.animation.setEndValue(val) ; self.animation.start()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(5, 5, -5, -5)
        pen = QPen(QColor(C['border']), 10, Qt.SolidLine)
        painter.setPen(pen); painter.drawArc(rect, 0, 360 * 16)
        pen.setColor(QColor(C['primary'])); pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen); painter.drawArc(rect, 90 * 16, -self.value * 3.6 * 16)
        font = QFont("Inter", 20, QFont.Bold); painter.setFont(font)
        pen.setColor(QColor(C['text_light'])); painter.setPen(pen)
        painter.drawText(rect, Qt.AlignCenter, f"{int(self.value)}%")

class StatCard(QFrame):
    """
    A reusable QFrame widget designed to display a single, prominent statistic.
    It features a title and a dynamic value, suitable for dashboard overviews.
    """
    def __init__(self, title: str, value: str = "0"):
        super().__init__(); self.setObjectName("StatCard"); self.setMinimumHeight(120)
        layout = QVBoxLayout(self); layout.setContentsMargins(20, 20, 20, 20)
        self.title_label = QLabel(title); self.title_label.setFont(QFont("Inter", 11, QFont.Bold)); self.title_label.setStyleSheet(f"color: {C['text_dark']};")
        self.value_label = QLabel(value); self.value_label.setFont(QFont("Inter", 28, QFont.Bold))
        layout.addWidget(self.title_label); layout.addStretch(); layout.addWidget(self.value_label)
    def setValue(self, value: int | str): self.value_label.setText(str(value))

def create_icon(icon_path: str, color: str) -> QIcon:
    """
    Creates a QIcon from an SVG file, applying a specific color dynamically.
    This is useful for theming SVG icons without modifying the SVG file directly.

    Args:
        icon_path (str): The path to the SVG icon file.
        color (str): The hexadecimal color string (e.g., "#RRGGBB") to apply to the icon.

    Returns:
        QIcon: A QIcon object with the specified SVG and color.
    """
    """Creates a QIcon from an SVG file, applying a specific color."""
    renderer = QSvgRenderer(str(Path(__file__).parent / icon_path))
    pixmap = QPixmap(renderer.defaultSize())
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return QIcon(pixmap)

# --- Main Application Window ---
class MainWindow(QWidget):
    """
    The main application window for the CyberRange Scanner.
    Manages the overall UI layout, page navigation, and central application logic.
    Connects various page-specific signals and handles dashboard updates.
    """
    activity_update_signal = Signal(str, str) # (message, type)
    def __init__(self):
        super().__init__(); self.setWindowTitle("CyberRange Scanner"); self.setGeometry(100, 100, 1280, 800)
        self.setStyleSheet(STYLESHEET); init_db(); self.setup_ui(); self.update_dashboard()


    def setup_ui(self):
        main_layout = QHBoxLayout(self); main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar); sidebar_layout.setContentsMargins(10, 20, 10, 20); sidebar_layout.setSpacing(10)
        title = QLabel("CyberRange"); title.setObjectName("TitleLabel"); title.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(title); sidebar_layout.addSpacing(30)
        
        self.nav_buttons = {}
        icon_map = {
            "Dashboard": "icons/dashboard.svg", "Network Scan": "icons/scan.svg", "Devices": "icons/devices.svg",
            "Vulnerabilities": "icons/vulns.svg", "Reports": "icons/reports.svg", "Settings": "icons/settings.svg"
        }
        for page_name, icon_path in icon_map.items():
            btn = QPushButton(page_name); btn.setObjectName("NavButton"); btn.setCheckable(True)
            btn.setIcon(create_icon(icon_path, C['text_dark']))
            btn.clicked.connect(self.switch_page); sidebar_layout.addWidget(btn); self.nav_buttons[page_name] = btn
        sidebar_layout.addStretch()

        content_area = QFrame(); content_area.setObjectName("ContentArea")
        content_layout = QVBoxLayout(content_area)
        self.stacked_widget = QStackedWidget(); content_layout.addWidget(self.stacked_widget)
        self.pages = {
            "Dashboard": DashboardPage(), "Network Scan": NetworkScanPage(self), "Devices": DevicesPage(),
            "Vulnerabilities": VulnerabilitiesPage(), "Reports": ReportsPage(), "Settings": SettingsPage(self)
        }
        for page in self.pages.values(): self.stacked_widget.addWidget(page)
        main_layout.addWidget(sidebar); main_layout.addWidget(content_area)
        
        self.pages["Network Scan"].scan_completed.connect(self.handle_scan_completion)
        self.activity_update_signal.connect(self.pages["Dashboard"].add_activity_entry)
        # Check if scan_thread exists before connecting signal
        if hasattr(self.pages["Network Scan"], 'scan_thread') and self.pages["Network Scan"].scan_thread:
            self.pages["Network Scan"].scan_thread.scan_percent.connect(self.pages["Dashboard"].progress_chart.setValue)
        self.nav_buttons["Dashboard"].setChecked(True)

    def switch_page(self):
        sender = self.sender()
        for name, btn in self.nav_buttons.items():
            if btn == sender:
                new_index = list(self.nav_buttons.keys()).index(name)
                self.fade_transition(new_index); btn.setChecked(True)
            else: btn.setChecked(False)

    def fade_transition(self, index):
        current_widget = self.stacked_widget.currentWidget()
        self.opacity_effect = QGraphicsOpacityEffect(current_widget)
        current_widget.setGraphicsEffect(self.opacity_effect)
        self.anim_out = QPropertyAnimation(self.opacity_effect, b"opacity"); self.anim_out.setDuration(150)
        self.anim_out.setStartValue(1.0); self.anim_out.setEndValue(0.0)
        self.anim_out.finished.connect(lambda: self.finalize_transition(index))
        self.anim_out.start()

    def finalize_transition(self, index):
        self.stacked_widget.setCurrentIndex(index)
        new_widget = self.stacked_widget.currentWidget()
        self.opacity_effect = QGraphicsOpacityEffect(new_widget)
        new_widget.setGraphicsEffect(self.opacity_effect)
        self.anim_in = QPropertyAnimation(self.opacity_effect, b"opacity"); self.anim_in.setDuration(150)
        self.anim_in.setStartValue(0.0); self.anim_in.setEndValue(1.0); self.anim_in.start()

    def handle_scan_completion(self):
        self.update_dashboard(); self.pages["Devices"].load_data(); 
        self.pages["Vulnerabilities"].load_data(); self.pages["Reports"].load_data()

    def update_dashboard(self):
        conn = sqlite3.connect(DB); cur = conn.cursor()
        try:
            stats = {
                "Total Scans": cur.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
                "Discovered Devices": cur.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                "Live Hosts": cur.execute("SELECT COUNT(*) FROM devices WHERE status = 'up'").fetchone()[0],
                "Vulnerabilities Found": cur.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            }
            log_message(f"Dashboard stats updated: {stats}")
            self.pages["Dashboard"].update_stats(stats)
            
            # Clear existing activity feed before populating with new data from signal
            self.pages["Dashboard"].activity_feed.clear()
            self.activity_update_signal.emit("Recent Activity", "header") # Emit header

            recent_scans = cur.execute("SELECT target, scan_type, timestamp FROM scans ORDER BY id DESC LIMIT 5").fetchall()
            for target, scan_type, ts in recent_scans:
                time_str = datetime.datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M')
                message = f"<b>{time_str}:</b> Scanned <b>{target}</b> with type <b>{scan_type}</b>"
                self.activity_update_signal.emit(message, "scan_info")

        except Exception as e:
            log_message(f"Error updating dashboard: {e}", "ERROR")
            self.activity_update_signal.emit(f"Error updating dashboard: {e}", "error")
        finally:
            conn.close()

# --- Page Widgets ---
class DashboardPage(QWidget):
    """
    The DashboardPage provides an overview of the CyberRange Scanner's activities.
    It displays key statistics (total scans, discovered devices, vulnerabilities),
    a circular progress chart for ongoing scans, and a real-time activity feed.
    """
    def __init__(self):
        super().__init__(); layout = QGridLayout(self); layout.setContentsMargins(30, 30, 30, 30); layout.setSpacing(25)

        # Statistics Cards
        self.stats = {
            "Total Scans": StatCard("Total Scans"),
            "Discovered Devices": StatCard("Discovered Devices"),
            "Live Hosts": StatCard("Live Hosts"),
            "Vulnerabilities Found": StatCard("Vulnerabilities Found")
        }
        # Add stat cards to the top row
        layout.addWidget(self.stats["Total Scans"], 0, 0)
        layout.addWidget(self.stats["Discovered Devices"], 0, 1)
        layout.addWidget(self.stats["Live Hosts"], 0, 2)
        layout.addWidget(self.stats["Vulnerabilities Found"], 0, 3)

        # Progress Chart
        self.progress_chart = AnimatedCircularProgress()
        layout.addWidget(self.progress_chart, 1, 0, 1, 2) # Span 1 row, 2 columns

        # Activity Feed
        activity_label = QLabel("Recent Activity"); activity_label.setFont(QFont("Inter", 14, QFont.Bold))
        self.activity_feed = QTextEdit(); self.activity_feed.setReadOnly(True); self.activity_feed.setStyleSheet("font-size: 10px;") # Smaller font for activity feed
        layout.addWidget(activity_label, 1, 2, 1, 2) # Span 1 row, 2 columns
        layout.addWidget(self.activity_feed, 2, 2, 2, 2) # Span 2 rows, 2 columns

        layout.setRowStretch(3, 1) # Give activity feed more vertical space
        layout.setColumnStretch(0, 1)
        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(2, 1)
        layout.setColumnStretch(3, 1)

    def update_stats(self, data: Dict[str, int]):
        for key, value in data.items():
            if key in self.stats: self.stats[key].setValue(value)

    def add_activity_entry(self, message: str, type: str):
        if type == "header":
            formatted_message = f"<h4>{message}</h4>"
        elif type == "scan_info":
            formatted_message = f"<p style='color:{C['primary']};'>{message}</p>"
        elif type == "success":
            formatted_message = f"<p style='color:{C['success']};'>{message}</p>"
        elif type == "error":
            formatted_message = f"<p style='color:{C['error']};'>{message}</p>"
        else: # Default type
            formatted_message = f"<p>{message}</p>"
        self.activity_feed.append(formatted_message)

class NetworkScanPage(QWidget):
    """
    The NetworkScanPage provides the interface for configuring and initiating Nmap network scans.
    Users can specify target IPs/networks, select scan templates, and view real-time scan output.
    It manages the lifecycle of `ScanThread` to perform scans without freezing the UI.
    """
    scan_completed = Signal()
    def __init__(self, main_window: 'MainWindow'):
        super().__init__(); self.main_window = main_window # Reference to main window for template updates
        layout = QVBoxLayout(self); layout.setContentsMargins(30, 30, 30, 30); layout.setSpacing(20)
        form_frame = QFrame(); form_frame.setObjectName("ScanFormFrame"); form_frame.setStyleSheet("background-color: transparent; border: none;")
        form_layout = QHBoxLayout(form_frame); form_layout.setSpacing(15); form_layout.setContentsMargins(0,0,0,0)
        
        # Target Input
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("Target(s) (e.g., 192.168.1.0/24, host.com)")
        
        # Exclude Input
        self.exclude_input = QLineEdit(); self.exclude_input.setPlaceholderText("Exclude (e.g., 192.168.1.5, other.com)")
        
        self.scan_type_combo = QComboBox(); self.scan_type_combo.currentIndexChanged.connect(self.load_template_flags)
        self.load_scan_templates() # Load templates into the combo box
        
        # New UI elements for OS Detection and Version Intensity
        self.os_detection_checkbox = QCheckBox("OS Detection (-O)")
        self.os_detection_checkbox.setStyleSheet(f"color: {C['text']};")
        
        self.version_intensity_combo = QComboBox()
        self.version_intensity_combo.addItem("Version Intensity: Default (-sV)")
        for i in range(0, 10):
            self.version_intensity_combo.addItem(f"Version Intensity: {i} (--version-intensity {i})")

        # New UI elements for Output Options
        self.output_xml_checkbox = QCheckBox("Output XML (-oX)")
        self.output_xml_checkbox.setStyleSheet(f"color: {C['text']};")
        self.output_greppable_checkbox = QCheckBox("Output Greppable (-oG)")
        self.output_greppable_checkbox.setStyleSheet(f"color: {C['text']};")


        self.start_scan_btn = QPushButton("START SCAN"); self.start_scan_btn.clicked.connect(self.start_scan)
        
        # Add widgets to layout
        form_layout.addWidget(self.target_input, 3);
        form_layout.addWidget(self.exclude_input, 2); # Added exclude input
        form_layout.addWidget(self.scan_type_combo, 2);
        form_layout.addWidget(self.os_detection_checkbox);
        form_layout.addWidget(self.version_intensity_combo);
        form_layout.addWidget(self.output_xml_checkbox); # Added Output XML
        form_layout.addWidget(self.output_greppable_checkbox); # Added Output Greppable
        form_layout.addWidget(self.start_scan_btn, 1)
        
        layout.addWidget(form_frame)
        self.results_display = QTextEdit(); self.results_display.setReadOnly(True); layout.addWidget(self.results_display, 1)
        self.scan_thread = ScanThread("", "", []) # Placeholder


    def load_scan_templates(self):
        self.scan_type_combo.clear()
        self.templates = load_templates()
        for name in self.templates.keys():
            self.scan_type_combo.addItem(name)

    def load_template_flags(self):
        selected_template = self.scan_type_combo.currentText()
        if selected_template in self.templates:
            flags = " ".join(self.templates[selected_template])
            # Optionally display flags or hints, for now, just load them implicitly

    def start_scan(self):
        target_text = self.target_input.text().strip()
        if not target_text:
            QMessageBox.warning(self, "Warning", "Target cannot be empty."); return
        
        selected_template_name = self.scan_type_combo.currentText()
        flags = list(self.templates.get(selected_template_name, [])) # Use list() to create a mutable copy

        # Add OS detection flag
        if self.os_detection_checkbox.isChecked():
            flags.append("-O")

        # Add Version Intensity flag
        version_intensity_text = self.version_intensity_combo.currentText()
        if "Default" not in version_intensity_text:
            if "Version Intensity: " in version_intensity_text:
                intensity_level = version_intensity_text.split(" ")[2] # e.g., "9" from "Version Intensity: 9"
                flags.append(f"--version-intensity {intensity_level}")
            elif "-sV" in version_intensity_text: # This condition might not be hit if "Default" is handled.
                flags.append("-sV") # Ensure -sV is added if intensity is chosen

        # Handle multiple targets and exclusion
        targets = []
        if "," in target_text:
            targets.extend([t.strip() for t in target_text.split(",") if t.strip()])
        elif " " in target_text:
            targets.extend([t.strip() for t in target_text.split(" ") if t.strip()])
        else:
            targets.append(target_text)

        exclude_text = self.exclude_input.text().strip()
        if exclude_text:
            flags.extend(["--exclude", exclude_text])

        # Add Output Options
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.output_xml_checkbox.isChecked():
            flags.append(f"-oX {REPORTS / f'scan_{timestamp}.xml'}")
        if self.output_greppable_checkbox.isChecked():
            flags.append(f"-oG {REPORTS / f'scan_{timestamp}.gnmap'}")

        # Nmap command will be constructed with all targets first, then flags
        nmap_command_parts = targets + flags
        
        self.results_display.clear()
        start_message = f"> Starting {selected_template_name} scan on {target_text} at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.results_display.append(start_message)
        self.main_window.activity_update_signal.emit(start_message, "scan_info") # Emit to dashboard
        log_message(f"Initiating scan for target: {target_text} with command parts: {nmap_command_parts}")

        # The ScanThread now needs to accept a list of targets and a list of flags separately
        # Or, construct the full command here and pass it as a single list.
        # Let's modify ScanThread to accept a full command list directly.
        self.scan_thread = ScanThread(target_text, selected_template_name, nmap_command_parts)
        self.scan_thread.progress.connect(self.update_results)
        self.scan_thread.finished.connect(self.finish_scan)
        self.scan_thread.scan_percent.connect(self.main_window.pages["Dashboard"].progress_chart.setValue) # Connect progress to dashboard
        self.scan_thread.start()

    def update_results(self, line: str): self.results_display.append(line); self.results_display.verticalScrollBar().setValue(self.results_display.verticalScrollBar().maximum())
    def finish_scan(self, output: str):
        finish_message = "\n> --- Scan Finished ---"
        self.results_display.append(finish_message)
        self.start_scan_btn.setEnabled(True); self.start_scan_btn.setText("START SCAN")
        log_message("Scan finished, processing results.")
        
        # Determine status and emit appropriate signal
        if "Nmap done: 1 IP address (1 host up)" in output or "Nmap done: 1 IP address (0 hosts up)" in output: # Basic check for successful Nmap run
            self.main_window.activity_update_signal.emit(f"Scan on {self.scan_thread.target} completed successfully.", "success")
            log_message(f"Scan on {self.scan_thread.target} completed successfully.")
        else:
            self.main_window.activity_update_signal.emit(f"Scan on {self.scan_thread.target} finished with errors or incomplete results.", "error")
            log_message(f"Scan on {self.scan_thread.target} finished with errors or incomplete results.", "ERROR")

        self.save_scan_results(output);
        self.scan_completed.emit();
        self.parse_and_store_nmap(output)
        self.main_window.update_dashboard() # Trigger full dashboard update
        log_message("Finished scan completion handler.")

    def save_scan_results(self, results: str):
        try:
            conn = sqlite3.connect(DB); cur = conn.cursor()
            cur.execute("INSERT INTO scans (target, scan_type, timestamp, results) VALUES (?, ?, ?, ?)", (self.scan_thread.target, self.scan_thread.scan_type, datetime.datetime.now().isoformat(), results))
            conn.commit(); conn.close()
            log_message(f"Scan results for {self.scan_thread.target} saved to DB.")
        except Exception as e:
            log_message(f"Error saving scan results to DB: {e}", "ERROR")
    def parse_and_store_nmap(self, nmap_output: str):
        log_message("Starting Nmap output parsing.")
        # print("\n--- RAW NMAP OUTPUT FOR DEBUGGING ---")
        # print(nmap_output)
        # print("--- END RAW NMAP OUTPUT ---\n")
        conn = sqlite3.connect(DB); cur = conn.cursor();
        current_ip = None; current_mac = None; current_vendor = None; current_os = None;
        ts = datetime.datetime.now().isoformat()
        
        mac_pattern = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?")
        os_pattern = re.compile(r"Running: (.*?)$|OS details: (.*?)$", re.IGNORECASE)

        parsing_ports_section = False
        parsing_host_script_results = False
        
        for line in nmap_output.splitlines():
            line = line.strip()

            if not line:
                continue

            # New host scan report starts
            if "Nmap scan report for" in line:
                if current_ip:
                    log_message(f"Saving previous device {current_ip} details (MAC: {current_mac}, OS: {current_os}).")
                    try:
                        cur.execute("INSERT OR IGNORE INTO devices (ip) VALUES (?)", (current_ip,))
                        cur.execute("UPDATE devices SET status = 'up', last_seen = ?, mac = ?, vendor = ?, os = ? WHERE ip = ?",
                                    (ts, current_mac, current_vendor, current_os, current_ip))
                        conn.commit() # Commit after each device update to ensure data is saved
                        log_message(f"Device {current_ip} details saved/updated successfully.")
                    except sqlite3.Error as e:
                        log_message(f"SQL Error saving device {current_ip}: {e}", "ERROR")
                
                current_ip = line.split()[-1].strip('()')
                current_mac = None; current_vendor = None; current_os = None;
                parsing_ports_section = False
                parsing_host_script_results = False
                log_message(f"Processing Nmap report for new host: {current_ip}")
                continue

            # Process MAC address
            mac_match = mac_pattern.search(line)
            if mac_match:
                current_mac = mac_match.group(1)
                current_vendor = mac_match.group(2)
                log_message(f"Detected MAC: {current_mac}, Vendor: {current_vendor}")
                continue

            # Process OS details
            os_match = os_pattern.search(line)
            if os_match:
                if os_match.group(1): current_os = os_match.group(1)
                elif os_match.group(2): current_os = os_match.group(2)
                log_message(f"Detected OS: {current_os}")
                continue
            
            # Identify the start of the PORT STATE SERVICE table
            if line.startswith("PORT      STATE SERVICE"):
                parsing_ports_section = True
                parsing_host_script_results = False
                log_message("Entered PORT STATE SERVICE section.")
                continue

            # Identify the start of Host script results
            if line.startswith("Host script results:"):
                parsing_host_script_results = True
                parsing_ports_section = False
                log_message("Entered Host script results section.")
                continue

            # Ignore Nmap internal progress/discovery messages, which do not contain full service info
            if line.startswith("Discovered open port") or line.startswith("Initiating ") or line.startswith("Completed "):
                continue

            # Parse lines within the PORT STATE SERVICE section
            if parsing_ports_section and current_ip:
                parts = line.split()
                # Ensure it's a valid port line (e.g., "135/tcp open msrpc")
                if len(parts) >= 3 and '/' in parts[0] and parts[1] in ['open', 'closed', 'filtered']:
                    try:
                        port_str = parts[0]
                        port_num = int(port_str.split('/')[0])
                        state = parts[1]
                        service = parts[2]
                        
                        # Store all open ports as informational vulnerabilities
                        if state == 'open':
                            log_message(f"Processing open port: {port_num}/{service}")
                            cur.execute("SELECT id FROM vulnerabilities WHERE device_ip = ? AND port = ? AND service = ?",
                                        (current_ip, port_num, service))
                            existing_vuln = cur.fetchone()

                            if not existing_vuln:
                                cur.execute("INSERT INTO vulnerabilities (device_ip, port, service, script_output, severity, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                                            (current_ip, port_num, service, "Open port detected", 'Informational', ts))
                                log_message(f"Inserted informational vulnerability for {current_ip}:{port_num}/{service}")
                            else:
                                log_message(f"Informational vulnerability for {current_ip}:{port_num}/{service} already exists (ID: {existing_vuln[0]}).")
                            
                    except (ValueError, IndexError) as e:
                        log_message(f"Warning: Could not parse standard port/service line: {line} - Error: {e}", "WARNING")
                # If the line is empty or does not conform to a port entry, stop parsing ports.
                # This helps transition to other sections if headers are missed.
                elif not line.strip(): # Handles empty lines indicating end of section
                    parsing_ports_section = False
                    log_message("Exited PORT STATE SERVICE section (empty line).")
                continue


            # Parse lines within the Host script results section
            if parsing_host_script_results and current_ip:
                if line.startswith("|_") or line.startswith("| "): # Nmap script output lines
                    script_output = line.strip()
                    log_message(f"Processing script output: {script_output}")
                    
                    # Heuristic to determine if script output indicates a vulnerability.
                    # This can be improved with more precise regex for known script outputs.
                    is_vulnerable = ("vulnerable" in script_output.lower() or "vulnerability" in script_output.lower()) and \
                                    ("false" not in script_output.lower() and \
                                     "could not negotiate" not in script_output.lower() and \
                                     "error" not in script_output.lower())
                    
                    if is_vulnerable:
                        script_port = 0
                        script_service = "host_level_service"
                        
                        port_match = re.search(r'(\d+)/tcp', script_output)
                        if port_match:
                            try: script_port = int(port_match.group(1))
                            except ValueError: pass
                        
                        service_match = re.search(r'(\d+)/tcp\s+(\S+)', script_output)
                        if service_match and len(service_match.groups()) > 1:
                            script_service = service_match.group(2)
                        else:
                            if "smb-vuln" in script_output: script_service = "smb"
                            elif "http-vuln" in script_output: script_service = "http"

                        log_message(f"Script detected vulnerability for {current_ip}:{script_port}/{script_service}. Output: {script_output}")
                        try:
                            cur.execute("SELECT id FROM vulnerabilities WHERE device_ip = ? AND port = ? AND service = ?",
                                        (current_ip, script_port, script_service))
                            existing_vuln = cur.fetchone()

                            if existing_vuln:
                                cur.execute("UPDATE vulnerabilities SET script_output = ?, severity = ?, timestamp = ? WHERE id = ?",
                                            (script_output, 'High', ts, existing_vuln[0]))
                                log_message(f"Updated existing vulnerability (ID: {existing_vuln[0]}) to High severity.")
                            else:
                                cur.execute("INSERT INTO vulnerabilities (device_ip, port, service, script_output, severity, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                                            (current_ip, script_port, script_service, script_output, 'High', ts))
                                log_message(f"Inserted new High severity vulnerability for {current_ip}:{script_port}/{script_service}.")
                            conn.commit() # Commit after each vulnerability update
                        except sqlite3.Error as e:
                            log_message(f"SQL Error saving vulnerability for {current_ip}:{script_port}/{script_service}: {e}", "ERROR")
                    else:
                        log_message(f"Script output does not indicate a vulnerability: {script_output}")
                
                # If the line is empty or does not conform to a script output entry, stop parsing script results.
                elif not line.strip(): # Handles empty lines indicating end of section
                    parsing_host_script_results = False
                    log_message("Exited Host script results section (empty line).")
                continue

        # Commit the last device data after the loop finishes
        if current_ip:
            log_message(f"Final save for device {current_ip} (MAC: {current_mac}, OS: {current_os}).")
            cur.execute("INSERT OR IGNORE INTO devices (ip) VALUES (?)", (current_ip,))
            cur.execute("UPDATE devices SET status = 'up', last_seen = ?, mac = ?, vendor = ?, os = ? WHERE ip = ?",
                        (ts, current_mac, current_vendor, current_os, current_ip))

        conn.commit(); conn.close()
        log_message("Nmap output parsing complete and changes committed.")

class BaseTablePage(QWidget):
    """
    A base class for pages that display tabular data.
    Provides common functionalities such as `QTableWidget` setup, data loading,
    search/filtering, and CSV export. Derived classes must implement `load_data`.
    """
    def __init__(self, title: str, headers: List[str]):
        super().__init__(); self.headers=headers; layout=QVBoxLayout(self); layout.setContentsMargins(30,30,30,30); layout.setSpacing(20)
        top_layout = QHBoxLayout(); title_label = QLabel(title); title_label.setObjectName("PageTitle")
        self.search_input = QLineEdit(); self.search_input.setPlaceholderText("Search..."); self.search_input.textChanged.connect(self.filter_table)
        self.export_btn = QPushButton("Export CSV"); self.export_btn.clicked.connect(self.export_to_csv)
        top_layout.addWidget(title_label); top_layout.addStretch(); top_layout.addWidget(self.search_input, 1); top_layout.addWidget(self.export_btn)
        self.table = QTableWidget(); self.table.setColumnCount(len(headers)); self.table.setHorizontalHeaderLabels(headers)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.table.verticalHeader().setVisible(False)
        layout.addLayout(top_layout); layout.addWidget(self.table); self.load_data()

    def load_data(self): raise NotImplementedError
    def populate_table(self, data: List[tuple]):
        log_message(f"Populating table with {len(data)} rows.")
        self.table.setRowCount(0)
        for row_idx, row_data in enumerate(data):
            self.table.insertRow(row_idx)
            for col_idx, cell_data in enumerate(row_data): self.table.setItem(row_idx, col_idx, QTableWidgetItem(str(cell_data)))
        log_message("Table population complete.")
    def filter_table(self, text: str):
        log_message(f"Filtering table with text: {text}")
        for i in range(self.table.rowCount()):
            match = any(text.lower() in (self.table.item(i, j).text() or "").lower() for j in range(self.table.columnCount()))
            self.table.setRowHidden(i, not match)
        log_message("Table filtering complete.")
    def export_to_csv(self):
        log_message("Exporting data to CSV.")
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", str(REPORTS / f"{self.windowTitle()}_export.csv"), "CSV Files (*.csv)")
        if not filename:
            log_message("CSV export cancelled.", "INFO")
            return
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(self.headers)
                for row in range(self.table.rowCount()):
                    if not self.table.isRowHidden(row): writer.writerow([self.table.item(row, col).text() for col in range(self.table.columnCount())])
            QMessageBox.information(self, "Success", f"Data exported to {filename}")
            log_message(f"Data exported to {filename} successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not export CSV: {e}")
            log_message(f"Error exporting CSV: {e}", "ERROR")

class DevicesPage(BaseTablePage):
    """
    The DevicesPage displays a list of network devices discovered through scans.
    It inherits from `BaseTablePage` to provide tabular viewing, searching,
    and exporting of device-specific information like IP, MAC, OS, and status.
    """
    def __init__(self):
        super().__init__("Discovered Devices", ["IP", "MAC", "Vendor", "OS", "Status", "Last Seen"])
    def load_data(self):
        log_message("Loading data for DevicesPage.")
        try:
            conn=sqlite3.connect(DB); data=conn.cursor().execute("SELECT ip, mac, vendor, os, status, last_seen FROM devices").fetchall(); conn.close(); self.populate_table(data)
            log_message(f"DevicesPage loaded {len(data)} records.")
        except Exception as e:
            log_message(f"Error loading data for DevicesPage: {e}", "ERROR")

class VulnerabilitiesPage(BaseTablePage):
    """
    The VulnerabilitiesPage presents a detailed list of detected vulnerabilities.
    Inheriting from `BaseTablePage`, it offers tabular display, search, and export
    functionality for vulnerability data, including target IP, port, service,
    script output, severity, and discovery timestamp.
    """
    def __init__(self):
        super().__init__("Detected Vulnerabilities", ["Device IP", "Port", "Service", "Details", "Severity", "Timestamp"])
    def load_data(self):
        log_message("Loading data for VulnerabilitiesPage.")
        try:
            conn=sqlite3.connect(DB); data=conn.cursor().execute("SELECT device_ip, port, service, script_output, severity, timestamp FROM vulnerabilities").fetchall(); conn.close(); self.populate_table(data)
            log_message(f"VulnerabilitiesPage loaded {len(data)} records.")
        except Exception as e:
            log_message(f"Error loading data for VulnerabilitiesPage: {e}", "ERROR")

class ReportsPage(BaseTablePage):
    """
    The ReportsPage provides an interface to view and export historical scan reports.
    It extends `BaseTablePage` by offering additional export options for JSON and
    a basic text-based PDF representation of the scan data.
    """
    def __init__(self):
        # Call QWidget's init directly and manually set up the layout
        QWidget.__init__(self) 
        self.headers = ["ID", "Target", "Scan Type", "Timestamp"]
        layout = QVBoxLayout(self); layout.setContentsMargins(30,30,30,30); layout.setSpacing(20)

        # Custom top_layout with additional buttons
        top_layout = QHBoxLayout()
        title_label = QLabel("Scan Reports"); title_label.setObjectName("PageTitle")
        
        self.search_input = QLineEdit(); self.search_input.setPlaceholderText("Search..."); self.search_input.textChanged.connect(self.filter_table)
        self.export_csv_btn = QPushButton("Export CSV"); self.export_csv_btn.clicked.connect(self.export_to_csv)
        self.export_json_btn = QPushButton("Export JSON"); self.export_json_btn.clicked.connect(self.export_to_json)
        self.export_pdf_btn = QPushButton("Export PDF"); self.export_pdf_btn.clicked.connect(self.export_to_pdf)
        
        top_layout.addWidget(title_label)
        top_layout.addStretch()
        top_layout.addWidget(self.search_input, 1)
        top_layout.addWidget(self.export_csv_btn)
        top_layout.addWidget(self.export_json_btn)
        top_layout.addWidget(self.export_pdf_btn)

        self.table = QTableWidget(); self.table.setColumnCount(len(self.headers)); self.table.setHorizontalHeaderLabels(self.headers)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.table.verticalHeader().setVisible(False)
        
        layout.addLayout(top_layout); layout.addWidget(self.table); self.load_data()

    def export_to_json(self):
        log_message("Exporting data to JSON.")
        filename, _ = QFileDialog.getSaveFileName(self, "Save JSON", str(REPORTS / f"{self.windowTitle()}_export.json"), "JSON Files (*.json)")
        if not filename:
            log_message("JSON export cancelled.", "INFO")
            return
        try:
            conn = sqlite3.connect(DB); cur = conn.cursor()
            cur.execute("SELECT id, target, scan_type, timestamp, results FROM scans ORDER BY id DESC")
            rows = cur.fetchall()
            cols = [description[0] for description in cur.description] # Get column names
            conn.close()

            data_to_export = []
            for row in rows:
                data_to_export.append(dict(zip(cols, row)))

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data_to_export, f, indent=4)
            QMessageBox.information(self, "Success", f"Data exported to {filename}")
            log_message(f"Data exported to {filename} successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not export JSON: {e}")
            log_message(f"Error exporting JSON: {e}", "ERROR")

    def export_to_pdf(self):
        log_message("Exporting data to PDF.")
        filename, _ = QFileDialog.getSaveFileName(self, "Save PDF", str(REPORTS / f"{self.windowTitle()}_report.pdf"), "PDF Files (*.pdf);;Text Files (*.txt)")
        if not filename:
            log_message("PDF export cancelled.", "INFO")
            return
        try:
            # Retrieve data from the table (visible rows only)
            export_data = []
            headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]
            export_data.append(headers)

            for row_idx in range(self.table.rowCount()):
                if not self.table.isRowHidden(row_idx):
                    row_data = [self.table.item(row_idx, col_idx).text() for col_idx in range(self.table.columnCount())]
                    export_data.append(row_data)

            with open(filename, 'w', encoding='utf-8') as f:
                # Simple text formatting for PDF placeholder
                f.write(f"Report: {self.windowTitle()}\n")
                f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write headers
                f.write("{:<5} {:<20} {:<15} {:<20}\n".format(*export_data[0]))
                f.write("-" * 60 + "\n") # Separator

                # Write data rows
                for row_data in export_data[1:]:
                    f.write("{:<5} {:<20} {:<15} {:<20}\n".format(*row_data))

            QMessageBox.information(self, "Success", f"Data exported to {filename}")
            log_message(f"Data exported to {filename} successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not export PDF: {e}")
            log_message(f"Error exporting PDF: {e}", "ERROR")

            
    def load_data(self):
        log_message("Loading data for ReportsPage.")
        try:
            conn=sqlite3.connect(DB); data=conn.cursor().execute("SELECT id, target, scan_type, timestamp FROM scans ORDER BY id DESC").fetchall(); conn.close(); self.populate_table(data)
            log_message(f"ReportsPage loaded {len(data)} records.")
        except Exception as e:
            log_message(f"Error loading data for ReportsPage: {e}", "ERROR")

class SettingsPage(QWidget):
    """
    The SettingsPage allows users to manage various application settings,
    primarily focusing on the creation, modification, and deletion of custom Nmap scan templates.
    """
    def __init__(self, main_window: 'MainWindow'):
        super().__init__(); self.main_window = main_window
        layout = QVBoxLayout(self); layout.setContentsMargins(30,30,30,30); layout.setAlignment(Qt.AlignTop)
        title = QLabel("Settings"); title.setObjectName("PageTitle"); layout.addWidget(title)
        
        # --- Scan Template Management ---
        template_group = QFrame(); template_group.setObjectName("TemplateGroup"); template_group_layout = QVBoxLayout(template_group)
        template_group_layout.addWidget(QLabel("<h2>Scan Templates</h2>"))

        self.template_name_input = QLineEdit(); self.template_name_input.setPlaceholderText("Template Name")
        self.template_flags_input = QLineEdit(); self.template_flags_input.setPlaceholderText("Nmap Flags (e.g., -sC -sV)")
        
        template_form_layout = QHBoxLayout()
        template_form_layout.addWidget(self.template_name_input)
        template_form_layout.addWidget(self.template_flags_input)

        add_template_btn = QPushButton("Add Template"); add_template_btn.clicked.connect(self.add_template)
        
        self.template_list_combo = QComboBox()
        self.template_list_combo.currentIndexChanged.connect(self.load_template_details)
        self.load_templates_to_ui()

        delete_template_btn = QPushButton("Delete Selected Template"); delete_template_btn.clicked.connect(self.delete_template)

        template_group_layout.addLayout(template_form_layout)
        template_group_layout.addWidget(add_template_btn)
        template_group_layout.addWidget(self.template_list_combo)
        template_group_layout.addWidget(delete_template_btn)
        
        layout.addWidget(template_group)

    def load_templates_to_ui(self):
        log_message("Loading templates to UI.")
        self.templates = load_templates()
        self.template_list_combo.clear()
        for name in self.templates.keys():
            self.template_list_combo.addItem(name)
        self.load_template_details()
        log_message("Templates loaded to UI.")

    def load_template_details(self):
        selected_name = self.template_list_combo.currentText()
        if selected_name and selected_name in self.templates:
            self.template_name_input.setText(selected_name)
            self.template_flags_input.setText(" ".join(self.templates[selected_name]))
            log_message(f"Loaded details for template: {selected_name}")
        else:
            self.template_name_input.clear()
            self.template_flags_input.clear()
            log_message("Cleared template details.")

    def add_template(self):
        name = self.template_name_input.text().strip()
        flags = self.template_flags_input.text().strip()
        log_message(f"Attempting to add template: {name} with flags: {flags}")
        if not name or not flags:
            QMessageBox.warning(self, "Warning", "Template name and flags cannot be empty.")
            log_message("Template name or flags were empty.", "WARNING")
            return
        
        self.templates[name] = flags.split()
        save_templates(self.templates)
        self.load_templates_to_ui()
        self.main_window.pages["Network Scan"].load_scan_templates()
        QMessageBox.information(self, "Success", f"Template '{name}' added/updated.")
        log_message(f"Template '{name}' added/updated successfully.")

    def delete_template(self):
        selected_name = self.template_list_combo.currentText()
        log_message(f"Attempting to delete template: {selected_name}")
        if selected_name and selected_name in self.templates:
            reply = QMessageBox.question(self, "Confirm Delete", 
                                         f"Are you sure you want to delete template '{selected_name}'?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                del self.templates[selected_name]
                save_templates(self.templates)
                self.load_templates_to_ui()
                self.main_window.pages["Network Scan"].load_scan_templates()
                QMessageBox.information(self, "Success", f"Template '{selected_name}' deleted.")
                log_message(f"Template '{selected_name}' deleted successfully.")
            else:
                log_message("Template deletion cancelled by user.")
        else:
            QMessageBox.warning(self, "Warning", "No template selected to delete.")
            log_message("No template selected for deletion.", "WARNING")


if __name__ == "__main__":
    log_message("Application started.")
    if not shutil.which("nmap"):
        # QMessageBox.critical(None, "Nmap Not Found", "Nmap executable not found in PATH. Scans will fail.\nPlease install Nmap from https://nmap.org and add it to your system's PATH.")
        log_message("Nmap executable not found in PATH.", "WARNING")
        pass # The ScanThread will handle this
    app = QApplication(sys.argv); window = MainWindow(); window.show(); sys.exit(app.exec())
    log_message("Application exited.")
