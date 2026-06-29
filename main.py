import sys
import os
import json
import base64
import re
import urllib.parse
import tempfile
import requests
import subprocess
import ctypes
import socket
import time
import winreg
from threading import Event
from time import sleep

from PySide6.QtCore import (
    Qt, QThread, Signal, QSize, QTimer, QRect
)
from PySide6.QtGui import (
    QIcon, QFont, QColor, QPainter, QPixmap, QTextCursor
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
    QCheckBox, QSystemTrayIcon, QMenu, QMessageBox, QStyleFactory,
    QHeaderView, QAbstractItemView, QDialog, QDialogButtonBox,
    QFormLayout
)

# ─── constants ───────────────────────────────────────────────────
DEFAULT_SUB_URL = "https://sub.whitedns.shop/sub/base64.txt"
APP_NAME = "Teria VPN"
APP_VERSION = "v1.0.0"
PROXY_PORT = 10890
CACHE_FILE = "servers_cache.json"
SETTINGS_FILE = "settings.json"

# ─── TUN constants ────────────────────────────────────────────────
TUN_STACK = "system"
TUN_GATEWAY = "10.0.0.2"
TUN_INTERFACE_NAME = "Teria VPN"        # changed from WhiteDNS VPN
TUN_METRIC = 1

# ─── paths ────────────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

XRAY_EXE = os.path.join(BASE_DIR, "xray.exe")
WINTUN_DLL = os.path.join(BASE_DIR, "wintun.dll")
LOGO_ICO = os.path.join(BASE_DIR, "logo.ico")
TEMP_CONFIG = os.path.join(tempfile.gettempdir(), "white_dns_config.json")
CACHE_PATH = os.path.join(tempfile.gettempdir(), CACHE_FILE)
SETTINGS_PATH = os.path.join(tempfile.gettempdir(), SETTINGS_FILE)

# ─── default settings ────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "kill_switch": False,
    "run_on_startup": False
}


def parse_vless_url(url: str) -> dict:
    """Parse a VLESS link and return a dict with outbound config and display info."""
    try:
        url = url.strip()
        if not url.startswith("vless://"):
            return None
        if "#" in url:
            url_part, comment = url.split("#", 1)
            comment = urllib.parse.unquote(comment)
        else:
            url_part, comment = url, ""

        # Clean up any @WhiteDNS mentions (with optional spaces around)
        clean_comment = re.sub(r'\s*@WhiteDNS\s*', '', comment).strip()
        # Collapse multiple spaces into one
        clean_comment = re.sub(r'\s+', ' ', clean_comment)

        parsed = urllib.parse.urlparse(url_part)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        params = urllib.parse.parse_qs(parsed.query)
        security = params.get("security", ["none"])[0]
        network = params.get("type", ["tcp"])[0]
        header_type = params.get("headerType", ["none"])[0]
        path = params.get("path", ["/"])[0]
        host_param = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        encryption = params.get("encryption", ["none"])[0]
        mode = params.get("mode", ["auto"])[0]
        extra_str = params.get("extra", ["{}"])[0]
        try:
            extra = json.loads(extra_str)
        except:
            extra = {}
        path = urllib.parse.unquote(path)
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "encryption": encryption,
                        "flow": ""
                    }]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": security
            }
        }
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                "headers": {"Host": host_param} if host_param else {}
            }
        elif network == "tcp":
            if header_type == "http":
                outbound["streamSettings"]["tcpSettings"] = {
                    "header": {"type": "http", "request": {"path": path}}
                }
        elif network == "xhttp":
            xhttp_settings = {"path": path, "host": host_param, "mode": mode}
            if extra:
                xhttp_settings["extra"] = extra
            outbound["streamSettings"]["xhttpSettings"] = xhttp_settings
        if security == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": sni if sni else host,
                "allowInsecure": False,
                "fingerprint": fp
            }
        comment_parts = clean_comment.split("|") if clean_comment else []
        country = ""
        speed = "N/A"
        if len(comment_parts) >= 2:
            first_part = comment_parts[0].strip()
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', first_part)
            country = flag_match.group(0) if flag_match else first_part
            if len(comment_parts) >= 3:
                speed = comment_parts[2].strip()
        return {
            "outbound": outbound,
            "display": {
                "comment": comment,          # original (not used for display)
                "country": country,
                "speed": speed,
                "full_comment": clean_comment
            }
        }
    except Exception as e:
        print(f"Error parsing VLESS: {e}")
        return None


def fetch_and_decode_sub(url: str) -> list:
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            text = resp.text.strip()
            try:
                decoded = base64.b64decode(text).decode('utf-8')
            except:
                decoded = text
            links = [line for line in decoded.splitlines() if line.startswith("vless://")]
            return links
        except requests.exceptions.ConnectionError as e:
            if attempt == max_retries:
                raise
            sleep(1)


def build_inbound(mode: str):
    """Build inbound config based on mode: proxy or tun."""
    if mode == "proxy":
        return {
            "tag": "socks-in",
            "protocol": "socks",
            "port": PROXY_PORT,
            "settings": {
                "auth": "noauth",
                "udp": True
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        }
    elif mode == "tun":
        return {
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "mtu": 1500,
                "stack": TUN_STACK,
                "address": ["10.0.0.1/30"],
                "gateway": [f"{TUN_GATEWAY}/30"],
                "name": TUN_INTERFACE_NAME,      # "Teria VPN"
                "metric": TUN_METRIC,
                "dns": ["1.1.1.1", "8.8.8.8"]
            },
            "sniffing": {"enabled": False}
        }


def resolve_server_ip(server):
    try:
        return socket.gethostbyname(server)
    except:
        return None


def get_original_gateway():
    """Get default gateway IP (excluding TUN gateway)."""
    out, _ = subprocess.Popen(
        "route print 0.0.0.0", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    ).communicate()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            if parts[2] != TUN_GATEWAY:
                return parts[2]
    return None


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                return json.load(f)
        except:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(settings):
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Could not save settings: {e}")


def set_run_on_startup(enable):
    """Enable or disable run on startup via registry."""
    if not getattr(sys, 'frozen', False):
        return False
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        if enable:
            exe_path = sys.executable
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Startup registry error: {e}")
        return False


class SubUpdateThread(QThread):
    finished = Signal(list, str)

    def run(self):
        try:
            links = fetch_and_decode_sub(DEFAULT_SUB_URL)
            items = []
            for link in links:
                parsed = parse_vless_url(link)
                if parsed:
                    items.append(parsed)
            self.finished.emit(items, "")
        except Exception:
            self.finished.emit([], "No connection could be made because the target machine actively refused it / Please use a VPN to update the servers")


class XrayThread(QThread):
    log_signal = Signal(str)
    error_signal = Signal(str)

    def __init__(self, config_file, parent=None):
        super().__init__(parent)
        self.config_file = config_file
        self.process = None
        self._stop_event = Event()

    def run(self):
        try:
            self.process = subprocess.Popen(
                [XRAY_EXE, "run", "-config", self.config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
                universal_newlines=True,
                bufsize=1
            )
            for line in iter(self.process.stdout.readline, ""):
                if self._stop_event.is_set():
                    self.process.terminate()
                    break
                self.log_signal.emit(line.strip())
            self.process.stdout.close()
            self.process.wait()
        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        self._stop_event.set()
        if self.process:
            self.process.terminate()


class PingAllThread(QThread):
    """Thread for TCP ping test to each server."""
    result_signal = Signal(int, str)   # index, result string
    finished_signal = Signal()

    def __init__(self, servers, parent=None):
        super().__init__(parent)
        self.servers = servers

    def run(self):
        for i, s in enumerate(self.servers):
            outbound = s["outbound"]
            addr = outbound["settings"]["vnext"][0]["address"]
            port = outbound["settings"]["vnext"][0]["port"]
            start = time.time()
            try:
                sock = socket.create_connection((addr, port), timeout=5)
                sock.close()
                latency = (time.time() - start) * 1000
                self.result_signal.emit(i, f"{latency:.1f} ms")
            except Exception:
                self.result_signal.emit(i, "Timeout")
        self.finished_signal.emit()


class Switch(QCheckBox):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setFixedSize(60, 30)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("QCheckBox::indicator { width:0px; height:0px; }")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.setChecked(not self.isChecked())
        super().mousePressEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        track_rect = self.rect().adjusted(2, 2, -2, -2)
        track_color = QColor("#34C759") if self.isChecked() else QColor("#E5E5EA")
        painter.setBrush(track_color)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(track_rect, 15, 15)
        thumb_size = self.height() - 8
        thumb_x = self.width() - thumb_size - 4 if self.isChecked() else 4
        thumb_rect = QRect(thumb_x, 4, thumb_size, thumb_size)
        painter.setBrush(QColor("#007AFF"))
        painter.drawEllipse(thumb_rect)
        painter.end()


class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(350)
        self.settings = current_settings.copy()
        self.original_settings = current_settings.copy()

        layout = QFormLayout(self)

        self.kill_switch_cb = QCheckBox("Enable Kill Switch (block internet if VPN drops unexpectedly)")
        self.kill_switch_cb.setChecked(self.settings.get("kill_switch", False))
        layout.addRow(self.kill_switch_cb)

        self.run_on_startup_cb = QCheckBox("Run on Windows startup")
        self.run_on_startup_cb.setChecked(self.settings.get("run_on_startup", False))
        layout.addRow(self.run_on_startup_cb)

        button_layout = QHBoxLayout()
        reset_btn = QPushButton("Reset to Default")
        reset_btn.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_btn)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_and_accept)
        button_box.rejected.connect(self.reject)
        button_layout.addWidget(button_box)
        layout.addRow(button_layout)

    def reset_settings(self):
        self.kill_switch_cb.setChecked(DEFAULT_SETTINGS["kill_switch"])
        self.run_on_startup_cb.setChecked(DEFAULT_SETTINGS["run_on_startup"])

    def save_and_accept(self):
        self.settings["kill_switch"] = self.kill_switch_cb.isChecked()
        self.settings["run_on_startup"] = self.run_on_startup_cb.isChecked()
        self.accept()

    def get_settings(self):
        return self.settings


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1000, 700)
        self.resize(1100, 750)

        self.xray_thread = None
        self.current_mode = "proxy"
        self.servers = []
        self.selected_server_index = -1
        self.connected = False
        self.current_server_ip = None
        self.original_gateway = None
        self.tun_routes_applied = False
        self.ping_thread = None
        self.ping_results = {}
        self.user_disconnect = False

        # Settings
        self.settings = load_settings()
        self.kill_switch_enabled = self.settings.get("kill_switch", False)
        self.run_on_startup = self.settings.get("run_on_startup", False)

        if self.run_on_startup:
            set_run_on_startup(True)

        self.init_ui()
        self.apply_dark_theme()

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.get_app_icon())
        tray_menu = QMenu()
        restore_action = tray_menu.addAction("Restore")
        restore_action.triggered.connect(self.show)
        exit_action = tray_menu.addAction("Exit")
        exit_action.triggered.connect(self.quit_app)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

        self.load_cached_servers()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setSpacing(15)

        self.setWindowIcon(self.get_app_icon())

        # header
        header = QHBoxLayout()
        title = QLabel(APP_NAME)
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setStyleSheet("color: #4A90E2;")
        header.addWidget(title)
        header.addStretch()
        settings_btn = QPushButton("Settings")
        settings_btn.setFixedHeight(35)
        settings_btn.clicked.connect(self.open_settings)
        header.addWidget(settings_btn)
        main_layout.addLayout(header)

        # mode switch
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Mode:")
        mode_label.setFont(QFont("Segoe UI", 11))
        self.mode_switch = Switch()
        self.mode_switch.toggled.connect(self.on_mode_changed)
        self.mode_label_proxy = QLabel("Proxy Mode")
        self.mode_label_vpn = QLabel("Full VPN")
        self.mode_label_proxy.setFont(QFont("Segoe UI", 10))
        self.mode_label_vpn.setFont(QFont("Segoe UI", 10))
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_label_proxy)
        mode_layout.addWidget(self.mode_switch)
        mode_layout.addWidget(self.mode_label_vpn)
        mode_layout.addStretch()
        main_layout.addLayout(mode_layout)

        # Server Table
        self.server_table = QTableWidget()
        self.server_table.setColumnCount(4)
        self.server_table.setHorizontalHeaderLabels(["Country", "Ping", "Info", ""])
        self.server_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.server_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.server_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.server_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self.server_table.setColumnWidth(3, 80)
        self.server_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.server_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.server_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.server_table.verticalHeader().setVisible(False)
        self.server_table.setShowGrid(False)
        self.server_table.setAlternatingRowColors(True)
        self.server_table.verticalHeader().setDefaultSectionSize(45)
        self.server_table.itemSelectionChanged.connect(self.on_table_selection)
        main_layout.addWidget(self.server_table, 2)

        # buttons
        btn_layout = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setFixedHeight(45)
        self.connect_btn.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.connect_btn.clicked.connect(self.toggle_connection)
        btn_layout.addWidget(self.connect_btn)

        self.status_led = QLabel("●")
        self.status_led.setFont(QFont("Segoe UI", 14))
        btn_layout.addWidget(self.status_led)
        self.status_text = QLabel("Disconnected")
        self.status_text.setFont(QFont("Segoe UI", 10))
        btn_layout.addWidget(self.status_text)

        self.proxy_info_label = QLabel("")
        self.proxy_info_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.proxy_info_label.setStyleSheet("color: #007AFF;")
        btn_layout.addWidget(self.proxy_info_label)

        btn_layout.addStretch()

        self.ping_all_btn = QPushButton("Ping All")
        self.ping_all_btn.setFixedHeight(35)
        self.ping_all_btn.clicked.connect(self.start_ping_all)
        self.ping_all_btn.setEnabled(False)
        btn_layout.addWidget(self.ping_all_btn)

        update_btn = QPushButton("Update Servers")
        update_btn.setFixedHeight(35)
        update_btn.clicked.connect(self.update_subscription)
        btn_layout.addWidget(update_btn)
        main_layout.addLayout(btn_layout)

        # log area
        log_label = QLabel("Logs")
        log_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        main_layout.addWidget(log_label)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        main_layout.addWidget(self.log_text)

        # footer
        footer = QHBoxLayout()
        version_lbl = QLabel(APP_VERSION)
        version_lbl.setFont(QFont("Segoe UI", 9))
        footer.addWidget(version_lbl)
        footer.addStretch()
        made_by = QLabel("Made With ❤️ By AmooReza")
        made_by.setFont(QFont("Segoe UI", 9))
        footer.addWidget(made_by)
        main_layout.addLayout(footer)

    def apply_dark_theme(self):
        dark_qss = """
            QMainWindow { background-color: #1C1C1E; }
            QLabel { color: #FFFFFF; }
            QTableWidget { background-color: #2C2C2E; color: #FFFFFF; border: 1px solid #3A3A3C; border-radius: 12px; padding: 5px; gridline-color: #3A3A3C; }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background-color: #0A84FF; color: white; }
            QHeaderView::section { background-color: #2C2C2E; color: #FFFFFF; padding: 8px; border: none; font-weight: bold; }
            QPushButton { background-color: #0A84FF; color: white; border-radius: 10px; padding: 8px 16px; }
            QPushButton:hover { background-color: #0066CC; }
            QPushButton:pressed { background-color: #004499; }
            QPushButton:disabled { background-color: #555555; color: #888888; }
            QTextEdit { background-color: #2C2C2E; border: 1px solid #3A3A3C; border-radius: 8px; padding: 8px; color: #FFFFFF; }
            QCheckBox { color: white; }
            QCheckBox::indicator { width: 18px; height: 18px; }
        """
        self.setStyleSheet(dark_qss)

    def get_app_icon(self):
        if os.path.exists(LOGO_ICO):
            return QIcon(LOGO_ICO)
        pix = QPixmap(64, 64)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setBrush(QColor("#4A90E2"))
        painter.drawEllipse(4, 4, 56, 56)
        painter.end()
        return QIcon(pix)

    def open_settings(self):
        dialog = SettingsDialog(self, self.settings)
        if dialog.exec() == QDialog.Accepted:
            new_settings = dialog.get_settings()
            self.settings = new_settings
            save_settings(new_settings)
            self.kill_switch_enabled = new_settings["kill_switch"]
            if new_settings["run_on_startup"] != self.run_on_startup:
                set_run_on_startup(new_settings["run_on_startup"])
                self.run_on_startup = new_settings["run_on_startup"]
            self.append_log("Settings saved.")

    def on_mode_changed(self, checked):
        if checked:
            self.current_mode = "tun"
            self.mode_label_proxy.setStyleSheet("color: gray;")
            self.mode_label_vpn.setStyleSheet("color: white;")
        else:
            self.current_mode = "proxy"
            self.mode_label_proxy.setStyleSheet("color: white;")
            self.mode_label_vpn.setStyleSheet("color: gray;")
        if self.connected:
            self.disconnect_vpn()

    def load_cached_servers(self):
        if os.path.exists(CACHE_PATH):
            try:
                with open(CACHE_PATH, "r", encoding="utf-8") as f:
                    self.servers = json.load(f)
                self.populate_server_list()
                self.log_text.append("✅ Loaded cached servers.")
            except Exception as e:
                self.log_text.append(f"⚠️ Failed to load cache: {e}")

    def save_cache(self):
        try:
            with open(CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(self.servers, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log_text.append(f"⚠️ Could not save cache: {e}")

    def update_subscription(self):
        self.log_text.append("Updating subscription...")
        self.sub_thread = SubUpdateThread()
        self.sub_thread.finished.connect(self.on_sub_updated)
        self.sub_thread.start()

    def on_sub_updated(self, items, error):
        if error:
            self.log_text.append(f"❌ Error: {error}")
            return
        self.servers = items
        self.ping_results.clear()
        self.save_cache()
        self.populate_server_list()
        self.log_text.append(f"✅ Subscription updated: {len(items)} servers loaded.")

    def populate_server_list(self):
        self.server_table.setRowCount(0)
        for i, s in enumerate(self.servers):
            disp = s["display"]
            self.server_table.insertRow(i)
            # Country
            self.server_table.setItem(i, 0, QTableWidgetItem(disp["country"]))
            # Ping
            ping_text = self.ping_results.get(i, "")
            self.server_table.setItem(i, 1, QTableWidgetItem(ping_text))
            # Info (clean)
            self.server_table.setItem(i, 2, QTableWidgetItem(disp["full_comment"]))
            # Delete button
            delete_btn = QPushButton("Delete")
            delete_btn.setFixedSize(60, 28)
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.setStyleSheet("""
                QPushButton {
                    background-color: #FF3B30; 
                    color: white; 
                    border-radius: 6px; 
                    padding: 2px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #CC2F26;
                }
                QPushButton:pressed {
                    background-color: #A6241D;
                }
            """)
            delete_btn.clicked.connect(lambda checked, row=i: self.delete_config(row))
            self.server_table.setCellWidget(i, 3, delete_btn)

        if len(self.servers) > 0:
            self.server_table.selectRow(0)
            self.selected_server_index = 0
        else:
            self.selected_server_index = -1
        self.ping_all_btn.setEnabled(len(self.servers) > 0)

    def delete_config(self, row):
        if row < 0 or row >= len(self.servers):
            return
        reply = QMessageBox.question(self, "Delete Config",
                                     "Are you sure you want to delete this server?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.servers[row]
            new_ping = {}
            for k, v in self.ping_results.items():
                if k > row:
                    new_ping[k-1] = v
                elif k < row:
                    new_ping[k] = v
            self.ping_results = new_ping
            self.save_cache()
            self.populate_server_list()
            self.log_text.append(f"Server {row+1} deleted.")

    def on_table_selection(self):
        selected = self.server_table.selectionModel().selectedRows()
        if selected:
            self.selected_server_index = selected[0].row()
        else:
            self.selected_server_index = -1

    # ─── Ping All ─────────────────────────────────────────────────
    def start_ping_all(self):
        if not self.servers or self.ping_thread is not None:
            return
        self.ping_all_btn.setEnabled(False)
        self.append_log("⏳ Starting ping test for all servers...")
        self.ping_thread = PingAllThread(self.servers)
        self.ping_thread.result_signal.connect(self.on_ping_result)
        self.ping_thread.finished_signal.connect(self.ping_finished)
        self.ping_thread.start()

    def on_ping_result(self, index, text):
        self.ping_results[index] = text
        item = self.server_table.item(index, 1)
        if item:
            item.setText(text)

    def ping_finished(self):
        self.ping_all_btn.setEnabled(True)
        self.append_log("✅ Ping test completed.")
        self.ping_thread = None

    def toggle_connection(self):
        if self.connected:
            self.user_disconnect = True
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self):
        if self.selected_server_index < 0:
            QMessageBox.warning(self, "No server", "Please select a server first.")
            return
        if self.current_mode == "tun" and not self.is_admin():
            reply = QMessageBox.question(self, "Admin Rights",
                "Full VPN mode requires Administrator privileges. Restart as admin?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit()
            return

        outbound = self.servers[self.selected_server_index]["outbound"]
        inbound = build_inbound(self.current_mode)
        server_config = outbound["settings"]["vnext"][0]
        server_address = server_config["address"]

        if self.current_mode == "tun":
            self.current_server_ip = resolve_server_ip(server_address)
            if not self.current_server_ip:
                QMessageBox.warning(self, "Error", "Could not resolve server IP. Check your internet connection.")
                return
            self.original_gateway = get_original_gateway()
            self.append_log(f"Server IP: {self.current_server_ip}, Gateway: {self.original_gateway}")

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [inbound],
            "outbounds": [
                outbound,
                {"protocol": "freedom", "tag": "direct", "settings": {}}
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "outboundTag": "proxy",
                        "network": "tcp,udp"
                    }
                ]
            }
        }

        if self.current_mode == "tun":
            config["dns"] = {
                "servers": [
                    {"address": "1.1.1.1", "port": 53, "queryStrategy": "UseIP"},
                    {"address": "8.8.8.8", "port": 53, "queryStrategy": "UseIP"}
                ],
                "hosts": {
                    server_address: self.current_server_ip
                }
            }

        with open(TEMP_CONFIG, "w") as f:
            json.dump(config, f, indent=2)

        self.xray_thread = XrayThread(TEMP_CONFIG)
        self.xray_thread.log_signal.connect(self.append_log)
        self.xray_thread.error_signal.connect(self.append_log)
        self.xray_thread.finished.connect(self.on_xray_finished)
        self.xray_thread.start()

        self.connected = True
        self.connect_btn.setText("Disconnect")
        self.status_led.setStyleSheet("color: #34C759;")
        self.status_text.setText("Connected")
        if self.current_mode == "proxy":
            self.proxy_info_label.setText(f"127.0.0.1:{PROXY_PORT}")
        else:
            self.proxy_info_label.setText("")
        self.set_ui_enabled(False)
        self.user_disconnect = False

        if self.current_mode == "tun":
            QTimer.singleShot(3000, self.apply_tun_routes)

    def apply_tun_routes(self):
        if not self.connected or self.current_mode != "tun" or self.tun_routes_applied:
            return
        try:
            if self.original_gateway:
                subprocess.run(
                    f"route delete 0.0.0.0 mask 0.0.0.0 {self.original_gateway}",
                    shell=True, capture_output=True
                )
            subprocess.run(
                f"route add 0.0.0.0 mask 0.0.0.0 {TUN_GATEWAY} metric 1",
                shell=True, capture_output=True
            )
            if self.current_server_ip and self.original_gateway:
                subprocess.run(
                    f"route add {self.current_server_ip} mask 255.255.255.255 {self.original_gateway} metric 1",
                    shell=True, capture_output=True
                )
            subprocess.run(
                f'netsh interface ip set interface "{TUN_INTERFACE_NAME}" metric=1',
                shell=True, capture_output=True
            )
            subprocess.run(
                f'netsh interface ip set dns name="{TUN_INTERFACE_NAME}" static 1.1.1.1 primary',
                shell=True, capture_output=True
            )
            subprocess.run(
                f'netsh interface ip add dns name="{TUN_INTERFACE_NAME}" 8.8.8.8 index=2',
                shell=True, capture_output=True
            )
            self.tun_routes_applied = True
            self.append_log("✅ Full VPN routing & DNS applied.")
        except Exception as e:
            self.append_log(f"⚠️ Failed to apply TUN routes: {e}")

    def remove_tun_routes(self):
        if not self.tun_routes_applied:
            return
        try:
            subprocess.run(
                f"route delete 0.0.0.0 mask 0.0.0.0 {TUN_GATEWAY}",
                shell=True, capture_output=True
            )
            if self.original_gateway:
                subprocess.run(
                    f"route add 0.0.0.0 mask 0.0.0.0 {self.original_gateway} metric 25",
                    shell=True, capture_output=True
                )
            if self.current_server_ip and self.original_gateway:
                subprocess.run(
                    f"route delete {self.current_server_ip} mask 255.255.255.255 {self.original_gateway}",
                    shell=True, capture_output=True
                )
            subprocess.run(
                f'netsh interface ip set interface "{TUN_INTERFACE_NAME}" metric=auto',
                shell=True, capture_output=True
            )
            subprocess.run(
                f'netsh interface ip set dns name="{TUN_INTERFACE_NAME}" dhcp',
                shell=True, capture_output=True
            )
            self.tun_routes_applied = False
            self.append_log("🔁 TUN routes removed.")
        except Exception as e:
            self.append_log(f"⚠️ Failed to remove TUN routes: {e}")

    def disconnect_vpn(self):
        if self.current_mode == "tun":
            if not self.user_disconnect and self.kill_switch_enabled:
                self.append_log("⚠️ Kill Switch active – routes left broken.")
            else:
                self.remove_tun_routes()

        if self.xray_thread:
            self.xray_thread.stop()
            self.xray_thread.wait(3000)
            self.xray_thread = None
        self.connected = False
        self.connect_btn.setText("Connect")
        self.status_led.setStyleSheet("color: #FF3B30;")
        self.status_text.setText("Disconnected")
        self.proxy_info_label.setText("")
        self.set_ui_enabled(True)
        self.current_server_ip = None
        self.original_gateway = None

    def on_xray_finished(self):
        self.connected = False
        self.connect_btn.setText("Connect")
        self.status_led.setStyleSheet("color: #FF3B30;")
        self.status_text.setText("Disconnected")
        self.proxy_info_label.setText("")
        self.set_ui_enabled(True)
        self.append_log("Xray core stopped unexpectedly.")
        if self.current_mode == "tun" and self.kill_switch_enabled:
            self.append_log("⚠️ Kill Switch active – routes left broken.")
        else:
            self.remove_tun_routes()

    def append_log(self, message):
        self.log_text.append(message)
        self.log_text.moveCursor(QTextCursor.End)

    def set_ui_enabled(self, enabled):
        self.server_table.setEnabled(enabled)
        self.mode_switch.setEnabled(enabled)
        self.connect_btn.setEnabled(True)

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Close Program")
            msg_box.setText("What do you want to do?")
            exit_btn = msg_box.addButton("Exit", QMessageBox.ActionRole)
            tray_btn = msg_box.addButton("Minimize to Tray", QMessageBox.ActionRole)
            cancel_btn = msg_box.addButton("Cancel", QMessageBox.RejectRole)
            msg_box.exec()
            if msg_box.clickedButton() == exit_btn:
                self.quit_app()
            elif msg_box.clickedButton() == tray_btn:
                self.hide()
                event.ignore()
            else:
                event.ignore()
        else:
            self.quit_app()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()

    def quit_app(self):
        if self.connected:
            self.user_disconnect = True
            self.disconnect_vpn()
        self.tray_icon.hide()
        QApplication.quit()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setQuitOnLastWindowClosed(False)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())