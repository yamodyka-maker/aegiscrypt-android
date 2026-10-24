import os
import threading
from kivy.clock import mainthread

from kivy.app import App
from kivy.clock import Clock
from kivy.properties import StringProperty, ListProperty
from kivy.uix.screenmanager import Screen
from plyer import filechooser

import arabic_reshaper
from bidi.algorithm import get_display

from crypto_engine import encrypt_file, decrypt_file


def fa(text: str) -> str:
    """اصلاح شکل و جهت نمایش متن فارسی در Kivy."""
    try:
        return get_display(arabic_reshaper.reshape(str(text)))
    except Exception:
        return str(text)

from kivy.properties import ListProperty, StringProperty
class AegisScreen(Screen): # یا هر نام کلاسی که صفحه‌تان دارد
    status_color = ListProperty([1, 1, 1, 1]) # رنگ پیش‌فرض مثلاً سفید یا سبز/قرمز دلخواه
    # تطابق ۱۰۰ درصدی با متغیرهای aegis.kv
    title_text = StringProperty("AegisCrypt Secure Vault")
    btn_algo_text = StringProperty("Algorithm: AES-256-GCM")
    btn_select_text = StringProperty("Select File")
    selected_file_text = StringProperty("No file selected")
    hint_pwd_text = StringProperty("Enter password...")
    
    memory_label = StringProperty("Argon2 Memory (MiB):")
    iterations_label = StringProperty("Iterations (Time Cost):")
    parallel_label = StringProperty("Parallelism (Threads):")
    
    btn_enc_text = StringProperty("Encrypt File")
    btn_dec_text = StringProperty("Decrypt File")
    status_text = StringProperty("Status: Ready")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_path = None
        self.current_algorithm = "AES-256-GCM"

    def toggle_algorithm(self):
        if self.current_algorithm == "AES-256-GCM":
            self.current_algorithm = "ChaCha20-Poly1305"
        else:
            self.current_algorithm = "AES-256-GCM"
        self.btn_algo_text = f"Algorithm: {self.current_algorithm}"

    def select_file(self):
        try:
            filechooser.open_file(on_selection=self._on_file_selected)
        except Exception as e:
            self.status_text = f"Error: {e}"

    @mainthread
    def _on_file_selected(self, selection):
        if not selection:
            self.status_text = "No file selected"
            return

        # اگر خروجی لیست یا تاپل بود اولین آیتم، وگرنه خود مقدار
        path = selection[0] if isinstance(selection, (list, tuple)) else selection
        
        if isinstance(path, bytes):
            path = path.decode('utf-8')
            
        self.selected_path = str(path)
        filename = os.path.basename(self.selected_path)
        
        # آپدیت فیلدهای نمایشی روی ترد اصلی
        self.selected_file_text = f"Selected: {filename}"
        self.status_text = "Status: File loaded successfully"
    def read_kdf_parameters(self):
        try:
            m_input = int(self.ids.memory_input.text.strip() or 64)
            t = int(self.ids.iterations_input.text.strip() or 2)
            p = int(self.ids.parallel_input.text.strip() or 2)
            
            if not (8 <= m_input <= 512):
                raise ValueError("Memory must be between 8 and 512 MiB")
            if not (1 <= t <= 10):
                raise ValueError("Iterations must be between 1 and 10")
            if not (1 <= p <= 8):
                raise ValueError("Parallelism must be between 1 and 8")
                
            return m_input * 1024, t, p
        except ValueError as ve:
            raise ValueError(str(ve))

    
    def run_action(self, mode, password):
        if not self.selected_path:
            self.status_text = "Error: Please select a valid file first."
            return

        # اگر مسیر با content:// شروع شود معتبر است؛ در غیر این صورت باید روی دیسک وجود داشته باشد
        if not self.selected_path.startswith("content://") and not os.path.exists(self.selected_path):
            self.status_text = "Error: File path is not accessible."
            return

        if not password:
            self.status_text = "Error: Password cannot be empty."
            return
        kdf_params = None
        algorithm = self.current_algorithm
        
        if mode == 'encrypt':
            try:
                kdf_params = self.read_kdf_parameters()
            except ValueError as e:
                self.status_text = f"Config Error: {e}"
                return

        src = self.selected_path
        self.status_text = f"Status: Processing {mode}..."

        threading.Thread(
            target=self._worker,
            args=(mode, password, src, algorithm, kdf_params),
            daemon=True,
        ).start()

    def _worker(self, mode, password, src, algorithm, kdf_params):
        try:
            if mode == 'encrypt':
                memory_kib, iterations, parallel = kdf_params
                dst = src + ".aegis"
                encrypt_file(
                    src, dst, password, algorithm,
                    memory_kib, iterations, parallel
                )
                Clock.schedule_once(lambda dt: self.on_success(dst, "encrypted"))
            else:
                dst = (src[:-6] + ".decrypted" 
                       if src.endswith(".aegis") 
                       else src + ".decrypted")
                decrypt_file(src, dst, password)
                Clock.schedule_once(lambda dt: self.on_success(dst, "decrypted"))
        except InvalidTag:
            Clock.schedule_once(lambda dt: self.on_error("Decryption failed: Wrong password or tampered file."))
        except Exception as exc:
            Clock.schedule_once(lambda dt: self.on_error(f"Error: {exc}"))

    def on_success(self, dst, action_type):
        filename = os.path.basename(dst)
        self.status_text = f"Success: File {action_type} -> {filename}"

    def on_error(self, message):
        self.status_text = message


class AegisApp(App):
    def build(self):
        return AegisScreen()


if __name__ == '__main__':
    AegisApp().run()
