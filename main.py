import os
import threading
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import StringProperty, ColorProperty
from kivy.clock import mainthread, Clock
from kivy.utils import platform
from kivy.uix.popup import Popup
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView

# تنظیم پشتیبانی از متن فارسی
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    def fa(text):
        try:
            reshaped = arabic_reshaper.reshape(text)
            return get_display(reshaped)
        except Exception:
            return text
except ImportError:
    def fa(text):
        return text

# ایمپورت‌های رمزنگاری
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AegisScreen(Screen):
    status_text = StringProperty("آماده به کار")
    status_color = ColorProperty([1, 1, 1, 1])
    selected_path = StringProperty("")

    def get_initial_path(self):
        """مسیر شروع مرورگر فایل بر اساس پلتفرم"""
        if platform == 'android':
            # مسیر حافظه مشترک و پوشه دانلود در اکثر گوشی‌های اندروید
            paths_to_try = [
                '/storage/emulated/0/Download',
                '/storage/emulated/0/Documents',
                '/storage/emulated/0'
            ]
            for p in paths_to_try:
                if os.path.exists(p):
                    return p
            return '/storage/emulated/0'
        return os.path.expanduser('~')

    def select_file(self):
        """باز کردن پنجره داخلی و پایدار برای انتخاب فایل"""
        layout = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        initial_path = self.get_initial_path()
        file_chooser = FileChooserListView(path=initial_path, dirselect=False)
        layout.add_widget(file_chooser)
        
        btn_layout = BoxLayout(size_hint_y=None, height='45dp', spacing=10)
        
        popup = Popup(
            title=fa("انتخاب فایل"),
            content=layout,
            size_hint=(0.95, 0.9)
        )
        
        def confirm_selection(instance):
            if file_chooser.selection:
                self.on_file_selected(file_chooser.selection)
                popup.dismiss()
            else:
                self.set_status("لطفاً یک فایل را لمس کرده و انتخاب کنید.", [1, 0.5, 0, 1])
                
        def cancel_selection(instance):
            popup.dismiss()

        btn_select = Button(text=fa("انتخاب"), font_name='tahoma.ttf' if os.path.exists('tahoma.ttf') else 'Roboto')
        btn_select.bind(on_release=confirm_selection)
        
        btn_cancel = Button(text=fa("انصراف"), font_name='tahoma.ttf' if os.path.exists('tahoma.ttf') else 'Roboto')
        btn_cancel.bind(on_release=cancel_selection)
        
        btn_layout.add_widget(btn_select)
        btn_layout.add_widget(btn_cancel)
        layout.add_widget(btn_layout)
        
        popup.open()

    @mainthread
    def on_file_selected(self, selection):
        """مدیریت فایل انتخاب‌شده"""
        if selection and len(selection) > 0:
            self.selected_path = selection[0]
            filename = os.path.basename(self.selected_path)
            self.set_status(f"فایل انتخاب شد: {filename}", [0, 1, 0, 1])
        else:
            self.set_status("هیچ فایلی انتخاب نشد.", [1, 0.5, 0, 1])

    def set_status(self, text, color):
        @mainthread
        def update(dt):
            self.status_text = fa(text)
            self.status_color = color
        Clock.schedule_once(update, 0)

    def run_action(self, action_type):
        if not self.selected_path or not os.path.exists(self.selected_path):
            self.set_status("لطفاً ابتدا یک فایل معتبر انتخاب کنید.", [1, 0, 0, 1])
            return

        try:
            iterations, parallel, password = self.read_kdf_parameters()
            if not password:
                return
            
            action_fa = "رمزنگاری" if action_type == 'encrypt' else "رمزگشایی"
            self.set_status(f"در حال {action_fa}...", [0, 0.7, 1, 1])
            threading.Thread(
                target=self._worker,
                args=(action_type, self.selected_path, password, iterations, parallel),
                daemon=True
            ).start()
        except Exception as e:
            self.set_status(f"خطا: {str(e)}", [1, 0, 0, 1])

    def read_kdf_parameters(self):
        try:
            iterations = int(self.ids.iterations_input.text or 600000)
            parallel = int(self.ids.parallel_input.text or 4)
            password = self.ids.memory_input.text
            if not password:
                self.set_status("رمز عبور نمی‌تواند خالی باشد.", [1, 0, 0, 1])
                return None, None, None
            return iterations, parallel, password
        except ValueError:
            self.set_status("پارامترهای عددی نامعتبر هستند.", [1, 0, 0, 1])
            return None, None, None

    def _worker(self, action_type, file_path, password, iterations, parallel):
        try:
            salt = b'AegisCryptSaltVal'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key = kdf.derive(password.encode('utf-8'))
            aesgcm = AESGCM(key)

            if action_type == 'encrypt':
                with open(file_path, 'rb') as f:
                    data = f.read()
                ciphertext = aesgcm.encrypt(b'aegis_iv_12bytes', data, None)
                out_path = file_path + '.aegis'
                with open(out_path, 'wb') as f:
                    f.write(ciphertext)
                self.on_success(f"فایل با موفقیت رمزنگاری شد:\n{os.path.basename(out_path)}")

            elif action_type == 'decrypt':
                with open(file_path, 'rb') as f:
                    ciphertext = f.read()
                plaintext = aesgcm.decrypt(b'aegis_iv_12bytes', ciphertext, None)
                out_path = file_path[:-6] if file_path.endswith('.aegis') else file_path + '.dec'
                with open(out_path, 'wb') as f:
                    f.write(plaintext)
                self.on_success(f"فایل با موفقیت رمزگشایی شد:\n{os.path.basename(out_path)}")

        except InvalidTag:
            self.on_error("خطا: رمز عبور اشتباه است یا فایل دستکاری شده است.")
        except Exception as e:
            self.on_error(f"خطا در پردازش: {str(e)}")

    @mainthread
    def on_success(self, message):
        self.set_status(message, [0, 1, 0, 1])

    @mainthread
    def on_error(self, message):
        self.set_status(message, [1, 0, 0, 1])


class AegisApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(AegisScreen(name='aegis'))
        return sm


if __name__ == '__main__':
    AegisApp().run()
