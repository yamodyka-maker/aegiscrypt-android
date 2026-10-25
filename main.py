import os
import threading
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import StringProperty, ColorProperty
from kivy.clock import mainthread
from kivy.utils import platform

# تلاش برای ایمپورت کردن پلیر برای دسکتاپ
try:
    from plyer import filechooser
except ImportError:
    filechooser = None

# ایمپورت‌های اندرویدی برای فایل‌پیکر بومی
if platform == 'android':
    from jnius import autoclass
    from android import mActivity
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Intent = autoclass('android.content.Intent')
    Uri = autoclass('android.net.Uri')

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
import base64


class AegisScreen(Screen):
    status_text = StringProperty("آماده به کار")
    status_color = ColorProperty([1, 1, 1, 1])
    selected_path = StringProperty("")

    def select_file(self):
        """انتخاب فایل با پشتیبانی از انتخابگر بومی اندروید و دسکتاپ"""
        self.set_status("در حال باز کردن انتخابگر فایل...", [1, 0.8, 0, 1])
        
        if platform == 'android':
            try:
                # استفاده از Intent بومی اندروید (ACTION_OPEN_DOCUMENT) برای سازگاری کامل با Scoped Storage
                intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
                intent.addCategory(Intent.CATEGORY_OPENABLE)
                intent.setType("*/*")  # همه فایل‌ها
                
                # تعریف کالبک یا دریافت نتیجه (در اندروید پایتون، دریافت نتیجه از طریق PythonActivity پیاده می‌شود)
                # روش ساده‌تر و پایدار در Kivy Android: استفاده از Intent مستقیم
                current_activity = PythonActivity.mActivity
                current_activity.startActivityForResult(intent, 42)
                
                # نکته: برای دریافت مسیر در اندروید نیاز به پیاده‌سازی onActivityResult در ریشه اپلیکیشن است.
                # اما برای اینکه کار سریع راه بیفتد، یک راهکار تضمینی دیگر: استفاده از Pyobjus یا کادر متنی کمکی.
            except Exception as e:
                self.set_status(f"خطا در باز کردن فایل‌پیکر بومی: {e}", [1, 0, 0, 1])
        
        # حالت دسکتاپ یا تست با plyer
        elif filechooser:
            try:
                filechooser.open_file(on_selection=self.on_file_selected)
            except Exception as e:
                self.set_status(f"خطا در پلیر: {e}", [1, 0, 0, 1])
        else:
            self.set_status("انتخابگر فایل در این پلتفرم پشتیبانی نمی‌شود.", [1, 0, 0, 1])

    @mainthread
    def on_file_selected(self, selection):
        """کالبک زمان انتخاب فایل"""
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
        from kivy.clock import Clock
        Clock.schedule_once(update, 0)

    def run_action(self, action_type):
        if not self.selected_path or not os.path.exists(self.selected_path):
            self.set_status("لطفاً ابتدا یک فایل معتبر انتخاب کنید.", [1, 0, 0, 1])
            return

        # خواندن پارامترها و اجرای عملیات در ترد جداگانه
        try:
            iterations, parallel, password = self.read_kdf_parameters()
            if not password:
                return
            
            self.set_status(f"در حال پردازش ({action_type})...", [0, 0.7, 1, 1])
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
            salt = b'AegisCryptSaltVal' # در نسخه نهایی باید تصادفی و ذخیره شود
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


if `__name__ == '__main__':
    AegisApp().run()
