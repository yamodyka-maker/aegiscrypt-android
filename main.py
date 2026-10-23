import traceback
import sys
from kivy.app import App
from kivy.uix.label import Label
try:
    import crypto_engine
except Exception as e:
    crypto_engine = None
    IMPORT_ERROR = str(e)

# تله برای گرفتن ارورهای پایتون و نمایش روی صفحه گوشی به جای بسته شدن ناگهانی
def show_crash_screen(error_text):
    class CrashApp(App):
        def build(self):
            return Label(text=error_text, font_size=14, halign='center', valign='middle')
    CrashApp().run()

import os
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.properties import StringProperty, ListProperty
from kivy.uix.screenmanager import Screen
from plyer import filechooser

#import arabic_reshaper
#from bidi.algorithm import get_display
#from cryptography.exceptions import InvalidTag

from crypto_engine import encrypt_file, decrypt_file

#def fix_text(text: str) -> str:
#    return text  # فعلا بدون reshaping برای تست اجرا

def fa(text: str) -> str:
    """اصلاح شکل و جهت نمایش متن فارسی در Kivy."""
    try:
#        return get_display(arabic_reshaper.reshape(str(text)))
    except Exception:
        return str(text)


class AegisScreen(Screen):
    title_text = StringProperty(fa("AegisCrypt - محافظ فایل"))

    btn_algo_text = StringProperty(fa("الگوریتم: AES-256-GCM"))
    btn_select_text = StringProperty(fa("[ انتخاب فایل ]"))
    hint_pwd_text = StringProperty(fa("رمز عبور را وارد کنید..."))
    btn_enc_text = StringProperty(fa("رمزنگاری"))
    btn_dec_text = StringProperty(fa("رمزگشایی"))

    memory_label = StringProperty(fa("حافظه (MiB)"))
    iterations_label = StringProperty(fa("تکرار"))
    parallel_label = StringProperty(fa("موازی‌سازی"))

    selected_path = None
    current_algorithm = "AES-256-GCM"

    selected_file_text = StringProperty(fa("فایلی انتخاب نشده است"))
    status_text = StringProperty(fa("سیستم آماده است (AEAD Protected)"))
    status_color = ListProperty([0.58, 0.64, 0.72, 1])

    def set_status(self, text, color=None):
        self.status_text = fa(text)
        if color is not None:
            self.status_color = color

    def toggle_algorithm(self):
        if self.current_algorithm == "AES-256-GCM":
            self.current_algorithm = "ChaCha20-Poly1305"
        else:
            self.current_algorithm = "AES-256-GCM"

        self.btn_algo_text = fa(f"الگوریتم: {self.current_algorithm}")
        self.set_status(
            f"الگوریتم انتخاب شد: {self.current_algorithm}",
            [0.13, 0.83, 0.93, 1],
        )

    def select_file(self):
        try:
            filechooser.open_file(on_selection=self.on_file_selected)
        except Exception as exc:
            self.set_status(
                f"خطا در باز کردن فایل‌خوان: {exc}",
                [0.97, 0.44, 0.44, 1],
            )

    def on_file_selected(self, selection):
        if not selection:
            return

        try:
            self.selected_path = selection[0]
            size_mb = os.path.getsize(self.selected_path) / (1024 * 1024)
            filename = os.path.basename(self.selected_path)

            self.selected_file_text = fa(
                f"فایل: {filename} ({size_mb:.2f} MB)"
            )
            self.set_status(
                "فایل انتخاب شد. آماده عملیات.",
                [0.13, 0.77, 0.37, 1],
            )
        except Exception as exc:
            self.set_status(
                f"خطا در خواندن فایل: {exc}",
                [0.97, 0.44, 0.44, 1],
            )

    def read_kdf_parameters(self):
        try:
            memory_mib = int(self.ids.memory_input.text.strip())
            iterations = int(self.ids.iterations_input.text.strip())
            parallel = int(self.ids.parallel_input.text.strip())
        except ValueError:
            raise ValueError("مقادیر حافظه، تکرار و موازی‌سازی باید عدد صحیح باشند.")

        if not 8 <= memory_mib <= 512:
            raise ValueError("حافظه باید بین 8 تا 512 MiB باشد.")

        if not 1 <= iterations <= 10:
            raise ValueError("تعداد تکرار باید بین 1 تا 10 باشد.")

        if not 1 <= parallel <= 8:
            raise ValueError("موازی‌سازی باید بین 1 تا 8 باشد.")

        memory_kib = memory_mib * 1024
        return memory_kib, iterations, parallel

    def run_action(self, mode: str, password: str):
        if not self.selected_path or not os.path.exists(self.selected_path):
            self.set_status(
                "لطفاً ابتدا یک فایل را انتخاب کنید.",
                [0.97, 0.44, 0.44, 1],
            )
            return

        if not password:
            self.set_status(
                "رمز عبور نمی‌تواند خالی باشد.",
                [0.97, 0.44, 0.44, 1],
            )
            return

        kdf_params = None
        algorithm = None

        if mode == "encrypt":
            try:
                kdf_params = self.read_kdf_parameters()
            except ValueError as exc:
                self.set_status(str(exc), [0.97, 0.44, 0.44, 1])
                return

            algorithm = self.current_algorithm

        src = self.selected_path

        self.set_status(
            "در حال پردازش در پس‌زمینه...",
            [0.13, 0.83, 0.93, 1],
        )

        threading.Thread(
            target=self._worker,
            args=(mode, password, src, algorithm, kdf_params),
            daemon=True,
        ).start()

    def _worker(self, mode, password, src, algorithm, kdf_params):
        try:
            if mode == "encrypt":
                memory_kib, iterations, parallel = kdf_params
                dst = src + ".aegis"

                encrypt_file(
                    src,
                    dst,
                    password,
                    algorithm,
                    memory_kib,
                    iterations,
                    parallel,
                )

                filename = os.path.basename(dst)
                message = (
                    f"[موفق] رمزنگاری انجام شد ({algorithm})\n"
                    f"حافظه: {memory_kib // 1024} MiB | "
                    f"تکرار: {iterations} | "
                    f"موازی‌سازی: {parallel}\n"
                    f"خروجی: {filename}"
                )

                Clock.schedule_once(
                    lambda dt: self.set_status(
                        message,
                        [0.13, 0.77, 0.37, 1],
                    )
                )

            else:
                dst = (
                    src[:-6] + ".decrypted"
                    if src.endswith(".aegis")
                    else src + ".decrypted"
                )

                algo_name, memory_kib, iterations, parallel = decrypt_file(
                    src,
                    dst,
                    password,
                )

                filename = os.path.basename(dst)
                message = (
                    f"[موفق] رمزگشایی انجام شد ({algo_name})\n"
                    f"حافظه: {memory_kib // 1024} MiB | "
                    f"تکرار: {iterations} | "
                    f"موازی‌سازی: {parallel}\n"
                    f"خروجی: {filename}"
                )

                Clock.schedule_once(
                    lambda dt: self.set_status(
                        message,
                        [0.13, 0.77, 0.37, 1],
                    )
                )

        except InvalidTag:
            Clock.schedule_once(
                lambda dt: self.set_status(
                    "[خطا] رمز عبور نادرست است یا فایل دستکاری شده است.",
                    [0.97, 0.44, 0.44, 1],
                )
            )

        except Exception as exc:
            error_message = f"[خطا] در پردازش: {exc}"
            Clock.schedule_once(
                lambda dt: self.set_status(
                    error_message,
                    [0.97, 0.44, 0.44, 1],
                )
            )


class AegisApp(App):
    def build(self):
        self.title = "AegisCrypt"
        return AegisScreen()


if __name__ == '__main__':
    try:
        # نام کلاس اصلی برنامه شما (مثلاً AegisApp)
        AegisApp().run()
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        
        # اگر خطا رخ داد، یک صفحه اضطراری متن خطا را نشان دهد
        from kivy.app import App
        from kivy.uix.scrollview import ScrollView
        from kivy.uix.label import Label
        
        class CrashReporterApp(App):
            def build(self):
                sv = ScrollView()
                lbl = Label(text=err_msg, size_hint_y=None, font_size='12sp')
                lbl.bind(texture_size=lbl.setter('size'))
                sv.add_widget(lbl)
                return sv
                
        CrashReporterApp().run()
