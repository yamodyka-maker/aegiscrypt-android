import sys
import traceback

CRASH_ERROR = None

try:
    import os, threading
    from kivy.app import App
    from kivy.clock import Clock
    from kivy.properties import StringProperty, ListProperty
    from kivy.uix.screenmanager import Screen
    from plyer import filechooser
    import arabic_reshaper
    from bidi.algorithm import get_display
    from cryptography.exceptions import InvalidTag
    from crypto_engine import encrypt_file, decrypt_file
except Exception:
    CRASH_ERROR = traceback.format_exc()

if CRASH_ERROR:
    from kivy.app import App
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.label import Label

    class CrashApp(App):
        def build(self):
            sv = ScrollView()
            lbl = Label(
                text=f"=== STARTUP IMPORT ERROR ===\n\n{CRASH_ERROR}",
                size_hint_y=None,
                font_size='13sp',
                halign='left',
                valign='top'
            )
            lbl.bind(texture_size=lbl.setter('size'))
            sv.add_widget(lbl)
            return sv

    if __name__ == '__main__':
        CrashApp().run()

else:
    # کدهای اصلی خود برنامه
    def fix_text(text: str) -> str:
        try:
            reshaped = arabic_reshaper.reshape(text)
            return get_display(reshaped)
        except Exception:
            return text

    class AegisScreen(Screen):
        selected_file = StringProperty("")
        status_text   = StringProperty("")
        status_color  = ListProperty([0.5, 0.5, 0.5, 1])

        def on_kv_post(self, base_widget):
            super().on_kv_post(base_widget)
            self.set_status("Ready", [0.4, 0.8, 0.4, 1])

        def set_status(self, text, color):
            self.status_text  = fix_text(text)
            self.status_color = color

        def open_file_chooser(self):
            try:
                filechooser.open_file(on_selection=self._on_file_selected)
            except Exception as e:
                self.set_status(f"Error opening file: {e}", [0.9, 0.3, 0.3, 1])

        def _on_file_selected(self, selection):
            if selection:
                self.selected_file = selection[0]
                fname = os.path.basename(selection[0])
                self.set_status(f"Selected: {fname}", [0.4, 0.8, 0.4, 1])

        def start_encrypt(self):
            pw  = self.ids.password_input.text
            alg = self.ids.algo_spinner.text
            path = self.selected_file

            if not path or not os.path.exists(path):
                self.set_status("Please select a file first.", [0.9, 0.3, 0.3, 1])
                return
            if not pw:
                self.set_status("Password cannot be empty.", [0.9, 0.3, 0.3, 1])
                return

            self.set_status("Encrypting...", [0.3, 0.6, 1, 1])
            self.ids.btn_encrypt.disabled = True
            self.ids.btn_decrypt.disabled = True

            t = threading.Thread(target=self._run_encrypt, args=(path, pw, alg), daemon=True)
            t.start()

        def _run_encrypt(self, path, pw, alg):
            try:
                out = encrypt_file(path, pw, alg)
                Clock.schedule_once(lambda dt: self._on_success(f"Encrypted:\n{os.path.basename(out)}"))
            except Exception as e:
                Clock.schedule_once(lambda dt: self._on_error(str(e)))

        def start_decrypt(self):
            pw   = self.ids.password_input.text
            path = self.selected_file

            if not path or not os.path.exists(path):
                self.set_status("Please select a file first.", [0.9, 0.3, 0.3, 1])
                return
            if not pw:
                self.set_status("Password cannot be empty.", [0.9, 0.3, 0.3, 1])
                return

            self.set_status("Decrypting...", [0.3, 0.6, 1, 1])
            self.ids.btn_encrypt.disabled = True
            self.ids.btn_decrypt.disabled = True

            t = threading.Thread(target=self._run_decrypt, args=(path, pw), daemon=True)
            t.start()

        def _run_decrypt(self, path, pw):
            try:
                out = decrypt_file(path, pw)
                Clock.schedule_once(lambda dt: self._on_success(f"Decrypted:\n{os.path.basename(out)}"))
            except InvalidTag:
                Clock.schedule_once(lambda dt: self._on_error("Decryption failed! Wrong password or corrupt file."))
            except Exception as e:
                Clock.schedule_once(lambda dt: self._on_error(str(e)))

        def _on_success(self, msg):
            self.set_status(msg, [0.4, 0.8, 0.4, 1])
            self.ids.btn_encrypt.disabled = False
            self.ids.btn_decrypt.disabled = False

        def _on_error(self, msg):
            self.set_status(f"Error: {msg}", [0.9, 0.3, 0.3, 1])
            self.ids.btn_encrypt.disabled = False
            self.ids.btn_decrypt.disabled = False


    class AegisApp(App):
        def build(self):
            self.title = "AegisCrypt"
            try:
                return AegisScreen()
            except Exception:
                from kivy.uix.scrollview import ScrollView
                from kivy.uix.label import Label
                sv = ScrollView()
                lbl = Label(text=traceback.format_exc(), size_hint_y=None, font_size='13sp')
                lbl.bind(texture_size=lbl.setter('size'))
                sv.add_widget(lbl)
                return sv

    if __name__ == '__main__':
        AegisApp().run()
