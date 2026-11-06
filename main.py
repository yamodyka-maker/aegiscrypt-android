import os
import struct
import threading
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp, sp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.utils import platform

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ----------------- Crypto (same format as desktop version) -----------------
MAGIC = b"AEGISCRYPT1"
CHUNK_SIZE = 1024 * 1024


def create_cipher(algorithm_name: str, key: bytes):
    if algorithm_name == "AES-256-GCM":
        return AESGCM(key), 1
    if algorithm_name == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key), 2
    raise ValueError(f"Unknown algorithm: {algorithm_name}")


def get_cipher_by_id(algo_id: int, key: bytes):
    if algo_id == 1:
        return AESGCM(key), "AES-256-GCM"
    if algo_id == 2:
        return ChaCha20Poly1305(key), "ChaCha20-Poly1305"
    raise ValueError(f"Unknown algorithm ID: {algo_id}")


def derive_key(password: str, salt: bytes, mem_kib: int, iters: int, parallel: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=iters,
        memory_cost=mem_kib,
        parallelism=parallel,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_file(src: str, dst: str, password: str, algo: str, mem_kib: int, iters: int, parallel: int):
    salt = os.urandom(16)
    nonce_prefix = os.urandom(8)
    key = derive_key(password, salt, mem_kib, iters, parallel)
    cipher, algo_id = create_cipher(algo, key)
    header = MAGIC + salt + nonce_prefix + bytes([algo_id]) + struct.pack(">III", mem_kib, iters, parallel)

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header)
        chunk_idx = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk and chunk_idx != 0:
                break
            nonce = nonce_prefix + struct.pack(">I", chunk_idx)
            aad = header + struct.pack(">I", chunk_idx)
            encrypted = cipher.encrypt(nonce, chunk, aad)
            fout.write(struct.pack(">I", len(encrypted)))
            fout.write(encrypted)
            chunk_idx += 1
            if not chunk:
                break


def decrypt_file(src: str, dst: str, password: str):
    header_len = len(MAGIC) + 16 + 8 + 1 + 12
    with open(src, "rb") as fin:
        header = fin.read(header_len)
        if len(header) < header_len or not header.startswith(MAGIC):
            raise ValueError("Invalid file format or missing AegisCrypt magic bytes.")

        offset = len(MAGIC)
        salt = header[offset:offset + 16]; offset += 16
        nonce_prefix = header[offset:offset + 8]; offset += 8
        algo_id = header[offset]; offset += 1
        mem_kib, iters, parallel = struct.unpack(">III", header[offset:offset + 12])

        key = derive_key(password, salt, mem_kib, iters, parallel)
        cipher, algo_name = get_cipher_by_id(algo_id, key)

        with open(dst, "wb") as fout:
            chunk_idx = 0
            while True:
                length_bytes = fin.read(4)
                if not length_bytes:
                    break
                chunk_len = struct.unpack(">I", length_bytes)[0]
                encrypted = fin.read(chunk_len)
                if len(encrypted) != chunk_len:
                    raise ValueError("File is corrupted or truncated.")
                nonce = nonce_prefix + struct.pack(">I", chunk_idx)
                aad = header + struct.pack(">I", chunk_idx)
                fout.write(cipher.decrypt(nonce, encrypted, aad))
                chunk_idx += 1

    return algo_name, mem_kib, iters, parallel


# ----------------- Android helpers -----------------
def storage_root() -> str:
    if platform == "android":
        from android.storage import primary_external_storage_path
        return primary_external_storage_path()
    return os.path.expanduser("~")


def output_dir() -> str:
    d = os.path.join(storage_root(), "Download", "AegisCrypt")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        from kivy.storage.jsonstore import JsonStore  # noqa: F401 (safe fallback below)
        d = os.path.join(App.get_running_app().user_data_dir, "AegisCrypt")
        os.makedirs(d, exist_ok=True)
    return d


def unique_path(path: str) -> str:
    base, ext = os.path.splitext(path)
    n = 1
    while os.path.exists(path):
        path = f"{base} ({n}){ext}"
        n += 1
    return path


DARK = {
    "bg": (0.04, 0.07, 0.12, 1),
    "panel": (0.07, 0.11, 0.17, 1),
    "accent": (0.13, 0.83, 0.93, 1),
    "text": (0.89, 0.91, 0.94, 1),
    "muted": (0.39, 0.45, 0.55, 1),
    "green": (0.13, 0.77, 0.37, 1),
    "red": (0.97, 0.44, 0.44, 1),
}


# ----------------- UI -----------------
class AegisApp(App):
    def build(self):
        self.title = "AegisCrypt"
        Window.clearcolor = DARK["bg"]
        self.src = None

        root = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(8))

        root.add_widget(Label(text="🛡 AegisCrypt", font_size=sp(22), color=DARK["accent"],
                              size_hint_y=None, height=dp(48)))

        self.mode = Spinner(text="Encrypt", values=("Encrypt", "Decrypt"),
                            size_hint_y=None, height=dp(44))
        self.mode.bind(text=self.on_mode_change)
        root.add_widget(self.mode)

        self.pick_btn = Button(text="📄 Select file", size_hint_y=None, height=dp(48),
                               background_color=DARK["accent"], color=(0, 0, 0, 1))
        self.pick_btn.bind(on_release=self.open_chooser)
        root.add_widget(self.pick_btn)

        self.file_lbl = Label(text="No file selected", color=DARK["muted"],
                              size_hint_y=None, height=dp(28), shorten=True)
        root.add_widget(self.file_lbl)

        params = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        self.memory = Spinner(text="64 MB", values=("32 MB", "64 MB", "128 MB", "256 MB"))
        self.iters = Spinner(text="3", values=("1", "2", "3", "4"))
        self.paral = Spinner(text="4", values=("1", "2", "4", "8"))
        for w in (self.memory, self.iters, self.paral):
            params.add_widget(w)
        root.add_widget(params)

        self.algo = Spinner(text="AES-256-GCM",
                            values=("AES-256-GCM", "ChaCha20-Poly1305"),
                            size_hint_y=None, height=dp(44))
        root.add_widget(self.algo)

        self.pwd = TextInput(hint_text="Password", password=True, multiline=False,
                             size_hint_y=None, height=dp(44))
        root.add_widget(self.pwd)

        self.action_btn = Button(text="🔒 Encrypt File", size_hint_y=None, height=dp(52),
                                 background_color=DARK["accent"], color=(0, 0, 0, 1))
        self.action_btn.bind(on_release=self.run_action)
        root.add_widget(self.action_btn)

        root.add_widget(Label(text="Encryption Log", color=DARK["text"], bold=True,
                              size_hint_y=None, height=dp(24)))
        self.log_label = Label(text="", color=DARK["accent"], font_size=sp(12),
                               size_hint_y=None, halign="left", valign="top")
        self.log_label.bind(width=lambda w, _: setattr(w, "text_size", (w.width, None)),
                            texture_size=lambda w, ts: setattr(w, "height", ts[1]))
        scroll = ScrollView()
        scroll.add_widget(self.log_label)
        root.add_widget(scroll)

        self.request_android_permissions()
        self.log("Ready. Output folder: " + output_dir())
        return root

    # --- helpers ---
    def request_android_permissions(self):
        if platform == "android":
            from android.permissions import request_permissions, Permission
            request_permissions([Permission.READ_EXTERNAL_STORAGE,
                                 Permission.WRITE_EXTERNAL_STORAGE])

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_label.text = (self.log_label.text + f"[{ts}] {msg}\n")

    def popup(self, title, msg):
        Popup(title=title, content=Label(text=msg, color=DARK["text"]),
              size_hint=(0.9, 0.4)).open()

    def on_mode_change(self, _spinner, value):
        self.src = None
        self.file_lbl.text = "No file selected"
        self.action_btn.text = "🔒 Encrypt File" if value == "Encrypt" else "🔓 Decrypt File"

    # --- file chooser ---
    def open_chooser(self, *_):
        encrypt = self.mode.text == "Encrypt"
        chooser = FileChooserListView(path=storage_root(), filters=[] if encrypt else [
            lambda folder, name: name.lower().endswith(".enc") or os.path.isdir(os.path.join(folder, name))
        ])
        box = BoxLayout(orientation="vertical", spacing=dp(6))
        box.add_widget(chooser)
        btn = Button(text="Select", size_hint_y=None, height=dp(48))
        box.add_widget(btn)
        pop = Popup(title="Choose file", content=box, size_hint=(0.95, 0.9))

        def chosen(*_):
            if chooser.selection:
                path = chooser.selection[0]
                if os.path.isfile(path):
                    self.src = path
                    size_mb = os.path.getsize(path) / (1024 * 1024)
                    self.file_lbl.text = f"{os.path.basename(path)}  ({size_mb:.2f} MB)"
                    self.log(f"File selected: {os.path.basename(path)}")
                    pop.dismiss()

        btn.bind(on_release=chosen)
        pop.open()

    # --- actions ---
    def run_action(self, *_):
        if not self.src:
            return self.popup("AegisCrypt", "Please select a file first.")
        pwd = self.pwd.text
        if not pwd:
            return self.popup("AegisCrypt", "Please enter a password.")

        name = os.path.basename(self.src)
        if self.mode.text == "Encrypt":
            dst = unique_path(os.path.join(output_dir(), name + ".enc"))
            args = (self.src, dst, pwd,
                    self.algo.text,
                    int(self.memory.text.split()[0]) * 1024,
                    int(self.iters.text),
                    int(self.paral.text))
            target = self._run_encrypt
        else:
            base = name[:-4] if name.lower().endswith(".enc") else name + ".decrypted"
            dst = unique_path(os.path.join(output_dir(), base))
            args = (self.src, dst, pwd)
            target = self._run_decrypt

        self.action_btn.disabled = True
        threading.Thread(target=target, args=args, daemon=True).start()

    def _done(self):
        self.action_btn.disabled = False

    def _ui(self, fn, *a):
        Clock.schedule_once(lambda dt: fn(*a))

    def _run_encrypt(self, src, dst, pwd, algo, mem_kib, iters, parallel):
        part = dst + ".part"
        t0 = time.time()
        try:
            self._ui(self.log, f"Encrypting {os.path.basename(src)} ...")
            self._ui(self.log, f"Argon2id: {mem_kib // 1024} MB, {iters} iters ...")
            encrypt_file(src, part, pwd, algo, mem_kib, iters, parallel)
            os.replace(part, dst)
            self._ui(self.log, f"SUCCESS in {time.time() - t0:.2f}s -> {dst}")
            self._ui(self.popup, "AegisCrypt", f"File encrypted:\n{dst}")
        except Exception as e:
            if os.path.exists(part):
                os.remove(part)
            self._ui(self.log, f"ERROR: {e}")
            self._ui(self.popup, "AegisCrypt", f"Encryption error:\n{e}")
        finally:
            self._ui(lambda *_: self._done())

    def _run_decrypt(self, src, dst, pwd):
        part = dst + ".part"
        t0 = time.time()
        try:
            self._ui(self.log, f"Decrypting {os.path.basename(src)} ...")
            algo_name, *_ = decrypt_file(src, part, pwd)
            os.replace(part, dst)
            self._ui(self.log, f"Algorithm verified: {algo_name}")
            self._ui(self.log, f"SUCCESS in {time.time() - t0:.2f}s -> {dst}")
            self._ui(self.popup, "AegisCrypt", f"File decrypted:\n{dst}")
        except InvalidTag:
            if os.path.exists(part):
                os.remove(part)
            self._ui(self.log, "ERROR: Wrong password or file was tampered with.")
            self._ui(self.popup, "AegisCrypt", "Wrong password or file was tampered with.")
        except Exception as e:
            if os.path.exists(part):
                os.remove(part)
            self._ui(self.log, f"ERROR: {e}")
            self._ui(self.popup, "AegisCrypt", f"Decryption error:\n{e}")
        finally:
            self._ui(lambda *_: self._done())


if __name__ == "__main__":
    AegisApp().run()
