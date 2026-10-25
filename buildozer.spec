[app]
title = AegisCrypt
package.name = aegiscrypt
package.domain = com.aegislabs.us
source.dir = .
source.exts = py,png,jpg,kv,atlas,ttf
version = 1.2.0
#requirements = python3,kivy==2.3.1,cryptography>=43.0.0,plyer,charset_normalizer<3.4
#requirements = python3,kivy==2.3.1,pycryptodome,plyer,charset_normalizer<3.4
#requirements = python3,kivy==2.3.1,pycryptodome,plyer,arabic_reshaper,python-bidi,charset_normalizer<3.4
#requirements = python3,kivy==2.3.1,pycryptodome,argon2-cffi,plyer,arabic_reshaper,python-bidi,charset_normalizer<3.4
#requirements = python3,kivy==2.3.1,pycryptodome,plyer,arabic_reshaper,python-bidi,charset_normalizer<3.4
#requirements = python3,kivy==2.3.1,pycryptodome,plyer,arabic-reshaper,python-bidi,charset_normalizer<3.4
requirements = python3,kivy,cryptography,arabic-reshaper,python-bidi

orientation = portrait
fullscreen = 0
android.permissions = WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.ndk = 25b
android.sdk = 33
android.accept_sdk_license = True
p4a.branch = master
# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2
