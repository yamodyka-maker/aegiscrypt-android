[app]
title = AegisCrypt
package.name = aegiscrypt
package.domain = org.aegis
source.dir = .
source.exts = py,png,jpg,kv,atlas,ttf
version = 1.2.0

requirements = python3,kivy,plyer,cryptography,argon2-cffi,arabic-reshaper,python-bidi

orientation = portrait
fullscreen = 0
android.permissions = WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.api = 33
android.minapi = 21
android.ndk = 25b
android.sdk = 33
android.accept_sdk_license = True
p4a.branch = master
