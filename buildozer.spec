[app]
title = AegisCrypt
package.name = aegiscrypt
package.domain = org.aegis
source.dir = .
source.include_exts = py
version = 1.3.0


requirements = python3,kivy==2.3.0,pyjnius,argon2-cffi,cffi,cryptography

orientation = portrait
fullscreen = 0

# Android 6.0 = API 23
android.minapi = 23
android.api = 33
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.permissions = READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE
android.accept_sdk_license = True
android.allow_backup = True
p4a.branch = v2024.01.21
[buildozer]
log_level = 2
warn_on_root = 1

