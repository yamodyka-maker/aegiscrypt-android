[app]
title = AegisCrypt
package.name = aegiscrypt
package.domain = org.aegis
source.dir = .
source.exts = py,png,jpg,kv,atlas,ttf
version = 1.2.0

requirements = python3,kivy==2.3.1,cryptography,plyer

orientation = portrait
fullscreen = 0
android.permissions = WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.api = 33
android.minapi = 21
android.archs = arm64-v8a
android.ndk = 25b
android.sdk = 33
android.accept_sdk_license = True
p4a.branch = master
# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2
