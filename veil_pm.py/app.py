import platform, os, shutil

print(f"OS: {platform.system()} {platform.release()}")
print(f"CPU: {platform.processor()}")
print(f"Void: {platform.machine()}")
print(f"Disco: {shutil.disk_usage('/').used / 1024**3:.1f} GB")
print(f"Uname: {os.uname()}")
