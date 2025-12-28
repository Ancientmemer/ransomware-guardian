import time
import math
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ransomware_db import identify_ransomware

# =======================
# SETTINGS
# =======================
WATCH_FOLDER = "test_folder"
MAX_EVENTS = 8          # burst detection
TIME_WINDOW = 6         # seconds
ENTROPY_THRESHOLD = 7.5

# Canary (fake bait files)
CANARY_FILES = [
    "salary_2024.xlsx",
    "passwords.txt",
    "photos_backup.zip"
]

events = []

# =======================
# HELPER FUNCTIONS
# =======================
def is_canary(path):
    for c in CANARY_FILES:
        if path.endswith(c):
            return True
    return False

def calculate_entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0
    for f in freq.values():
        p = f / len(data)
        entropy -= p * math.log2(p)
    return entropy

# =======================
# DETECTOR CLASS
# =======================
class GuardianV2(FileSystemEventHandler):

    def on_modified(self, event):
        if event.is_directory:
            return

        now = time.time()
        events.append(now)

        # Remove old timestamps
        events[:] = [t for t in events if now - t <= TIME_WINDOW]

        print(f"📄 Modified: {event.src_path}")

        # 🐦 CANARY FILE CHECK (HIGH CONFIDENCE)
        if is_canary(event.src_path):
            print("\n🐦 CANARY FILE TOUCHED!")
            print("🚨 HIGH CONFIDENCE RANSOMWARE DETECTED")
            print("🛑 Disconnect Internet IMMEDIATELY\n")
            return

        # 🔓 Known ransomware extension check
        info = identify_ransomware(event.src_path)
        if info:
            print("\n🚨 KNOWN RANSOMWARE FILE DETECTED!")
            print(f"🦠 Type: {info['name']}")
            print(f"🔓 Suggested Decryptor: {info['decryptor']}")
            print(f"🌐 Visit: {info['link']}")
            print("⚠️ Disconnect internet!\n")

        # 🔬 ENTROPY CHECK (Encryption detection)
        try:
            with open(event.src_path, "rb") as f:
                chunk = f.read(2048)
                entropy = calculate_entropy(chunk)

            if entropy >= ENTROPY_THRESHOLD:
                print("\n⚠️ HIGH ENTROPY FILE DETECTED!")
                print(f"📊 Entropy: {round(entropy, 2)}")
                print("🦠 Possible encryption activity\n")
        except:
            pass  # ignore unreadable files

        # 🚨 BURST FILE ACTIVITY CHECK
        if len(events) >= MAX_EVENTS:
            print("\n🚨 ABNORMAL FILE ACTIVITY!")
            print("🧠 Possible SARA-like ransomware behavior")
            print("🛑 Recommended actions:")
            print(" - Disconnect Internet")
            print(" - Stop unknown processes")
            print(" - Backup remaining files\n")
            events.clear()

# =======================
# MAIN
# =======================
if __name__ == "__main__":

    # Create canary files if not exists
    os.makedirs(WATCH_FOLDER, exist_ok=True)
    for c in CANARY_FILES:
        path = os.path.join(WATCH_FOLDER, c)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("DO NOT TOUCH")

    print("🛡️ Guardian v2 Started")
    print(f"📂 Monitoring folder: {WATCH_FOLDER}")
    print("🐦 Canary files armed")
    print("⏳ Waiting for threats...\n")

    observer = Observer()
    observer.schedule(GuardianV2(), path=WATCH_FOLDER, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
