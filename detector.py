import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ransomware_db import identify_ransomware

# SETTINGS
MAX_EVENTS = 10          # max file changes
TIME_WINDOW = 5          # seconds
events = []

class RansomwareDetector(FileSystemEventHandler):

    def on_modified(self, event):
        if event.is_directory:
            return

        now = time.time()
        events.append(now)

        # Remove old events
        events[:] = [t for t in events if now - t <= TIME_WINDOW]

        # Detect known ransomware extensions
        info = identify_ransomware(event.src_path)
        if info:
            print("\n🚨 RANSOMWARE FILE DETECTED!")
            print(f"📄 File: {event.src_path}")
            print(f"🦠 Type: {info['name']}")
            print(f"🔓 Suggested Decryptor: {info['decryptor']}")
            print(f"🌐 Visit: {info['link']}")
            print("⚠️ Disconnect internet immediately!\n")

        # Detect abnormal file activity
        if len(events) >= MAX_EVENTS:
            print("\n🚨 POSSIBLE RANSOMWARE ACTIVITY DETECTED!")
            print("⚠️ Too many file changes in short time!")
            print("🛑 Recommended Actions:")
            print(" - Disconnect Internet")
            print(" - Stop suspicious processes")
            print(" - Backup remaining files\n")

            events.clear()  # reset counter

if __name__ == "__main__":
    path_to_watch = "test_folder"  # Folder to monitor

    print("🛡️ Ransomware Guardian Started")
    print(f"📂 Monitoring folder: {path_to_watch}")
    print("⏳ Waiting for suspicious activity...\n")

    event_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
