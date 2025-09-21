from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess, time, os, sys


class ReloadHandler(FileSystemEventHandler):
    def __init__(self, script):
        self.script = script
        self.process = None
        self.run_script()

    def run_script(self):
        if self.process:
            self.process.kill()
        print(f"▶ Running {self.script}...")
        self.process = subprocess.Popen([sys.executable, self.script])

    def on_modified(self, event):
        if event.src_path.endswith(self.script):
            print("🔄 Restarting script...")
            self.run_script()


if __name__ == "__main__":
    # 👇 point this to your UI file
    script_name = "src/gui.py"

    event_handler = ReloadHandler(script_name)
    observer = Observer()
    observer.schedule(event_handler, ".", recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
