import os
import sys
import time
import subprocess
import threading
from pathlib import Path

# from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
from concurrent.futures import ThreadPoolExecutor

FFMPEG_BIN = (
    "./ffmpeg"  # Path to ffmpeg binary, ensure it's in your PATH or provide full path
)


class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events and manages subprocess execution."""

    def __init__(self, max_workers=1):
        """
        Initialize the file change handler.

        Args:
            script_path (str): Path to the Python script to run for each file change
            max_workers (int): Maximum number of concurrent subprocesses (default: 4)
        """
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.running_processes = {}  # Track running processes by file path
        self.lock = threading.Lock()

    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self.process_file(event.src_path, "modified")

    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self.process_file(event.src_path, "created")

    def on_moved(self, event):
        """Handle file move/rename events."""
        if not event.is_directory:
            # Cancel any existing process for the old path
            self.cancel_process(event.src_path)
            # Start new process for the new path
            self.process_file(event.dest_path, "moved")

    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            # Cancel any running process for the deleted file
            self.cancel_process(event.src_path)

    def process_file(self, file_path, event_type):
        """
        Process a file by running the specified script as a subprocess.

        Args:
            file_path (str): Path to the file that changed
            event_type (str): Type of event (created, modified, moved)
        """

        # Skip temporary files and hidden files
        skip_patterns = [
            ".",  # Hidden files
            "~",  # Temporary files
            ".tmp",  # Temporary files
            ".log",  # Log files
            ".lock",  # Lock files
            "__pycache__",  # Python cache
            ".DS_Store",  # macOS system files
            "tmp_",
        ]
        if any(
            file_path.startswith(pattern) or file_path.endswith(pattern)
            for pattern in skip_patterns
        ):
            return

        with self.lock:
            # Cancel any existing process for this file
            if file_path in self.running_processes:
                print(f"Skip because already running for {file_path}")
                return

            # Submit new task to executor
            future = self.executor.submit(self.run_script, file_path, event_type)
            self.running_processes[file_path] = future

    def run_script(self, file_path, event_type):
        """
        Run the specified Python script with the file path as an argument.

        Args:
            file_path (str): Path to the file that changed
            event_type (str): Type of event that triggered this
        """
        print(f"Processing {event_type} file: {file_path}")
        process = None

        try:
            pass
        except Exception as e:
            print(f"Skipping processing {file_path} because it failed the zip check")
            self.cleanup_process(file_path)
            return

        try:
            # Run the script with the file path as an argument
            # cmd = [sys.executable, self.script_path, file_path]

            # if job.suffix in [".mov", ".mp4", ".avi", ".mkv", ".flv", ".wmv", ".webm"]:
            # Convert video files to mp4 x264 fps=10 format if they are not already

            # out_fname = job.with_stem(f"{job.stem}_converted").with_suffix(
            #    ".mp4"
            # )  # Change extension to .mp4

            if not any(file_path.lower().endswith(ext) for ext in [".mov", ".avi", ".mkv", ".flv", ".wmv", ".webm", ".mp4"]):
                print(f"Skipping conversion for {file_path}, not a supported video format.")
                self.cleanup_process(file_path)
                return

            out_name = file_path + "_converted.mp4"
            out_name_path = Path(out_name)

            if "_converted" in file_path:
                print(f"Skipping conversion for {file_path}, already converted.")
                self.cleanup_process(file_path)
                return

            if out_name_path.exists():
                print(f"Converted file already exists, skipping: {out_name}")
                self.cleanup_process(file_path)
                return
            

            job_exec = [
                FFMPEG_BIN,
                "-y",  # Overwrite output file without asking
                "-noautorotate",  # Disable auto-rotation
                "-i",
                f'{str(file_path)}',  # Input file
                "-c:v",
                "libx264",  # Video codec
                "-pix_fmt",
                "yuv420p",  # Pixel format
                #"-vf",
                #"\"scale='if(gt(iw,ih),-2,480)':'if(gt(iw,ih),480,-2)'\"",
                # "-vf", "\"crop=trunc(iw/2)*2:trunc(ih/2)*2\"",
                "-preset",
                "fast",  # Encoding preset
                "-crf",
                "23",  # Constant Rate Factor for quality
                "-an",  # Disable audio
                "-r",
                "30",  # "10",  # Set frame rate to 10 fps
                f'{out_name}',  # Output file
            ]

            # Start the subprocess
            process = subprocess.Popen(
                #cmd,
                job_exec,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,  # subprocess.PIPE,
                text=True,
            )

            # Wait for completion and capture output
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                print(f"✓ Successfully processed {file_path}")
            else:
                print(
                    f"✗ Error processing {file_path} (exit code: {process.returncode})"
                )

            if stdout.strip():
                print(f"STDOUT:\n", stdout.strip())
            if stderr.strip():
                print(f"STDERR:\n", stderr.strip())

        except subprocess.TimeoutExpired:
            print(f"⚠ Timeout processing {file_path}")
            if process:
                process.kill()
        except Exception as e:
            if process:
                process.kill()
            print(f"✗ Exception processing {file_path}: {e}")

        self.cleanup_process(file_path)

    def cancel_process(self, file_path):
        """
        Cancel a running process for a specific file.
        """
        with self.lock:
            if file_path in self.running_processes:
                future = self.running_processes[file_path]
                future.cancel()
                del self.running_processes[file_path]

    def cleanup_process(self, file_path):
        """
        Clean up completed process from tracking dictionary.
        """
        # print("cleaning... ")
        with self.lock:
            if file_path in self.running_processes:
                del self.running_processes[file_path]

    def shutdown(self):
        """Shutdown the thread pool executor and cancel pending tasks."""
        print("Shutting down watchdog...")
        self.executor.shutdown(wait=True)


def main():
    """Main function to set up and run the folder watchdog."""
    if len(sys.argv) < 2:
        print("Usage: python folder_watchdog.py <folder_to_watch>")
        print("Example: python folder_watchdog.py /path/to/watch")
        sys.exit(1)

    watch_folder = sys.argv[1]

    # Validate inputs
    if not os.path.exists(watch_folder):
        print(f"Error: Watch folder does not exist: {watch_folder}")
        sys.exit(1)

    if not os.path.isdir(watch_folder):
        print(f"Error: Watch path is not a directory: {watch_folder}")
        sys.exit(1)

    # Convert to absolute paths
    watch_folder = os.path.abspath(watch_folder)

    print(f"Watching folder: {watch_folder}")
    print("Maximum concurrent processes: 4")
    print("Press Ctrl+C to stop...")

    # Set up file system event handler
    event_handler = FileChangeHandler(max_workers=1)

    # Set up observer
    observer = PollingObserver(timeout=1)
    observer.schedule(event_handler, watch_folder, recursive=True)

    try:
        # Start monitoring
        observer.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nReceived interrupt signal...")

    finally:
        # Clean shutdown
        observer.stop()
        event_handler.shutdown()
        observer.join()
        print("Watchdog stopped.")


if __name__ == "__main__":
    main()
