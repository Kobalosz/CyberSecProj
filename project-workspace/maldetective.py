import os
import hashlib
import re
import logging
import mimetypes
import struct
import time
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Set, Callable, Any
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from queue import Queue, Empty
import threading
import shutil
import tempfile

@dataclass
class SuspiciousPattern:
    pattern: str
    offset: int

@dataclass
class ScanResult:
    file_path: Path
    file_size: int
    file_type: str
    creation_time: datetime
    last_modified: datetime
    sha256: str
    suspicious_patterns: List[SuspiciousPattern]
    is_malicious: bool
    threat_name: Optional[str]

class FileTypeDetector:
    """Handles file type detection using various methods."""
    
    # Enhanced signatures with more precise matching
    SIGNATURES = [
        (b'\xFF\xD8\xFF\xE0', 'JPEG image'),
        (b'\xFF\xD8\xFF\xE1', 'JPEG image'),  # EXIF variant
        (b'\x89PNG\r\n\x1A\n', 'PNG image'),
        (b'GIF87a', 'GIF image'),
        (b'GIF89a', 'GIF image'),
        (b'%PDF-', 'PDF document'),
        (b'PK\x03\x04', 'ZIP archive'),
        (b'\x50\x4B\x03\x04', 'Office document'),
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'Microsoft Office document'),
        (b'MZ', 'Windows executable'),
        (b'\x7FELF', 'Linux executable'),
        (b'\xCA\xFE\xBA\xBE', 'Mac executable'),
        (b'#!/', 'Shell script'),
        (b'<?php', 'PHP script'),
        (b'<?xml', 'XML document'),
    ]
    
    @classmethod
    def detect_type(cls, file_path: Path) -> str:
        """
        Detect file type using multiple methods.
        Now includes better error handling and file access checks.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"No read permission for file: {file_path}")
            
        try:
            # First try to detect by file signature
            with file_path.open('rb') as f:
                header = f.read(16)  # Read first 16 bytes for signature matching
                
                # Check known signatures
                for signature, file_type in cls.SIGNATURES:
                    if header.startswith(signature):
                        return file_type
            
            # Try mimetypes based on extension
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type:
                return mime_type
            
            # Basic text file detection with proper encoding handling
            try:
                with file_path.open('r', encoding='utf-8') as f:
                    f.read(1024)
                return 'Text file (UTF-8)'
            except UnicodeDecodeError:
                # Try alternative encodings
                for encoding in ['latin-1', 'cp1252', 'ascii']:
                    try:
                        with file_path.open('r', encoding=encoding) as f:
                            f.read(1024)
                        return f'Text file ({encoding})'
                    except UnicodeDecodeError:
                        continue
            
            # If all else fails, examine the content
            return cls._analyze_content(file_path)
            
        except Exception as e:
            logging.error(f"Error detecting file type for {file_path}: {e}")
            return "Unknown"
    
    @classmethod
    def _analyze_content(cls, file_path: Path) -> str:
        """Analyze file content for type detection with improved binary detection."""
        try:
            with file_path.open('rb') as f:
                content = f.read(4096)  # Read first 4KB for better analysis
                
                # Improved binary content detection
                if not content:
                    return "Empty file"
                    
                # Calculate the ratio of printable to non-printable characters
                printable = sum(32 <= byte <= 126 or byte in {7,8,9,10,12,13,27}
                              for byte in content)
                ratio = printable / len(content)
                
                if ratio < 0.30:  # If less than 30% printable characters
                    if cls._is_pe_file(content):
                        return "Windows executable"
                    elif cls._is_elf_file(content):
                        return "Linux executable"
                    return "Binary data"
                else:
                    return "Text file"
                    
        except Exception as e:
            logging.error(f"Error analyzing content of {file_path}: {e}")
            return "Unknown"

class SafeFileHandler:
    """Handles file operations with safety checks and atomic operations."""
    
    @staticmethod
    def safe_move(src: Path, dest: Path) -> bool:
        """
        Safely move a file with atomic operations and rollback capability.
        """
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src}")
            
        # Create parent directories if they don't exist
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Create a temporary file in the destination directory
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=str(dest.parent), delete=False) as tmp:
                temp_path = Path(tmp.name)
                # Copy to temporary location first
                shutil.copy2(src, temp_path)
                
            # Atomic rename to final destination
            temp_path.rename(dest)
            
            # Only remove source after successful move
            src.unlink()
            return True
            
        except Exception as e:
            logging.error(f"Error moving file {src} to {dest}: {e}")
            # Cleanup temporary file if it exists
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            return False

class FileMonitorHandler(FileSystemEventHandler):
    """Handles file system events for real-time monitoring."""
    
    def __init__(self, detector: 'MalwareDetector', event_queue: Queue):
        super().__init__()
        self.detector = detector
        self.event_queue = event_queue
        self.processing_paths: Set[str] = set()
        self._lock = threading.Lock()
        self._skip_patterns = re.compile(r'(\.tmp$|\.temp$|~$|\.swp$)')

    def dispatch(self, event: FileSystemEvent) -> None:
        """Override dispatch to add better error handling."""
        try:
            super().dispatch(event)
        except Exception as e:
            self.detector.logger.error(f"Error dispatching event {event}: {e}")

    def on_created(self, event):
        if not event.is_directory and self._should_process(event.src_path):
            self._queue_scan(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory and self._should_process(event.src_path):
            self._queue_scan(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory and self._should_process(event.dest_path):
            self._queue_scan(event.dest_path, "moved")

    def _should_process(self, file_path: str) -> bool:
        """Determine if a file should be processed based on patterns and state."""
        return (
            not self._skip_patterns.search(file_path) and
            os.path.exists(file_path) and
            os.access(file_path, os.R_OK)
        )

    def _queue_scan(self, file_path: str, event_type: str):
        """Queue a file for scanning with proper locking and error handling."""
        with self._lock:
            try:
                if file_path not in self.processing_paths:
                    self.processing_paths.add(file_path)
                    self.event_queue.put((file_path, event_type))
            except Exception as e:
                self.detector.logger.error(f"Error queuing {file_path}: {e}")
                self.processing_paths.discard(file_path)

class RealTimeProtection:
    """Manages real-time file system monitoring and scanning."""
    
    def __init__(self, detector: 'MalwareDetector', callback: Optional[Callable[[ScanResult], None]] = None):
        self.detector = detector
        self.callback = callback or self._default_callback
        self.event_queue: Queue = Queue()
        self.observer = Observer()
        self.handler = FileMonitorHandler(detector, self.event_queue)
        self.running = threading.Event()
        self.scan_thread: Optional[threading.Thread] = None

    def start(self, paths: List[str]) -> bool:
        """Start real-time protection for specified paths."""
        if self.running.is_set():
            return False

        # Validate paths before starting
        valid_paths = []
        for path in paths:
            try:
                path_obj = Path(path)
                if not path_obj.exists():
                    self.detector.logger.error(f"Path does not exist: {path}")
                    continue
                if not os.access(path, os.R_OK):
                    self.detector.logger.error(f"No read permission for path: {path}")
                    continue
                valid_paths.append(path)
            except Exception as e:
                self.detector.logger.error(f"Invalid path {path}: {e}")

        if not valid_paths:
            self.detector.logger.error("No valid paths to monitor")
            return False

        try:
            # Start the observer
            for path in valid_paths:
                self.observer.schedule(self.handler, path, recursive=True)
                self.detector.logger.info(f"Started monitoring: {path}")

            self.observer.start()
            self.running.set()
            
            # Start the scanning thread
            self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
            self.scan_thread.start()
            
            return True
            
        except Exception as e:
            self.detector.logger.error(f"Failed to start monitoring: {e}")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop real-time protection with proper cleanup."""
        if not self.running.is_set():
            return

        self.running.clear()
        
        # Stop the observer
        try:
            self.observer.stop()
            self.observer.join(timeout=5)  # Wait up to 5 seconds
        except Exception as e:
            self.detector.logger.error(f"Error stopping observer: {e}")

        # Stop the scan worker
        try:
            self.event_queue.put((None, None))  # Sentinel to stop the worker
            if self.scan_thread:
                self.scan_thread.join(timeout=5)
        except Exception as e:
            self.detector.logger.error(f"Error stopping scan worker: {e}")

        # Clear the queue
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except Empty:
                break

    def _scan_worker(self) -> None:
        """Worker thread to process file events with improved error handling."""
        while self.running.is_set():
            try:
                try:
                    file_path, event_type = self.event_queue.get(timeout=1)
                except Empty:
                    continue

                if file_path is None:  # Sentinel value
                    break
                    
                # Add a small delay to allow file operations to complete
                time.sleep(0.1)
                
                try:
                    if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                        result = self.detector.analyze_file(file_path)
                        if result:
                            self._safe_callback(result)
                except Exception as e:
                    self.detector.logger.error(f"Error scanning {file_path}: {e}")
                finally:
                    with self.handler._lock:
                        self.handler.processing_paths.discard(file_path)
                        
            except Exception as e:
                self.detector.logger.error(f"Error in scan worker: {e}")

    def _safe_callback(self, result: ScanResult) -> None:
        """Safely execute callback with error handling."""
        try:
            self.callback(result)
        except Exception as e:
            self.detector.logger.error(f"Error in callback for {result.file_path}: {e}")

    def _handle_threat(self, result: ScanResult) -> bool:
        """Handle detected threats with improved safety."""
        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            
            # Generate unique quarantine path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = quarantine_dir / f"{result.file_path.name}_{timestamp}_{result.sha256[:8]}"
            
            # Safely move file to quarantine
            if SafeFileHandler.safe_move(Path(result.file_path), quarantine_path):
                self.detector.logger.info(
                    f"Successfully quarantined malicious file:\n"
                    f"Original: {result.file_path}\n"
                    f"Quarantine: {quarantine_path}"
                )
                return True
            return False
            
        except Exception as e:
            self.detector.logger.error(f"Failed to quarantine {result.file_path}: {e}")
            return False

def main():
    detector = MalwareDetector()
    
    # Example usage with real-time protection and error handling
    paths_to_monitor = ["/path/to/watch1", "/path/to/watch2"]
    
    def custom_callback(result: ScanResult):
        try:
            print(format_scan_result(result))
            if result.is_malicious:
                print("🚨 Taking protective action!")
        except Exception as e:
            print(f"Error in callback: {e}")
    
    # Start real-time protection with proper error handling
    protection = detector.start_monitoring(paths_to_monitor, custom_callback)
    if not protection:
        print("Failed to start protection")
        return
    
    try:
        print("Real-time protection active. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping real-time protection...")
        protection.stop()
        print("Stopped real-time protection.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        protection.stop()

if __name__ == "__main__":
    main()