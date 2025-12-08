#!/usr/bin/env python3
"""
QIDK Camera Uploader
Captures from USB webcam on QIDK and streams to Flask server
"""

import cv2
import requests
import time
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CameraUploader:
    def __init__(self, camera_index=0, server_url="http://localhost:5000/upload", 
                 resolution=(1280, 720), fps=30, quality=85):
        self.camera_index = camera_index
        self.server_url = server_url
        self.resolution = resolution
        self.fps = fps
        self.quality = quality
        self.camera = None
        
    def initialize_camera(self):
        """Initialize camera with specified settings"""
        logger.info(f"Initializing camera {self.camera_index}...")
        
        # Try multiple camera indices if first fails
        for idx in [self.camera_index, 0, 1, 2]:
            self.camera = cv2.VideoCapture(idx)
            if self.camera.isOpened():
                logger.info(f"✓ Camera {idx} opened successfully")
                self.camera_index = idx
                break
        
        if not self.camera or not self.camera.isOpened():
            logger.error("✗ Failed to open any camera")
            return False
            
        # Set camera properties
        self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.resolution[0])
        self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.resolution[1])
        self.camera.set(cv2.CAP_PROP_FPS, self.fps)
        
        # Verify settings
        actual_width = int(self.camera.get(cv2.CAP_PROP_FRAME_WIDTH))
        actual_height = int(self.camera.get(cv2.CAP_PROP_FRAME_HEIGHT))
        actual_fps = int(self.camera.get(cv2.CAP_PROP_FPS))
        
        logger.info(f"Camera settings: {actual_width}x{actual_height} @ {actual_fps}fps")
        return True
        
    def upload_stream(self):
        """Continuously capture and upload frames"""
        if not self.initialize_camera():
            return
            
        frame_count = 0
        start_time = time.time()
        upload_errors = 0
        
        logger.info(f"Starting upload to {self.server_url}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                ret, frame = self.camera.read()
                if not ret:
                    logger.warning("Failed to read frame")
                    time.sleep(0.1)
                    continue
                
                # Encode frame as JPEG
                encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), self.quality]
                _, buffer = cv2.imencode('.jpg', frame, encode_param)
                
                # Upload to server
                try:
                    response = requests.post(
                        self.server_url,
                        files={'frame': ('frame.jpg', buffer.tobytes(), 'image/jpeg')},
                        timeout=1.0
                    )
                    
                    if response.status_code == 200:
                        upload_errors = 0  # Reset error counter on success
                    else:
                        upload_errors += 1
                        if upload_errors % 10 == 1:  # Log every 10th error
                            logger.warning(f"Upload failed: {response.status_code}")
                            
                except requests.exceptions.RequestException as e:
                    upload_errors += 1
                    if upload_errors % 10 == 1:
                        logger.warning(f"Upload error: {e}")
                
                # Too many consecutive errors - try to reconnect
                if upload_errors > 50:
                    logger.error("Too many upload errors, reinitializing camera...")
                    self.camera.release()
                    time.sleep(2)
                    if not self.initialize_camera():
                        break
                    upload_errors = 0
                
                frame_count += 1
                
                # Log stats every 100 frames
                if frame_count % 100 == 0:
                    elapsed = time.time() - start_time
                    actual_fps = frame_count / elapsed
                    logger.info(f"Uploaded {frame_count} frames ({actual_fps:.1f} fps)")
                
                # Frame rate limiting
                time.sleep(1.0 / self.fps)
                
        except KeyboardInterrupt:
            logger.info("\nStopping upload...")
        finally:
            if self.camera:
                self.camera.release()
            logger.info(f"Total frames uploaded: {frame_count}")

def main():
    # Configuration
    CAMERA_INDEX = 0
    SERVER_URL = "http://localhost:5000/upload"  # Change to your server IP
    RESOLUTION = (1280, 720)
    FPS = 30
    QUALITY = 85
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        SERVER_URL = sys.argv[1]
    
    logger.info("=" * 60)
    logger.info("QIDK Camera Uploader")
    logger.info("=" * 60)
    logger.info(f"Server URL: {SERVER_URL}")
    logger.info(f"Resolution: {RESOLUTION[0]}x{RESOLUTION[1]}")
    logger.info(f"Target FPS: {FPS}")
    logger.info("=" * 60)
    
    uploader = CameraUploader(
        camera_index=CAMERA_INDEX,
        server_url=SERVER_URL,
        resolution=RESOLUTION,
        fps=FPS,
        quality=QUALITY
    )
    
    uploader.upload_stream()

if __name__ == "__main__":
    main()
