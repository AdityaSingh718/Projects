#!/usr/bin/env python3
"""
HTTPS Webcam Streaming Server
Streams webcam feed to QIDK app over network
"""

from flask import Flask, Response, render_template_string, jsonify, request
import cv2
import time
import logging
import numpy as np
from threading import Lock
import os
from typing import List, Optional

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Camera settings
camera = None
frame_count = 0
start_time = time.time()

# For receiving uploaded frames
latest_frame = None
frame_lock = Lock()
upload_mode = False  # Set to True to accept uploaded frames instead of local camera

DEFAULT_CAMERA_SCAN_ORDER = [1, 0, 2, 3, 4]


def _build_camera_scan_order(preferred_index: Optional[int]) -> List[int]:
    """Build ordered list of camera indices to attempt."""
    discovered: List[int] = []

    def append_unique(idx: Optional[int]) -> None:
        if idx is None:
            return
        if idx < 0:
            logging.warning("Ignoring negative camera index %s", idx)
            return
        if idx not in discovered:
            discovered.append(idx)

    append_unique(preferred_index)

    env_index = os.environ.get("EXTERNAL_CAMERA_INDEX")
    if env_index is not None:
        try:
            append_unique(int(env_index))
        except ValueError:
            logging.warning("EXTERNAL_CAMERA_INDEX must be an integer, got '%s'", env_index)

    for idx in DEFAULT_CAMERA_SCAN_ORDER:
        append_unique(idx)

    return discovered

def init_camera(preferred_index: Optional[int] = None):
    global camera
    if upload_mode:
        logging.info("Running in UPLOAD MODE - waiting for frames from QIDK")
        return True
    
    scan_order = _build_camera_scan_order(preferred_index)
    logging.info("Attempting to initialize camera in this order: %s", scan_order or '[none]')

    if not scan_order:
        logging.error("No camera indices to try. Set EXTERNAL_CAMERA_INDEX or pass --camera-index.")
        return False

    for idx in scan_order:
        try:
            logging.info(f"Trying camera index {idx}...")
            # Use DirectShow backend on Windows for better compatibility
            if os.name == 'nt':
                cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
            else:
                cap = cv2.VideoCapture(idx)
            
            # Check if camera opened successfully
            if cap.isOpened():
                # Test read a frame to ensure camera is working
                ret, test_frame = cap.read()
                if not ret:
                    logging.warning(f"Camera {idx} opened but can't read frames")
                    cap.release()
                    continue
                
                # Configure camera settings
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                cap.set(cv2.CAP_PROP_FPS, 30)
                
                # Get actual settings
                width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
                height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
                fps = cap.get(cv2.CAP_PROP_FPS)
                
                camera = cap
                logging.info(f"✓ Camera {idx} initialized successfully!")
                logging.info(f"  Resolution: {width}x{height}")
                logging.info(f"  FPS: {fps}")
                return True
            else:
                logging.debug(f"Camera {idx} could not be opened")
                cap.release()
        except Exception as e:
            logging.error(f"Error initializing camera {idx}: {e}")
    
    logging.error("❌ Failed to open any camera")
    logging.warning("Running in UPLOAD mode as fallback - use --upload flag or send frames to /upload endpoint")
    return False

def generate_frames():
    """Generate video frames from camera or uploaded frames"""
    global frame_count, latest_frame, upload_mode
    
    # If no camera and not in upload mode, switch to upload mode automatically
    if camera is None and not upload_mode:
        logging.info("No camera available, switching to UPLOAD mode")
        upload_mode = True
    
    if upload_mode or camera is None:
        # Serve uploaded frames
        while True:
            with frame_lock:
                if latest_frame is not None:
                    frame = latest_frame.copy()
                else:
                    # Show placeholder if no frame uploaded yet
                    frame = np.zeros((720, 1280, 3), dtype=np.uint8)
                    cv2.putText(frame, "Waiting for frames from QIDK...", 
                               (300, 360), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                    cv2.putText(frame, "Send frames to /upload endpoint", 
                               (250, 410), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (200, 200, 200), 2)
            
            ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
            if ret:
                frame_count += 1
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            time.sleep(0.033)  # ~30 FPS
    else:
        # Serve from local camera
        while True:
            try:
                success, frame = camera.read()
                if not success:
                    logging.warning("Failed to read frame")
                    time.sleep(0.1)
                    continue
                
                ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                if not ret:
                    continue
                frame_bytes = buffer.tobytes()
                frame_count += 1
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n'
                       + f"Content-Length: {len(frame_bytes)}\r\n\r\n".encode()
                       + frame_bytes + b'\r\n')
            except Exception as e:
                logging.error(f"Error generating frame: {e}")
                time.sleep(0.1)

@app.route('/')
def index():
    """Home page with stream preview"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Webcam Stream</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                text-align: center;
                background: #1a1a1a;
                color: white;
                padding: 20px;
            }
            h1 { color: #4CAF50; }
            img {
                max-width: 90%;
                border: 3px solid #4CAF50;
                border-radius: 10px;
                margin: 20px;
            }
            .info {
                background: #2d2d2d;
                padding: 20px;
                border-radius: 10px;
                margin: 20px auto;
                max-width: 600px;
            }
            .endpoint {
                background: #444;
                padding: 10px;
                border-radius: 5px;
                font-family: monospace;
                margin: 10px 0;
            }
        </style>
    </head>
    <body>
        <h1>📷 Webcam Streaming Server</h1>
        <img src="/video_feed" alt="Webcam Stream">
        <div class="info">
            <h3>Stream Endpoints</h3>
            <p><strong>MJPEG Stream:</strong></p>
            <div class="endpoint">/video_feed</div>
            <p><strong>For QIDK App:</strong></p>
            <div class="endpoint">http://YOUR_IP:5000/video_feed</div>
            <p>Frames served: <span id="counter">0</span></p>
        </div>
        <script>
            // Update frame counter
            setInterval(() => {
                fetch('/stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('counter').textContent = data.frames;
                    });
            }, 1000);
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/video_feed')
def video_feed():
    """Video streaming route"""
    try:
        return Response(generate_frames(),
                        mimetype='multipart/x-mixed-replace; boundary=frame')
    except Exception as e:
        logging.error(f"Error in video_feed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def stats():
    """Return streaming statistics"""
    uptime = time.time() - start_time
    fps = frame_count / uptime if uptime > 0 else 0
    return jsonify({
        'frames': frame_count, 
        'status': 'active',
        'uptime_seconds': round(uptime, 2),
        'avg_fps': round(fps, 2),
        'mode': 'upload' if upload_mode else 'camera'
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    mode = "upload" if upload_mode else "camera"
    return jsonify({
        'status': 'ok', 
        'mode': mode, 
        'camera_available': camera is not None,
        'frames_served': frame_count
    })

@app.route('/upload', methods=['POST'])
def upload_frame():
    """Endpoint to receive frames from QIDK uploader"""
    global latest_frame
    
    if 'frame' not in request.files:
        return {'error': 'No frame provided'}, 400
    
    file = request.files['frame']
    
    # Read image from upload
    img_bytes = file.read()
    nparr = np.frombuffer(img_bytes, np.uint8)
    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if frame is None:
        return {'error': 'Invalid image'}, 400
    
    # Store latest frame
    with frame_lock:
        latest_frame = frame
    
    return {'status': 'ok'}, 200

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="MJPEG streaming server for QIDK pose pipeline")
    parser.add_argument('-u', '--upload', action='store_true', help='Run in upload mode (accept frames via /upload).')
    parser.add_argument('--camera-index', type=int, help='Preferred camera index to open first (external USB).')
    args = parser.parse_args()

    upload_mode = args.upload

    if upload_mode:
        logging.info("=" * 60)
        logging.info("UPLOAD MODE ENABLED")
        logging.info("Server will receive frames from QIDK uploader")
        logging.info("=" * 60)
    
    preferred_index = args.camera_index
    
    # Try to initialize camera (will fail gracefully if no camera)
    if not upload_mode:
        camera_success = init_camera(preferred_index)
        if not camera_success:
            logging.warning("No camera available - server will run in UPLOAD mode")
            upload_mode = True
    
    logging.info("\n" + "=" * 60)
    logging.info("🚀 Webcam Streaming Server Starting")
    logging.info("=" * 60)
    logging.info(f"Mode: {'📤 UPLOAD (receiving from QIDK)' if upload_mode else '📹 CAMERA (local webcam)'}")
    logging.info(f"Server URL: http://0.0.0.0:5000")
    logging.info(f"Stream URL: http://0.0.0.0:5000/video_feed")
    if upload_mode:
        logging.info(f"Upload URL: http://0.0.0.0:5000/upload")
    logging.info("=" * 60 + "\n")
    
    try:
        # Run on all interfaces, port 5000
        app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
    except KeyboardInterrupt:
        logging.info("\n🛑 Server stopped by user")
    except Exception as e:
        logging.error(f"❌ Server error: {e}")
    finally:
        if camera is not None:
            camera.release()
            logging.info("📷 Camera released")
        logging.info("👋 Server shutdown complete")
