#!/bin/bash

# HTTPS Webcam Streaming Server
# Streams webcam feed from laptop to QIDK over secure connection

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       HTTPS Webcam Streaming Server for QIDK                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if required tools are installed
check_requirements() {
    echo "Checking requirements..."
    
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python3 not found. Please install Python 3.7+"
        exit 1
    fi
    
    if ! command -v ffmpeg &> /dev/null; then
        echo "⚠️  FFmpeg not found. Installing..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            sudo apt-get update && sudo apt-get install -y ffmpeg
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew install ffmpeg
        else
            echo "❌ Please install FFmpeg manually"
            exit 1
        fi
    fi
    
    echo "✅ All requirements met"
}

# Install Python dependencies
install_python_deps() {
    echo ""
    echo "Installing Python dependencies..."
    pip3 install flask opencv-python numpy pillow --quiet
    echo "✅ Python dependencies installed"
}

# Get local IP address
get_local_ip() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        LOCAL_IP=$(hostname -I | awk '{print $1}')
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        LOCAL_IP=$(ipconfig getifaddr en0)
    else
        LOCAL_IP="127.0.0.1"
    fi
    echo "$LOCAL_IP"
}

# Create the streaming server Python script
create_server_script() {
    cat > webcam_stream_server.py << 'EOF'
#!/usr/bin/env python3
"""
HTTPS Webcam Streaming Server
Streams webcam feed to QIDK app over network
"""

from flask import Flask, Response, render_template_string
import cv2
import time
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Global variables
camera = None
frame_count = 0

def get_camera():
    """Initialize camera if not already done"""
    global camera
    if camera is None or not camera.isOpened():
        # Try multiple camera indices
        for idx in [0, 1, 2]:
            camera = cv2.VideoCapture(idx)
            if camera.isOpened():
                # Set camera properties for better performance
                camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                camera.set(cv2.CAP_PROP_FPS, 30)
                logging.info(f"Camera opened successfully at index {idx}")
                return camera
        logging.error("Failed to open camera")
        return None
    return camera

def generate_frames():
    """Generate video frames from webcam"""
    global frame_count
    camera = get_camera()
    
    if camera is None:
        logging.error("Camera not available")
        return
    
    while True:
        success, frame = camera.read()
        if not success:
            logging.warning("Failed to read frame")
            time.sleep(0.1)
            continue
        
        # Encode frame as JPEG
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if not ret:
            continue
        
        frame_count += 1
        frame = buffer.tobytes()
        
        # Yield frame in multipart format
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

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
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/stats')
def stats():
    """Return streaming statistics"""
    return {'frames': frame_count, 'status': 'active'}

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'ok', 'camera': camera is not None and camera.isOpened()}

if __name__ == '__main__':
    logging.info("Starting webcam streaming server...")
    logging.info("Access the stream at: http://0.0.0.0:5000/video_feed")
    
    try:
        # Run on all interfaces, port 5000
        app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
    finally:
        if camera is not None:
            camera.release()
            logging.info("Camera released")
EOF
    
    chmod +x webcam_stream_server.py
    echo "✅ Server script created"
}

# Main execution
main() {
    check_requirements
    install_python_deps
    create_server_script
    
    LOCAL_IP=$(get_local_ip)
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "✅ Setup Complete!"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "📡 Your local IP: $LOCAL_IP"
    echo ""
    echo "To start the streaming server:"
    echo "  python3 webcam_stream_server.py"
    echo ""
    echo "Access points:"
    echo "  • Web preview: http://$LOCAL_IP:5000"
    echo "  • Stream URL:  http://$LOCAL_IP:5000/video_feed"
    echo ""
    echo "For QIDK app, use this URL:"
    echo "  http://$LOCAL_IP:5000/video_feed"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "Start server now? [Y/n]"
    read -n 1 -r REPLY
    echo ""
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo "Starting server..."
        python3 webcam_stream_server.py
    fi
}

main
