# ESW Posture Detection App

A real-time AI-powered posture detection and correction Android application that uses YOLOv11 pose estimation to monitor and improve sitting posture.

## Table of Contents

- [Project Structure](#project-structure)
- [Code Architecture](#code-architecture)
- [Core Components](#core-components)
- [Technical Implementation](#technical-implementation)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Model Training](#model-training)
- [Configuration](#configuration)

---

## Project Structure

```
ESWposedetection/
├── app/
│   ├── src/main/
│   │   ├── java/com/example/eswproject/
│   │   │   ├── MainActivity.kt                    # Main UI, navigation, screen routing
│   │   │   ├── PostureDetector.kt                 # Core posture analysis engine
│   │   │   ├── YoloV11PoseDetector.kt            # YOLO pose detection wrapper
│   │   │   ├── PersonalizedPostureManager.kt     # LightGBM model integration
│   │   │   ├── PoseDetectionViewModel.kt         # State management & data flow
│   │   │   ├── SettingsManager.kt                # Preferences & configuration
│   │   │   ├── SettingsScreen.kt                 # Settings UI components
│   │   │   ├── ProfileSelectionScreen.kt         # Multi-user profile management
│   │   │   ├── PersonalizedSetupScreen.kt        # Calibration workflow UI
│   │   │   ├── PerformanceOverlay.kt             # FPS/latency metrics display
│   │   │   ├── SkeletonOverlay.kt                # Visual pose rendering
│   │   │   ├── NetworkVideoStreamReceiver.kt     # MJPEG stream handler
│   │   │   ├── CameraPreview.kt                  # CameraX integration
│   │   │   ├── PoseDetectionBackend.kt           # ONNX runtime interface
│   │   │   ├── RuntimeProvider.kt                # CPU/GPU/NPU selection
│   │   │   ├── HardwareDetector.kt               # Device capability detection
│   │   │   └── ui/theme/                         # Material3 theme config
│   │   ├── assets/
│   │   │   └── yolov8n-pose.onnx                 # YOLOv11 pose model (ONNX)
│   │   ├── res/                                   # Android resources
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts                           # App-level dependencies
├── Model/
│   ├── lightGBM/
│   │   └── lightGBM.py                           # Personalized model training
│   └── README.md                                 # Model documentation
├── webcam_stream_server.py                       # MJPEG streaming server
├── build.gradle.kts                              # Project-level Gradle config
├── settings.gradle.kts                           # Module configuration
└── README.md                                     # This file
```

---

## Code Architecture

### Data Flow Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ANDROID APPLICATION                         │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
         ┌──────────▼─────────┐      ┌─────────▼──────────┐
         │  CameraX Preview   │      │  Network Stream    │
         │  (Built-in Camera) │      │  (MJPEG Receiver)  │
         └──────────┬─────────┘      └─────────┬──────────┘
                    │                           │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   YoloV11PoseDetector     │
                    │   • ONNX Runtime Engine   │
                    │   • RuntimeProvider        │
                    │     (CPU/GPU/NPU)         │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    17 COCO Keypoints      │
                    │   • x, y coordinates      │
                    │   • confidence scores     │
                    └─────────────┬─────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 │                                 │
    ┌────────────▼────────────┐     ┌─────────────▼──────────────┐
    │   PostureDetector.kt    │     │ PersonalizedPostureManager │
    │   • Angle calculation   │     │   • Chaquopy Python        │
    │   • Confidence filter   │     │   • LightGBM model         │
    │   • Score computation   │     │   • User-specific ML       │
    │   • Standard mode       │     │   • Personalized mode      │
    └────────────┬────────────┘     └─────────────┬──────────────┘
                 │                                 │
                 └────────────────┬────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │      PostureResult        │
                    │   • Classification        │
                    │   • Score (0-100)         │
                    │   • Angles (neck/back/leg)│
                    │   • Suggestions           │
                    │   • Confidence            │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  PoseDetectionViewModel   │
                    │   • StateFlow emission    │
                    │   • UI state management   │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │      MainActivity UI      │
                    │   • Compose components    │
                    │   • Skeleton overlay      │
                    │   • Stats panels          │
                    │   • Suggestions           │
                    └───────────────────────────┘
```

---

## Core Components

### 1. **PostureDetector.kt** - Standard Posture Analysis

**Purpose**: Rule-based posture detection using geometric angle analysis

**Key Methods**:
```kotlin
class PostureDetector(confidenceThreshold: Float) {
    // Main entry point
    fun analyzePosture(persons: List<PersonDetection>): PostureResult
    
    // Calibration
    fun calibrate(neckAngle: Double, backAngle: Double, legsAngle: Double)
    fun resetToDefaults()
    fun getCalibrationValues(): Triple<Double, Double, Double>
    
    // Internal calculations
    private fun calculateAngle(a: Point, b: Point, c: Point): Double
    private fun calculatePostureScore(neck: Double, back: Double, legs: Double): Double
    private fun classifyPostureWithTolerance(...): Triple<String, String, List<String>>
}
```

**Algorithm**:
1. Select body side (left/right) based on ear confidence
2. Extract 5 required keypoints: ear, shoulder, hip, knee, ankle
3. Calculate minimum confidence from required keypoints
4. Filter if confidence < threshold
5. Calculate 3 angles:
   - Neck: Hip → Shoulder → Ear
   - Back: Knee → Hip → Shoulder  
   - Legs: Ankle → Knee → Hip
6. Compute weighted score (0-100)
7. Classify posture with tolerance checks

**Constants**:
- `NECK_TOLERANCE = 8.0°`
- `BACK_TOLERANCE = 8.0°`
- `LEGS_TOLERANCE = 8.0°`
- Weights: neck=1.0, back=1.5, legs=0.5

---

### 2. **YoloV11PoseDetector.kt** - Pose Inference Engine

**Purpose**: ONNX model inference with runtime provider selection

**Key Methods**:
```kotlin
class YoloV11PoseDetector {
    fun initializeBackend(context: Context, runtimeProvider: RuntimeProvider)
    fun detectPose(bitmap: Bitmap): List<PersonDetection>
    fun release()
    
    private fun preprocessImage(bitmap: Bitmap): OnnxTensor
    private fun postprocessOutput(output: FloatArray): List<PersonDetection>
    private fun nonMaxSuppression(boxes: List<Detection>): List<Detection>
}
```

**Processing Pipeline**:
```
Input Bitmap (any size)
    ↓
Resize to 640x640
    ↓
Normalize [0-255] → [0.0-1.0]
    ↓
Convert to CHW format (channels-first)
    ↓
ONNX Inference (CPU/GPU/NPU)
    ↓
Parse output [1, 56, 8400]
    ↓
Apply confidence threshold
    ↓
Non-Maximum Suppression (NMS)
    ↓
Return List<PersonDetection>
```

---

### 3. **MainActivity.kt** - UI & Navigation

**Purpose**: Jetpack Compose UI with navigation and state management

**Screen Routes**:
```kotlin
object HomeScreenRoute : Screen("home", "Home")
object CameraScreenRoute : Screen("camera", "Camera")
object HistoryScreenRoute : Screen("history", "History")
object SettingsScreenRoute : Screen("settings", "Settings")
object PersonalizedSetupScreenRoute : Screen("personalized_setup", "Setup")
object ProfileSelectionScreenRoute : Screen("profile_selection", "Profiles")
```

**Key Composables**:
- `CameraScreen()` - Live camera feed with pose overlay
- `NetworkStreamScreen()` - MJPEG stream viewer
- `ToolsMenuPanel()` - Calibrate/Reset/Camera/Server menu
- `ExpandableSuggestionsPanel()` - Collapsible tips sidebar
- `ExpandableStatsPanel()` - Angle measurements display
- `PostureInfoCard()` - Score and classification card
- `PerformanceOverlay()` - FPS/latency/runtime metrics

---

### 4. **PoseDetectionViewModel.kt** - State Management

**Purpose**: ViewModel for reactive state updates

**State Flow**:
```kotlin
data class PoseState(
    val persons: List<PersonDetection>,
    val processingTimeMs: Long,
    val currentPose: String,
    val postureScore: Int
)

class PoseDetectionViewModel : ViewModel() {
    private val _poseState = MutableStateFlow(PoseState(...))
    val poseState: StateFlow<PoseState> = _poseState.asStateFlow()
    
    fun initializeBackend(context: Context)
    fun updatePoseState(persons: List<PersonDetection>)
    fun getPoseDescription(): String
    fun getPostureScore(): Int
}
```

---

### 5. **PersonalizedPostureManager.kt** - ML Integration

**Purpose**: Chaquopy Python/LightGBM integration for personalized mode

**Key Methods**:
```kotlin
class PersonalizedPostureManager(context: Context) {
    fun initialize()
    fun loadModel(userId: String): Boolean
    fun predictPosture(keypoints: FloatArray): PostureResult
    fun trainPersonalizedModel(userId: String, samples: List<Sample>)
    
    private fun callPythonScript(scriptName: String, args: Map<String, Any>): PyObject
}
```

**Python Integration**:
```python
# Called via Chaquopy
import lightgbm as lgb
import numpy as np

def train_model(features, labels, user_id):
    model = lgb.LGBMClassifier(n_estimators=100, max_depth=5)
    model.fit(features, labels)
    model.save_model(f"models/{user_id}_model.txt")
    return {"status": "success"}

def predict(features, user_id):
    model = lgb.Booster(model_file=f"models/{user_id}_model.txt")
    prediction = model.predict(features)
    return {"posture": prediction[0], "confidence": 0.95}
```

---

### 6. **SettingsManager.kt** - Configuration Persistence

**Purpose**: SharedPreferences wrapper for app settings

**Stored Values**:
```kotlin
object SettingsManager {
    // Detection mode
    fun getPostureMode(): PostureDetectionMode
    fun setPostureMode(mode: PostureDetectionMode)
    
    // Confidence threshold
    fun getConfidenceThreshold(): Float  // 0.0 - 1.0
    fun setConfidenceThreshold(threshold: Float)
    
    // User profiles
    fun getUserId(): String
    fun setUserId(userId: String)
    fun getAllUsers(): Set<String>
    
    // Profile images
    fun getProfileImageUri(userId: String): String?
    fun setProfileImageUri(userId: String, uri: String?)
}
```

---

## Overview

ESW Posture Detection is an Android application designed to help users maintain healthy sitting posture through real-time monitoring. The app uses computer vision and machine learning to detect body keypoints, calculate posture angles, and provide actionable feedback.

### Key Capabilities

- **Real-time pose detection** using YOLOv11 pose estimation model
- **Posture scoring system** (0-100) based on ergonomic principles
- **Personalized calibration** for individual body types
- **Multiple camera sources** - built-in camera or network webcam streaming
- **Netflix-style profile selection** for multi-user support
- **Detailed posture analytics** with angle measurements


### 7. **SkeletonOverlay.kt** - Pose Visualization

**Purpose**: Canvas-based rendering of detected pose keypoints and connections

**Key Functions**:
```kotlin
@Composable
fun SkeletonOverlay(
    persons: List<PersonDetection>,
    modifier: Modifier,
    fillCenter: Boolean,
    showDebugInfo: Boolean
)

// Renders skeleton with color-coded confidence
private fun DrawScope.drawSkeleton(
    person: PersonDetection,
    keypoints: List<Keypoint>,
    scaleX: Float,
    scaleY: Float
) {
    // Draw connections (bones)
    SKELETON_CONNECTIONS.forEach { (start, end) ->
        drawLine(color, thickness, ...)
    }
    
    // Draw keypoints (joints)
    keypoints.forEach { keypoint ->
        val color = when {
            confidence > 0.8f -> Color.Green
            confidence > 0.5f -> Color.Yellow
            else -> Color.Red
        }
        drawCircle(color, radius, center)
    }
}
```

**COCO Skeleton Connections**:
```kotlin
val SKELETON_CONNECTIONS = listOf(
    5 to 6,   // Shoulders
    5 to 7,   // Left arm
    7 to 9,   // Left forearm
    6 to 8,   // Right arm
    8 to 10,  // Right forearm
    5 to 11,  // Left torso
    6 to 12,  // Right torso
    11 to 12, // Hips
    11 to 13, // Left thigh
    13 to 15, // Left shin
    12 to 14, // Right thigh
    14 to 16  // Right shin
)
```

---

### 8. **NetworkVideoStreamReceiver.kt** - MJPEG Client

**Purpose**: Receives MJPEG stream from network webcam server

**Implementation**:
```kotlin
class NetworkVideoStreamReceiver {
    fun startStream(url: String, onFrame: (Bitmap) -> Unit, onError: (String) -> Unit)
    fun stopStream()
    
    private suspend fun receiveFrames() {
        // HTTP connection to MJPEG endpoint
        val connection = URL(streamUrl).openConnection()
        val inputStream = BufferedInputStream(connection.getInputStream())
        
        // Parse multipart/x-mixed-replace stream
        while (isActive) {
            val boundary = readBoundary(inputStream)
            val contentLength = readContentLength(inputStream)
            val jpegData = readJpegData(inputStream, contentLength)
            
            // Decode and emit bitmap
            val bitmap = BitmapFactory.decodeByteArray(jpegData, 0, jpegData.size)
            onFrame(bitmap)
        }
    }
}
```

**Server Integration**:
```python
# webcam_stream_server.py
from flask import Flask, Response
import cv2

app = Flask(__name__)
camera = cv2.VideoCapture(0)

def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            break
        
        ret, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()
        
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

### 9. **RuntimeProvider.kt** - Execution Backend

**Purpose**: Hardware acceleration selection for ONNX inference

**Enum Definition**:
```kotlin
enum class RuntimeProvider(val displayName: String, val onnxFlag: Int) {
    CPU("CPU", OrtSession.SessionOptions.ExecutionMode.SEQUENTIAL),
    GPU_NNAPI("GPU (NNAPI)", OrtSession.SessionOptions.ExecutionMode.PARALLEL),
    NPU_NNAPI("NPU (NNAPI)", OrtSession.SessionOptions.ExecutionMode.PARALLEL)
}
```

**Configuration**:
```kotlin
fun createSessionOptions(provider: RuntimeProvider): OrtSession.SessionOptions {
    return OrtSession.SessionOptions().apply {
        when (provider) {
            RuntimeProvider.CPU -> {
                setExecutionMode(ExecutionMode.SEQUENTIAL)
                setInterOpNumThreads(4)
                setIntraOpNumThreads(4)
            }
            RuntimeProvider.GPU_NNAPI -> {
                addNnapi()
                setExecutionMode(ExecutionMode.PARALLEL)
            }
            RuntimeProvider.NPU_NNAPI -> {
                addNnapi()
                setExecutionMode(ExecutionMode.PARALLEL)
                setNnapiFlags(NNAPI_FLAG_USE_NPU)
            }
        }
    }
}
```

---

### 10. **PerformanceOverlay.kt** - Metrics Display

**Purpose**: Real-time performance monitoring UI

**Displayed Metrics**:
```kotlin
data class PerformanceMetrics(
    val latencyMs: Long,           // Inference time
    val fps: Float,                // Frames per second
    val runtimeProvider: RuntimeProvider  // CPU/GPU/NPU
)

@Composable
fun PerformanceOverlay(
    metrics: PerformanceMetrics,
    onRuntimeSwitch: () -> Unit,
    isCompact: Boolean = false
) {
    // Shows: "Latency: 45ms • FPS: 22.3 • NPU [Switch Button]"
}
```

---

## Technical Implementation

### Pose Detection Pipeline

```
Camera Frame (Bitmap)
    ↓
Resize to 640x640 (YOLOv11 input)
    ↓
Normalize pixel values [0-255] → [0.0-1.0]
    ↓
Convert RGB → CHW tensor format
    ↓
ONNX Inference (CPU/GPU/NPU)
    ↓
Output: [1, 56, 8400] tensor
    ↓
Parse detections (bounding boxes + keypoints)
    ↓
Apply confidence threshold (default: 0.5)
    ↓
Non-Maximum Suppression (IoU threshold: 0.4)
    ↓
Extract 17 COCO keypoints per person
    ↓
PostureDetector.analyzePosture()
    ↓
Calculate angles & score
    ↓
Return PostureResult
```

### Keypoint Indices (COCO Format)

| Index | Keypoint | Used For |
|-------|----------|----------|
| 0 | Nose | - |
| 1 | Left Eye | - |
| 2 | Right Eye | - |
| 3 | Left Ear | Neck angle |
| 4 | Right Ear | Neck angle |
| 5 | Left Shoulder | Neck & Back angles |
| 6 | Right Shoulder | Neck & Back angles |
| 7-10 | Arms/Elbows/Wrists | - |
| 11 | Left Hip | All angles |
| 12 | Right Hip | All angles |
| 13 | Left Knee | Back & Legs angles |
| 14 | Right Knee | Back & Legs angles |
| 15 | Left Ankle | Legs angle |
| 16 | Right Ankle | Legs angle |

### Angle Calculation Formula

```kotlin
// Vector-based angle calculation between 3 points (a-b-c)
fun calculateAngle(a: Point, b: Point, c: Point): Double {
    // Vector from b to a
    val ba = Vector(a.x - b.x, a.y - b.y)
    
    // Vector from b to c
    val bc = Vector(c.x - b.x, c.y - b.y)
    
    // Dot product
    val dotProduct = ba.x * bc.x + ba.y * bc.y
    
    // Magnitudes
    val magBa = sqrt(ba.x² + ba.y²)
    val magBc = sqrt(bc.x² + bc.x²)
    
    // Cosine of angle
    val cosAngle = dotProduct / (magBa * magBc + 1e-6)
    
    // Clamp to [-1, 1] to avoid numerical errors
    val clampedCos = cosAngle.coerceIn(-1.0, 1.0)
    
    // Return angle in degrees
    return Math.toDegrees(acos(clampedCos))
}
```

### Posture Score Formula

```
Score = 100 × (1 - totalDeviation / maxDeviation)

Where:
  totalDeviation = Σ weight[i] × (angle[i] - ideal[i])²
  
  neck_deviation = 1.0 × (neck_angle - 165°)²
  back_deviation = 1.5 × (back_angle - 175°)²
  legs_deviation = 0.5 × (legs_angle - 170°)²
  
  totalDeviation = neck_deviation + back_deviation + legs_deviation
  
  maxDeviation = maximum possible deviation (precomputed)
```

### Confidence Filtering Flow

```
1. Detect persons with YOLOv11
2. Extract required keypoints: ear, shoulder, hip, knee, ankle
3. Get confidence scores for each keypoint
4. Calculate filteringConfidence = min(keypoint_confidences)
5. Compare: filteringConfidence vs userThreshold
6. If below threshold:
   → Return LOW_CONFIDENCE result
   → Skip angle calculation
7. If above threshold:
   → Proceed with full posture analysis
   → Calculate angles
   → Compute score
   → Classify posture
8. Always display actual confidence in UI
```

---

## Features

### 1. Dual Detection Modes

| Mode | Description |
|------|-------------|
| **Standard Mode** | Rule-based posture detection using calibrated angle thresholds |
| **Personalized Mode** | LightGBM machine learning model trained on user-specific posture data |

### 2. Camera Sources

- **USB/Built-in Camera**: Direct camera feed using CameraX
- **Network Stream**: MJPEG stream from external webcam server (Python-based)

### 3. Real-time Analysis

- **3 Key Angles Monitored**:
  - **Neck Angle**: Hip → Shoulder → Ear alignment
  - **Back Angle**: Knee → Hip → Shoulder alignment
  - **Legs Angle**: Ankle → Knee → Hip alignment

- **Posture Classifications**:
  - ALIGNED - Perfect posture
  - NECK_MISALIGNMENT - Head too far forward/back
  - BACK_MISALIGNMENT - Slouching or leaning
  - LEGS_MISALIGNMENT - Improper leg positioning
  - Combined misalignments (NECK_BACK, NECK_LEGS, etc.)

### 4. User Interface

- **Tools Menu**: Collapsible menu with Calibrate, Reset, Camera Toggle, and Server Settings
- **Expandable Stats Panel**: Detailed angle measurements and confidence scores
- **Suggestions Panel**: Actionable tips that expand from the right side
- **Posture Score Card**: Real-time 0-100 score with color-coded feedback
- **Skeleton Overlay**: Visual representation of detected pose on camera feed

### 5. Profile System

- Netflix-style profile selection screen
- Per-user calibration settings
- Profile images support
- Quick profile switching

### 6. Calibration

- **One-tap calibration**: Set current posture as reference
- **Reset to defaults**: Restore factory calibration values
- **Tolerance-based thresholds**: ±8° tolerance for each angle

### 7. Confidence Filtering

- Adjustable confidence threshold (0-100%)
- Filters unreliable keypoint detections
- Uses minimum confidence of 5 required keypoints (ear, shoulder, hip, knee, ankle)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Android App                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   CameraX   │  │   Network   │  │    Chaquopy Python      │ │
│  │   Preview   │  │   Stream    │  │    (LightGBM Model)     │ │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      │               │
│  ┌─────────────────────────────────────────┐   │               │
│  │         YOLOv11 Pose Detector           │   │               │
│  │         (ONNX + NNAPI Runtime)          │   │               │
│  └──────────────────┬──────────────────────┘   │               │
│                     │                          │               │
│                     ▼                          │               │
│  ┌─────────────────────────────────────────┐   │               │
│  │              Keypoints                   │   │               │
│  │   (17 COCO format body landmarks)        │   │               │
│  └──────────────────┬──────────────────────┘   │               │
│                     │                          │               │
│         ┌───────────┴───────────┐              │               │
│         ▼                       ▼              ▼               │
│  ┌─────────────┐         ┌─────────────────────────┐           │
│  │  Standard   │         │     Personalized        │           │
│  │  Posture    │         │     Posture Manager     │           │
│  │  Detector   │         │     (Python/LightGBM)   │           │
│  └──────┬──────┘         └────────────┬────────────┘           │
│         │                             │                         │
│         └──────────────┬──────────────┘                         │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Posture Result                         │   │
│  │  • Classification (ALIGNED, NECK_MISALIGNMENT, etc.)    │   │
│  │  • Score (0-100)                                         │   │
│  │  • Angles (neck, back, legs)                             │   │
│  │  • Suggestions                                           │   │
│  │  • Confidence                                            │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Android Studio Hedgehog (2023.1.1) or later
- Android SDK 36
- JDK 11+
- Python 3.8+ (for Model training and webcam server)

### Build Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/zyxro/ESWposedetection.git
   cd ESWposedetection
   ```

2. **Open in Android Studio**
   - Open the project folder
   - Let Gradle sync complete

3. **Build the APK**
   ```powershell
   ./gradlew assembleDebug
   ```

4. **Install on device**
   ```powershell
   ./gradlew installDebug
   ```

### Network Webcam Setup (Optional)

To use an external webcam via network streaming:

1. Install Python dependencies:
   ```powershell
   pip install flask opencv-python
   ```

2. Start the webcam server:
   ```powershell
   python webcam_stream_server.py
   ```

3. In the app, switch to Network Stream mode and enter the URL:
   ```
   http://<your-pc-ip>:5000/video_feed
   ```

---

## Usage

### Quick Start

1. Launch the app and grant camera permissions
2. Navigate to the **Camera** tab
3. Position yourself so your full body is visible (side profile works best)
4. The app will display your posture score and suggestions

### Calibrating Your Posture

1. Sit in your ideal posture position
2. Open the **Tools** menu (top-left)
3. Tap **Calibrate**
4. The app will use your current position as the reference

### Adjusting Confidence Threshold

1. Go to **Settings** tab
2. Adjust the **Detection Confidence Threshold** slider
3. Higher values = stricter filtering (may reject poses in poor lighting)
4. Lower values = more permissive (may include unreliable detections)

### Using Personalized Mode

1. Go to **Settings** → Enable **Personalized Mode**
2. Complete the setup by capturing calibration samples
3. The LightGBM model will be trained on your specific posture patterns

---

## Technical Implementation

### Pose Detection Pipeline

```
Camera Frame → YOLOv11 Inference → 17 Keypoints → Angle Calculation → Posture Classification
```

### Keypoint Indices (COCO Format)

| Index | Keypoint | Used For |
|-------|----------|----------|
| 3/4 | Left/Right Ear | Neck angle |
| 5/6 | Left/Right Shoulder | Neck & Back angles |
| 11/12 | Left/Right Hip | All angles |
| 13/14 | Left/Right Knee | Back & Legs angles |
| 15/16 | Left/Right Ankle | Legs angle |

### Angle Calculation

```kotlin
// Vector-based angle calculation between 3 points
fun calculateAngle(a: Point, b: Point, c: Point): Double {
    val ba = Vector(a.x - b.x, a.y - b.y)
    val bc = Vector(c.x - b.x, c.y - b.y)
    val dotProduct = ba.dot(bc)
    val angle = acos(dotProduct / (ba.magnitude * bc.magnitude))
    return Math.toDegrees(angle)
}
```

### Posture Score Formula

```
Score = 100 × (1 - totalDeviation / maxDeviation)

Where:
  totalDeviation = neck_weight × (neck_angle - ideal_neck)² +
                   back_weight × (back_angle - ideal_back)² +
                   legs_weight × (legs_angle - ideal_legs)²
                   
Weights: neck=1.0, back=1.5, legs=0.5
```

### Confidence Filtering Flow

1. Get confidence values for 5 required keypoints
2. Calculate minimum confidence (`filteringConfidence`)
3. Compare against user-set threshold
4. If below threshold → return LOW_CONFIDENCE result
5. If above threshold → proceed with full posture analysis

---

## Project Structure

```
ESWposedetection/
├── app/
│   ├── src/main/java/com/example/eswproject/
│   │   ├── MainActivity.kt              # Main UI and navigation
│   │   ├── PostureDetector.kt           # Standard posture detection
│   │   ├── PersonalizedPostureManager.kt # LightGBM integration
│   │   ├── YoloV11PoseDetector.kt       # YOLO inference engine
│   │   ├── SettingsManager.kt           # Preferences management
│   │   ├── SettingsScreen.kt            # Settings UI
│   │   ├── ProfileSelectionScreen.kt    # Profile selection UI
│   │   ├── PersonalizedSetupScreen.kt   # Calibration setup UI
│   │   ├── SkeletonOverlay.kt           # Pose visualization
│   │   ├── NetworkVideoStreamReceiver.kt # MJPEG stream client
│   │   ├── PoseDetectionViewModel.kt    # State management
│   │   └── ...
│   ├── src/main/assets/
│   │   └── yolov8n-pose.onnx            # YOLO pose model
│   └── build.gradle.kts
├── Model/
│   ├── create_dataset.py                # Dataset creation from keypoints
│   ├── train_model.py                   # Model training script
│   ├── posture_corrector.py             # Posture analysis logic
│   ├── run_live_model.py                # Live capture script
│   ├── lightGBM/
│   │   └── lightGBM.py                  # LightGBM model training
│   └── requirements.txt
├── webcam_stream_server.py              # Flask MJPEG server
├── build.gradle.kts
└── README.md
```

---

## Model Training

### Creating Training Dataset

1. Capture keypoint JSON files using `run_live_model.py`
2. Organize files into labeled folders (good_posture, bad_posture, etc.)
3. Run dataset creation:
   ```powershell
   cd Model
   python create_dataset.py
   ```

### Training the Model

```powershell
cd Model
python train_model.py
```

This creates `posture_model_final.pkl` using Random Forest with 500 trees.

### LightGBM Personalized Model

For personalized mode, the app uses Chaquopy to run Python/LightGBM on-device:

```python
# Model trained per-user with their specific posture samples
import lightgbm as lgb
model = lgb.LGBMClassifier(n_estimators=100, max_depth=5)
model.fit(user_features, user_labels)
```

---

## Configuration

### Settings Options

| Setting | Range | Default | Description |
|---------|-------|---------|-------------|
| Detection Mode | Standard/Personalized | Standard | Posture detection algorithm |
| Confidence Threshold | 0-100% | 75% | Minimum keypoint confidence |
| Profile | User profiles | Default | Active user profile |

### Posture Thresholds

| Angle | Ideal | Tolerance | Weight |
|-------|-------|-----------|--------|
| Neck | 165° | ±8° | 1.0 |
| Back | 175° | ±8° | 1.5 |
| Legs | 170° | ±8° | 0.5 |

### Angle Limits (Dataset)

| Angle | Min | Max |
|-------|-----|-----|
| Neck | 125.19° | 178.45° |
| Back | 59.70° | 145.25° |
| Legs | 86.13° | 164.73° |

---

## Dependencies

### Android

- CameraX (camera2)
- Jetpack Compose (Material3)
- ONNX Runtime (pose detection)
- Chaquopy (Python integration)
- Firebase (optional, for cloud sync)

### Python (Model folder)

- ultralytics (YOLO)
- opencv-python
- numpy
- scikit-learn
- lightgbm
- flask (webcam server)

---

## Authors

- EngineersWithoutSleep