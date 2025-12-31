package com.example.eswproject

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import ai.onnxruntime.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import kotlin.math.max
import kotlin.math.min

/**
 * YOLOv11n-pose detector using ONNX Runtime for Android
 * Detects 17 COCO keypoints for pose estimation
 * Supports CPU, GPU (NNAPI), and NPU (NNAPI) execution providers
 */
class YoloV11PoseDetector : PoseDetectionBackend {
    
    private var ortSession: OrtSession? = null
    private var ortEnvironment: OrtEnvironment? = null
    private var currentRuntime: RuntimeProvider = RuntimeProvider.CPU
    private val performanceTracker = PerformanceTracker(windowSize = 30)
    private val sessionMutex = Mutex()
    
    @Volatile private var isSwitching = false
    
    // Callback for performance metrics updates
    var onPerformanceUpdate: ((PerformanceMetrics) -> Unit)? = null
    
    companion object {
        private const val TAG = "YoloV11PoseDetector"
        private const val MODEL_NAME = "yolo11n-pose.onnx"
        private const val INPUT_SIZE = 640
        private const val CONFIDENCE_THRESHOLD = 0.3f
        private const val IOU_THRESHOLD = 0.5f
        
        // YOLOv11-pose output format: [batch, 56, 8400]
        // 56 channels = 4 (bbox) + 1 (confidence) + 51 (17 keypoints * 3 values each: x, y, confidence)
        private const val NUM_KEYPOINTS = 17
        private const val KEYPOINT_CHANNELS = 3 // x, y, confidence
        private const val BBOX_CHANNELS = 4
        private const val CONF_CHANNEL = 1
    }
    
    override suspend fun initialize(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Initializing YOLOv11n-pose detector with ${currentRuntime.displayName}...")
            
            // Load ONNX model from assets
            val modelBytes = loadModelFromAssets(context, MODEL_NAME)
            
            // Create ONNX Runtime environment and session with runtime provider
            ortEnvironment = OrtEnvironment.getEnvironment()
            ortSession = createSessionWithRuntime(modelBytes, currentRuntime)
            
            Log.i(TAG, "✓ YOLOv11n-pose model loaded successfully with ${currentRuntime.displayName}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "✗ Failed to initialize YOLOv11n-pose detector", e)
            false
        }
    }
    
    /**
     * Create ONNX session with specified runtime provider
     */
    private fun createSessionWithRuntime(modelBytes: ByteArray, runtime: RuntimeProvider): OrtSession {
        val sessionOptions = OrtSession.SessionOptions().apply {
            setInterOpNumThreads(4)
            setIntraOpNumThreads(4)
            setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
            
            when (runtime) {
                RuntimeProvider.CPU -> {
                    // CPU only - no additional configuration needed
                    Log.i(TAG, "Using CPU execution provider")
                }
                RuntimeProvider.GPU_NNAPI, RuntimeProvider.NPU_NNAPI -> {
                    try {
                        // Add NNAPI execution provider for GPU/NPU acceleration
                        addNnapi()
                        Log.i(TAG, "Using NNAPI execution provider for ${runtime.displayName}")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to enable NNAPI, falling back to CPU", e)
                    }
                }
            }
        }
        
        return ortEnvironment?.createSession(modelBytes, sessionOptions)
            ?: throw RuntimeException("Failed to create ONNX session")
    }
    
    /**
     * Switch runtime provider (CPU, GPU, NPU)
     * Reinitializes the ONNX session with the new runtime
     */
    suspend fun switchRuntime(context: Context, newRuntime: RuntimeProvider): Boolean = withContext(Dispatchers.IO) {
        if (isSwitching) {
            Log.w(TAG, "Already switching runtime, please wait")
            return@withContext false
        }
        
        sessionMutex.withLock {
            try {
                isSwitching = true
                Log.i(TAG, "Switching runtime from ${currentRuntime.displayName} to ${newRuntime.displayName}")
                
                // Small delay to let any running inference complete
                kotlinx.coroutines.delay(100)
                
                // Release current session
                try {
                    ortSession?.close()
                } catch (e: Exception) {
                    Log.w(TAG, "Error closing previous session", e)
                }
                ortSession = null
                
                // Update runtime
                currentRuntime = newRuntime
                performanceTracker.reset()
                
                // Load model with new runtime
                val modelBytes = loadModelFromAssets(context, MODEL_NAME)
                ortSession = createSessionWithRuntime(modelBytes, newRuntime)
                
                Log.i(TAG, "✓ Successfully switched to ${newRuntime.displayName}")
                isSwitching = false
                true
            } catch (e: Exception) {
                Log.e(TAG, "✗ Failed to switch to ${newRuntime.displayName}", e)
                isSwitching = false
                // Try to restore to CPU if switch failed
                try {
                    val modelBytes = loadModelFromAssets(context, MODEL_NAME)
                    currentRuntime = RuntimeProvider.CPU
                    ortSession = createSessionWithRuntime(modelBytes, RuntimeProvider.CPU)
                    Log.i(TAG, "Restored to CPU after failed switch")
                } catch (restoreException: Exception) {
                    Log.e(TAG, "Failed to restore to CPU", restoreException)
                }
                false
            }
        }
    }
    
    /**
     * Get current runtime provider
     */
    fun getCurrentRuntime(): RuntimeProvider = currentRuntime
    
    /**
     * Get current performance metrics
     */
    fun getPerformanceMetrics(): PerformanceMetrics = performanceTracker.getMetrics(currentRuntime)
    
    override suspend fun detectAndPose(bitmap: Bitmap): PoseDetectionResult = withContext(Dispatchers.Default) {
        val startTime = System.currentTimeMillis()
        
        // Skip inference if switching runtime
        if (isSwitching) {
            return@withContext PoseDetectionResult(emptyList(), 0, MLBackend.TENSORFLOW_LITE)
        }
        
        try {
            val session = sessionMutex.withLock {
                ortSession ?: run {
                    Log.w(TAG, "Model not initialized")
                    return@withContext PoseDetectionResult(emptyList(), 0, MLBackend.TENSORFLOW_LITE)
                }
            }
            
            // Preprocess image
            val inputTensor = preprocessImage(bitmap)
            
            // Run inference
            val inputs = mapOf(session.inputNames.iterator().next() to inputTensor)
            val outputs = session.run(inputs)
            
            // Parse outputs
            val outputTensor = outputs[0].value as Array<*>
            val persons = parseOutputs(outputTensor, bitmap.width, bitmap.height)
            
            // Note: ONNX Runtime handles resource cleanup automatically
            
            val inferenceTime = System.currentTimeMillis() - startTime
            
            // Track performance
            performanceTracker.addInferenceTime(inferenceTime)
            val metrics = performanceTracker.getMetrics(currentRuntime)
            
            // Notify performance update callback
            onPerformanceUpdate?.invoke(metrics)
            
            Log.d(TAG, "Detection complete: ${persons.size} persons, ${inferenceTime}ms, ${currentRuntime.displayName}, FPS: ${"%.1f".format(metrics.fps)}")
            
            PoseDetectionResult(persons, inferenceTime, MLBackend.TENSORFLOW_LITE)
        } catch (e: Exception) {
            Log.e(TAG, "Error during pose detection", e)
            PoseDetectionResult(emptyList(), System.currentTimeMillis() - startTime, MLBackend.TENSORFLOW_LITE)
        }
    }
    
    override fun release() {
        try {
            ortSession?.close()
            ortSession = null
            Log.i(TAG, "YOLOv11n-pose detector released")
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing detector", e)
        }
    }
    
    /**
     * Load model from assets folder
     */
    private fun loadModelFromAssets(context: Context, modelName: String): ByteArray {
        return context.assets.open(modelName).use { inputStream ->
            inputStream.readBytes()
        }
    }
    
    /**
     * Preprocess bitmap to model input format
     * YOLOv11 expects [1, 3, 640, 640] in RGB format, normalized to [0, 1]
     */
    private fun preprocessImage(bitmap: Bitmap): OnnxTensor {
        // Resize bitmap to INPUT_SIZE x INPUT_SIZE
        val resizedBitmap = Bitmap.createScaledBitmap(bitmap, INPUT_SIZE, INPUT_SIZE, true)
        
        // Create float buffer for RGB channels
        val floatBuffer = FloatBuffer.allocate(1 * 3 * INPUT_SIZE * INPUT_SIZE)
        
        // Extract pixels
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        resizedBitmap.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)
        
        // Convert to CHW format (channels, height, width) and normalize
        for (c in 0 until 3) {
            for (h in 0 until INPUT_SIZE) {
                for (w in 0 until INPUT_SIZE) {
                    val pixel = pixels[h * INPUT_SIZE + w]
                    val value = when (c) {
                        0 -> ((pixel shr 16) and 0xFF) / 255.0f  // Red
                        1 -> ((pixel shr 8) and 0xFF) / 255.0f   // Green
                        else -> (pixel and 0xFF) / 255.0f        // Blue
                    }
                    floatBuffer.put(value)
                }
            }
        }
        
        floatBuffer.rewind()
        
        // Create ONNX tensor
        val shape = longArrayOf(1, 3, INPUT_SIZE.toLong(), INPUT_SIZE.toLong())
        return OnnxTensor.createTensor(ortEnvironment, floatBuffer, shape)
    }
    
    /**
     * Parse YOLOv11-pose outputs
     * Output format: [1, 56, 8400]
     * 56 channels: 4 bbox coords + 1 confidence + 51 keypoint values (17 * 3)
     */
    private fun parseOutputs(output: Array<*>, imgWidth: Int, imgHeight: Int): List<PersonDetection> {
        val detections = mutableListOf<PersonDetection>()
        
        try {
            // Output shape: [1, 56, 8400]
            val batch = output[0] as Array<*>
            val numChannels = batch.size  // 56
            val numDetections = (batch[0] as FloatArray).size  // 8400
            
            Log.d(TAG, "Output shape: [1, $numChannels, $numDetections]")
            
            // Transpose to [8400, 56] for easier processing
            val transposed = Array(numDetections) { FloatArray(numChannels) }
            for (c in 0 until numChannels) {
                val channelData = batch[c] as FloatArray
                for (d in 0 until numDetections) {
                    transposed[d][c] = channelData[d]
                }
            }
            
            // Process each detection
            for (i in 0 until numDetections) {
                val detection = transposed[i]
                
                // Extract confidence (channel 4)
                val confidence = detection[4]
                
                if (confidence < CONFIDENCE_THRESHOLD) continue
                
                // Extract bounding box (channels 0-3)
                val cx = detection[0]
                val cy = detection[1]
                val w = detection[2]
                val h = detection[3]
                
                // Convert from center format to corner format
                val x1 = (cx - w / 2) * imgWidth / INPUT_SIZE
                val y1 = (cy - h / 2) * imgHeight / INPUT_SIZE
                val x2 = (cx + w / 2) * imgWidth / INPUT_SIZE
                val y2 = (cy + h / 2) * imgHeight / INPUT_SIZE
                
                // Extract keypoints (channels 5-55)
                val keypoints = mutableListOf<Keypoint>()
                for (k in 0 until NUM_KEYPOINTS) {
                    val baseIdx = 5 + k * KEYPOINT_CHANNELS
                    val kx = detection[baseIdx] * imgWidth / INPUT_SIZE
                    val ky = detection[baseIdx + 1] * imgHeight / INPUT_SIZE
                    val kconf = detection[baseIdx + 2]
                    
                    val keypointType = KeypointType.fromId(k)
                    if (keypointType != null) {
                        keypoints.add(Keypoint(kx, ky, kconf, keypointType))
                    }
                }
                
                detections.add(
                    PersonDetection(
                        boundingBox = BoundingBox(x1, y1, x2, y2),
                        confidence = confidence,
                        keypoints = keypoints,
                        imageWidth = imgWidth,
                        imageHeight = imgHeight
                    )
                )
            }
            
            // Apply NMS (Non-Maximum Suppression)
            val nmsDetections = applyNMS(detections, IOU_THRESHOLD)
            Log.d(TAG, "Detections: ${detections.size} before NMS, ${nmsDetections.size} after NMS")
            
            return nmsDetections
            
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing outputs", e)
            return emptyList()
        }
    }
    
    /**
     * Apply Non-Maximum Suppression to remove overlapping detections
     */
    private fun applyNMS(detections: List<PersonDetection>, iouThreshold: Float): List<PersonDetection> {
        if (detections.isEmpty()) return emptyList()
        
        val sorted = detections.sortedByDescending { it.confidence }
        val keep = mutableListOf<PersonDetection>()
        val suppressed = BooleanArray(sorted.size)
        
        for (i in sorted.indices) {
            if (suppressed[i]) continue
            
            keep.add(sorted[i])
            val box1 = sorted[i].boundingBox
            
            for (j in i + 1 until sorted.size) {
                if (suppressed[j]) continue
                
                val box2 = sorted[j].boundingBox
                val iou = calculateIoU(box1, box2)
                
                if (iou > iouThreshold) {
                    suppressed[j] = true
                }
            }
        }
        
        return keep
    }
    
    /**
     * Calculate Intersection over Union (IoU) between two bounding boxes
     */
    private fun calculateIoU(box1: BoundingBox, box2: BoundingBox): Float {
        val x1 = max(box1.left, box2.left)
        val y1 = max(box1.top, box2.top)
        val x2 = min(box1.right, box2.right)
        val y2 = min(box1.bottom, box2.bottom)
        
        val intersection = max(0f, x2 - x1) * max(0f, y2 - y1)
        val area1 = (box1.right - box1.left) * (box1.bottom - box1.top)
        val area2 = (box2.right - box2.left) * (box2.bottom - box2.top)
        val union = area1 + area2 - intersection
        
        return if (union > 0) intersection / union else 0f
    }
}
