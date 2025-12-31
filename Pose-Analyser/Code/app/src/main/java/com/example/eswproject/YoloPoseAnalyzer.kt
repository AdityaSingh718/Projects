package com.example.eswproject

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.Rect
import android.graphics.YuvImage
import android.media.Image
import android.util.Log
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import kotlin.math.max
import kotlin.math.min

/**
 * YOLOv11-based pose analyzer for camera frames
 * Replaces ML Kit with YOLOv11n-pose model for keypoint detection
 * Optimized for low latency and smooth overlay
 */
class YoloPoseAnalyzer(
    private val context: Context,
    private val onPersonsDetected: (List<PersonDetection>) -> Unit,
    private val onPerformanceUpdate: ((PerformanceMetrics) -> Unit)? = null
) : ImageAnalysis.Analyzer {

    private val yoloDetector = YoloV11PoseDetector()
    private val analyzerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    
    @Volatile private var processing = false
    @Volatile private var initialized = false
    private var frameCount = 0L
    private var lastProcessTime = 0L

    companion object {
        private const val TAG = "YoloPoseAnalyzer"
        private const val MIN_FRAME_INTERVAL_MS = 25L // ~40 FPS (ultra-aggressive optimization for minimal latency)
    }

    init {
        // Initialize YOLO model asynchronously
        analyzerScope.launch {
            try {
                Log.d(TAG, "Initializing YOLOv11n-pose detector...")
                initialized = yoloDetector.initialize(context)
                if (initialized) {
                    Log.d(TAG, "✓ YOLOv11n-pose detector ready")
                    
                    // Setup performance callback
                    yoloDetector.onPerformanceUpdate = { metrics ->
                        onPerformanceUpdate?.invoke(metrics)
                    }
                } else {
                    Log.e(TAG, "✗ Failed to initialize YOLOv11n-pose detector")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error initializing detector", e)
                initialized = false
            }
        }
    }
    
    /**
     * Get the underlying YOLO detector for runtime switching
     */
    fun getDetector(): YoloV11PoseDetector = yoloDetector

    override fun analyze(image: ImageProxy) {
        // Skip if already processing or not initialized
        if (processing || !initialized) {
            image.close()
            return
        }

        // Frame rate limiting to reduce CPU usage and improve responsiveness
        val currentTime = System.currentTimeMillis()
        if (currentTime - lastProcessTime < MIN_FRAME_INTERVAL_MS) {
            image.close()
            return
        }
        lastProcessTime = currentTime

        processing = true
        frameCount++

        try {
            // Get image rotation
            val rotationDegrees = image.imageInfo.rotationDegrees
            
            // Convert ImageProxy to Bitmap
            val bitmap = imageProxyToBitmap(image, rotationDegrees)
            
            if (bitmap != null) {
                // Run YOLOv11 detection asynchronously
                analyzerScope.launch {
                    try {
                        val result = yoloDetector.detectAndPose(bitmap)
                        
                        // Callback with detected persons (on main thread for UI updates)
                        // Using withContext for more efficient thread switching
                        kotlinx.coroutines.withContext(Dispatchers.Main) {
                            onPersonsDetected(result.persons)
                        }
                        
                        if (frameCount % 60 == 0L) { // Log every 60 frames (reduced overhead)
                            Log.d(TAG, "Detected ${result.persons.size} person(s) in ${result.inferenceTime}ms")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error during pose detection", e)
                        kotlinx.coroutines.withContext(Dispatchers.Main) {
                            onPersonsDetected(emptyList())
                        }
                    } finally {
                        bitmap.recycle()
                        processing = false
                    }
                }
            } else {
                Log.w(TAG, "Failed to convert image to bitmap")
                processing = false
                onPersonsDetected(emptyList())
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in analyze", e)
            processing = false
            onPersonsDetected(emptyList())
        } finally {
            image.close()
        }
    }

    /**
     * Convert ImageProxy to Bitmap for YOLO processing with proper rotation
     * Optimized for speed to reduce latency
     */
    private fun imageProxyToBitmap(image: ImageProxy, rotationDegrees: Int): Bitmap? {
        return try {
            val mediaImage: Image = image.image ?: return null
            
            val rawBitmap = when (image.format) {
                ImageFormat.YUV_420_888 -> {
                    // Convert YUV to RGB (reduced JPEG quality for speed)
                    val yuvImage = YuvImage(
                        imageToByteArray(mediaImage),
                        ImageFormat.NV21,
                        mediaImage.width,
                        mediaImage.height,
                        null
                    )
                    
                    val outputStream = ByteArrayOutputStream()
                    yuvImage.compressToJpeg(
                        Rect(0, 0, mediaImage.width, mediaImage.height),
                        50, // Ultra-low quality for maximum speed (still sufficient for pose detection)
                        outputStream
                    )
                    
                    val jpegData = outputStream.toByteArray()
                    val options = BitmapFactory.Options().apply {
                        inPreferredConfig = Bitmap.Config.RGB_565 // Faster than ARGB_8888, less memory
                        inSampleSize = 1 // No downsampling - YOLO needs full resolution
                        inMutable = false // Immutable for faster processing
                    }
                    BitmapFactory.decodeByteArray(jpegData, 0, jpegData.size, options)
                }
                else -> {
                    // Try to get bitmap directly
                    image.toBitmap()
                }
            }
            
            // Rotate bitmap if needed
            if (rawBitmap != null && rotationDegrees != 0) {
                val matrix = Matrix().apply {
                    postRotate(rotationDegrees.toFloat())
                }
                val rotatedBitmap = Bitmap.createBitmap(
                    rawBitmap, 0, 0,
                    rawBitmap.width, rawBitmap.height,
                    matrix, true
                )
                if (rotatedBitmap != rawBitmap) {
                    rawBitmap.recycle()
                }
                rotatedBitmap
            } else {
                rawBitmap
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error converting ImageProxy to Bitmap", e)
            null
        }
    }

    /**
     * Convert Image to byte array for YUV processing
     */
    private fun imageToByteArray(image: Image): ByteArray {
        val yBuffer = image.planes[0].buffer
        val uBuffer = image.planes[1].buffer
        val vBuffer = image.planes[2].buffer

        val ySize = yBuffer.remaining()
        val uSize = uBuffer.remaining()
        val vSize = vBuffer.remaining()

        val nv21 = ByteArray(ySize + uSize + vSize)

        yBuffer.get(nv21, 0, ySize)
        vBuffer.get(nv21, ySize, vSize)
        uBuffer.get(nv21, ySize + vSize, uSize)

        return nv21
    }

    /**
     * Release resources when done
     */
    fun release() {
        yoloDetector.release()
        Log.d(TAG, "YoloPoseAnalyzer released")
    }
    
    /**
     * Analyze a bitmap directly (for network stream or other bitmap sources)
     * Returns list of detected persons synchronously
     */
    suspend fun analyzeBitmap(bitmap: Bitmap): List<PersonDetection> {
        return if (initialized) {
            try {
                val result = yoloDetector.detectAndPose(bitmap)
                result.persons
            } catch (e: Exception) {
                Log.e(TAG, "Error analyzing bitmap", e)
                emptyList()
            }
        } else {
            emptyList()
        }
    }
}

/**
 * Extension function to convert ImageProxy to Bitmap
 * Fallback method if YUV conversion fails
 */
private fun ImageProxy.toBitmap(): Bitmap? {
    val buffer = planes[0].buffer
    val bytes = ByteArray(buffer.remaining())
    buffer.get(bytes)
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
}
