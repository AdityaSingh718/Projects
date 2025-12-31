package com.example.eswproject

/**
 * Runtime execution provider for ONNX inference
 * Supports CPU, GPU (NNAPI), and NPU (NNAPI) acceleration
 */
enum class RuntimeProvider(val displayName: String, val onnxProviderName: String) {
    CPU("CPU", "CPUExecutionProvider"),
    GPU_NNAPI("GPU (NNAPI)", "NnapiExecutionProvider"),
    NPU_NNAPI("NPU (NNAPI)", "NnapiExecutionProvider"); // NPU uses NNAPI with specific device selection
    
    companion object {
        fun fromDisplayName(name: String): RuntimeProvider? {
            return values().find { it.displayName == name }
        }
    }
}

/**
 * Performance metrics for pose detection
 * Tracks latency and FPS for real-time monitoring
 */
data class PerformanceMetrics(
    val latencyMs: Long = 0L,
    val fps: Float = 0f,
    val runtimeProvider: RuntimeProvider = RuntimeProvider.CPU,
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        /**
         * Calculate FPS from a window of inference times
         */
        fun calculateFPS(inferenceTimesMs: List<Long>): Float {
            if (inferenceTimesMs.isEmpty()) return 0f
            val avgInferenceTimeMs = inferenceTimesMs.average()
            return if (avgInferenceTimeMs > 0) {
                (1000.0 / avgInferenceTimeMs).toFloat()
            } else {
                0f
            }
        }
    }
}

/**
 * Tracks performance metrics over a sliding window
 */
class PerformanceTracker(private val windowSize: Int = 10) {
    private val inferenceTimesMs = mutableListOf<Long>()
    
    /**
     * Add a new inference time measurement
     */
    fun addInferenceTime(timeMs: Long) {
        inferenceTimesMs.add(timeMs)
        if (inferenceTimesMs.size > windowSize) {
            inferenceTimesMs.removeAt(0)
        }
    }
    
    /**
     * Get current performance metrics
     */
    fun getMetrics(runtimeProvider: RuntimeProvider): PerformanceMetrics {
        if (inferenceTimesMs.isEmpty()) {
            return PerformanceMetrics(runtimeProvider = runtimeProvider)
        }
        
        val latencyMs = inferenceTimesMs.lastOrNull() ?: 0L
        val fps = PerformanceMetrics.calculateFPS(inferenceTimesMs)
        
        return PerformanceMetrics(
            latencyMs = latencyMs,
            fps = fps,
            runtimeProvider = runtimeProvider
        )
    }
    
    /**
     * Reset the performance tracker
     */
    fun reset() {
        inferenceTimesMs.clear()
    }
}
