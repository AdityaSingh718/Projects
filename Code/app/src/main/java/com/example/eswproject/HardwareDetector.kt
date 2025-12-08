package com.example.eswproject

import android.os.Build
import android.util.Log
import java.io.File

/**
 * Hardware detection utility for choosing optimal ML backend
 * Determines whether to use TensorFlow Lite (universal) or DLC/SNPE (Qualcomm optimized)
 */
object HardwareDetector {
    
    private const val TAG = "HardwareDetector"
    
    /**
     * Supported Qualcomm chipsets for SNPE acceleration
     */
    private val SUPPORTED_SNAPDRAGON_CHIPS = setOf(
        // Snapdragon 8 series
        "sm8550", "sm8450", "sm8350", "sm8250", "sm8150",
        // Snapdragon 7 series  
        "sm7450", "sm7350", "sm7250", "sm7150",
        // Snapdragon 6 series
        "sm6450", "sm6350", "sm6250", "sm6150"
    )
    
    /**
     * Detects if device supports Qualcomm SNPE runtime
     */
    fun isQualcommDevice(): Boolean {
        return try {
            val hardware = getHardwareInfo()
            val isQualcomm = hardware.contains("qcom") || 
                           hardware.contains("snapdragon") ||
                           isSupportedSnapdragonChip()
            
            Log.d(TAG, "Hardware: $hardware, Is Qualcomm: $isQualcomm")
            isQualcomm
        } catch (e: Exception) {
            Log.e(TAG, "Error detecting hardware", e)
            false
        }
    }
    
    /**
     * Gets hardware information from system properties
     */
    private fun getHardwareInfo(): String {
        return try {
            val hardware = Build.HARDWARE.lowercase()
            val board = Build.BOARD.lowercase()  
            val device = Build.DEVICE.lowercase()
            
            "$hardware $board $device"
        } catch (e: Exception) {
            Log.e(TAG, "Error reading hardware info", e)
            ""
        }
    }
    
    /**
     * Checks if device uses supported Snapdragon chipset
     */
    private fun isSupportedSnapdragonChip(): Boolean {
        return try {
            val socModel = getSoCModel()
            val isSupported = SUPPORTED_SNAPDRAGON_CHIPS.any { 
                socModel.contains(it, ignoreCase = true) 
            }
            
            Log.d(TAG, "SoC Model: $socModel, Is Supported: $isSupported")
            isSupported
        } catch (e: Exception) {
            Log.e(TAG, "Error checking SoC model", e)
            false
        }
    }
    
    /**
     * Attempts to read SoC model from system files
     */
    private fun getSoCModel(): String {
        val socPaths = listOf(
            "/sys/devices/soc0/soc_id",
            "/sys/devices/system/soc/soc0/id", 
            "/proc/cpuinfo"
        )
        
        for (path in socPaths) {
            try {
                val file = File(path)
                if (file.exists() && file.canRead()) {
                    val content = file.readText().lowercase()
                    if (content.isNotBlank()) {
                        return content
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Could not read from $path", e)
            }
        }
        
        return Build.HARDWARE.lowercase()
    }
    
    /**
     * Checks if SNPE runtime libraries are available
     */
    fun isSnpeRuntimeAvailable(): Boolean {
        return try {
            // Try to load SNPE native library
            System.loadLibrary("SNPE")
            Log.d(TAG, "SNPE runtime available")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "SNPE runtime not available", e)
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error checking SNPE runtime", e)
            false
        }
    }
    
    /**
     * Determines the best backend to use for ML inference
     */
    fun getRecommendedBackend(): MLBackend {
        return when {
            isQualcommDevice() && isSnpeRuntimeAvailable() -> {
                Log.i(TAG, "Using SNPE backend for optimal performance")
                MLBackend.SNPE_DLC
            }
            else -> {
                Log.i(TAG, "Using TensorFlow Lite backend for compatibility")
                MLBackend.TENSORFLOW_LITE
            }
        }
    }
    
    /**
     * Gets device performance tier for model selection
     */
    fun getPerformanceTier(): PerformanceTier {
        return when {
            isQualcommDevice() && isSnpeRuntimeAvailable() -> PerformanceTier.HIGH
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> PerformanceTier.MEDIUM
            else -> PerformanceTier.LOW
        }
    }
}

/**
 * Available ML backends
 */
enum class MLBackend {
    TENSORFLOW_LITE,  // Universal compatibility
    SNPE_DLC         // Qualcomm optimization
}

/**
 * Device performance tiers
 */
enum class PerformanceTier {
    LOW,     // Basic CPU inference
    MEDIUM,  // GPU acceleration available
    HIGH     // Dedicated NPU/DSP acceleration
}