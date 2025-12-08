package com.example.eswproject

import android.util.Log
import kotlin.math.*

/**
 * Advanced Posture Detector with Calibration Support
 * 
 * Based on posture_corrector.py from Model folder:
 * - Supports personalized calibration (reference posture)
 * - Calculates posture score (0-100) like Python version
 * - Uses tolerance-based ranges instead of fixed thresholds
 * - Optimized for minimal latency
 */
class PostureDetector(
    private val confidenceThreshold: Float = 0.75f
) {
    
    companion object {
        private const val TAG = "PostureDetector"
        
        // COCO Keypoint indices for right side (matching YOLO model)
        private const val RIGHT_EAR = 4
        private const val RIGHT_SHOULDER = 6
        private const val RIGHT_HIP = 12
        private const val RIGHT_KNEE = 14
        private const val RIGHT_ANKLE = 16
        
        // COCO Keypoint indices for left side (matching YOLO model)
        private const val LEFT_EAR = 3
        private const val LEFT_SHOULDER = 5
        private const val LEFT_HIP = 11
        private const val LEFT_KNEE = 13
        private const val LEFT_ANKLE = 15
        
        // Tolerance for acceptable posture range (from posture_corrector.py)
        private const val NECK_TOLERANCE = 8.0
        private const val BACK_TOLERANCE = 8.0
        private const val LEGS_TOLERANCE = 8.0
        
        // Angle weights for scoring (from posture_corrector.py)
        private const val NECK_WEIGHT = 1.0
        private const val BACK_WEIGHT = 1.5
        private const val LEGS_WEIGHT = 0.5
        
        // Dataset angle limits (from posture_corrector.py)
        private val ANGLE_LIMITS = mapOf(
            "neck" to Pair(125.19, 178.45),
            "back" to Pair(59.70, 145.25),
            "legs" to Pair(86.13, 164.73)
        )
    }
    
    // Ideal posture angles (can be calibrated)
    private var idealNeckAngle = 165.0  // Default from training data
    private var idealBackAngle = 175.0
    private var idealLegsAngle = 170.0
    private var maxDeviationThreshold = 0.0
    
    init {
        // Calculate max deviation threshold on initialization
        maxDeviationThreshold = computeMaxDeviationThreshold()
    }
    
    /**
     * Calibrate the detector with a reference "good" posture
     * Call this when user is in their ideal sitting position
     */
    fun calibrate(neckAngle: Double, backAngle: Double, legsAngle: Double) {
        idealNeckAngle = neckAngle
        idealBackAngle = backAngle
        idealLegsAngle = legsAngle
        maxDeviationThreshold = computeMaxDeviationThreshold()
        Log.i(TAG, "Calibrated: Neck=${"%.1f".format(neckAngle)}°, " +
                   "Back=${"%.1f".format(backAngle)}°, " +
                   "Legs=${"%.1f".format(legsAngle)}°")
    }
    
    /**
     * Reset to default calibration values
     */
    fun resetToDefaults() {
        idealNeckAngle = 165.0
        idealBackAngle = 175.0
        idealLegsAngle = 170.0
        maxDeviationThreshold = computeMaxDeviationThreshold()
        Log.i(TAG, "Reset to default calibration")
    }
    
    /**
     * Get current calibration values
     */
    fun getCalibrationValues(): Triple<Double, Double, Double> {
        return Triple(idealNeckAngle, idealBackAngle, idealLegsAngle)
    }
    
    /**
     * Compute max deviation threshold (from posture_corrector.py)
     */
    private fun computeMaxDeviationThreshold(): Double {
        var maxDeviation = 0.0
        
        val angles = mapOf(
            "neck" to idealNeckAngle,
            "back" to idealBackAngle,
            "legs" to idealLegsAngle
        )
        
        val weights = mapOf(
            "neck" to NECK_WEIGHT,
            "back" to BACK_WEIGHT,
            "legs" to LEGS_WEIGHT
        )
        
        for ((region, idealAngle) in angles) {
            val weight = weights[region] ?: 1.0
            val (minAngle, maxAngle) = ANGLE_LIMITS[region] ?: continue
            
            val worstAngle = if (abs(minAngle - idealAngle) > abs(maxAngle - idealAngle)) {
                minAngle
            } else {
                maxAngle
            }
            
            val worstDiff = abs(worstAngle - idealAngle)
            maxDeviation += weight * (worstDiff * worstDiff)
        }
        
        return maxDeviation
    }
    
    /**
     * Calculates the angle between three points in 2D space.
     * This is the EXACT SAME function as calculate_angle() in Python Model folder.
     * 
     * Formula: angle at point b formed by points a-b-c
     * @param a First point [x, y]
     * @param b Vertex point [x, y]
     * @param c Third point [x, y]
     * @return Angle in degrees
     */
    private fun calculateAngle(a: FloatArray, b: FloatArray, c: FloatArray): Double {
        // Vector from b to a
        val baX = a[0] - b[0]
        val baY = a[1] - b[1]
        
        // Vector from b to c
        val bcX = c[0] - b[0]
        val bcY = c[1] - b[1]
        
        // Dot product
        val dotProduct = (baX * bcX + baY * bcY).toDouble()
        
        // Magnitudes
        val magnitudeBa = sqrt((baX * baX + baY * baY).toDouble())
        val magnitudeBc = sqrt((bcX * bcX + bcY * bcY).toDouble())
        
        // Cosine of angle (with small epsilon to avoid division by zero)
        val cosineAngle = dotProduct / (magnitudeBa * magnitudeBc + 1e-6)
        
        // Clip to [-1.0, 1.0] to avoid numerical errors in acos
        val clippedCosine = cosineAngle.coerceIn(-1.0, 1.0)
        
        // Return angle in degrees
        val angleRadians = acos(clippedCosine)
        return Math.toDegrees(angleRadians)
    }
    
    /**
     * Extracts features and classifies posture from YOLO keypoints.
     * Uses EXACT SAME logic as create_dataset.py and run_live_model.py
     * 
     * @param persons List of detected persons with keypoints from YOLOv11
     * @return Posture classification result
     */
    fun analyzePosture(persons: List<PersonDetection>): PostureResult {
        if (persons.isEmpty()) {
            return PostureResult(
                posture = "NO_PERSON",
                confidence = 0.0f,
                angles = null,
                message = "No persons detected",
                score = 0,
                suggestions = emptyList()
            )
        }
        
        // Use first detected person (same as Python: data['persons'][0])
        val person = persons[0]
        val keypoints = person.keypoints
        
        // --- SIDE SELECTION LOGIC (matching Python personalized_posture_detector.py) ---
        // Compare left ear vs right ear confidence to determine which side is more visible
        val leftEarConf = if (LEFT_EAR < keypoints.size) keypoints[LEFT_EAR].confidence else 0f
        val rightEarConf = if (RIGHT_EAR < keypoints.size) keypoints[RIGHT_EAR].confidence else 0f
        
        // Select side with higher ear confidence
        val useLeftSide = leftEarConf >= rightEarConf
        val sideName = if (useLeftSide) "left" else "right"
        
        Log.d(TAG, "Side selection: left_ear_conf=${"%.2f".format(leftEarConf)}, " +
                   "right_ear_conf=${"%.2f".format(rightEarConf)}, selected=$sideName")
        
        // Set keypoint indices based on selected side
        val earIdx = if (useLeftSide) LEFT_EAR else RIGHT_EAR
        val shoulderIdx = if (useLeftSide) LEFT_SHOULDER else RIGHT_SHOULDER
        val hipIdx = if (useLeftSide) LEFT_HIP else RIGHT_HIP
        val kneeIdx = if (useLeftSide) LEFT_KNEE else RIGHT_KNEE
        val ankleIdx = if (useLeftSide) LEFT_ANKLE else RIGHT_ANKLE
        
        // Check confidence for all required keypoints BEFORE extracting coordinates
        val requiredKeypointTypes = listOf(earIdx, shoulderIdx, hipIdx, kneeIdx, ankleIdx)
        
        // Calculate confidence as the MINIMUM of required keypoints
        // This is the same value used for filtering decisions
        val requiredKeypointConfidences = requiredKeypointTypes.mapNotNull { index ->
            if (index < keypoints.size) keypoints[index].confidence else null
        }
        val filteringConfidence = if (requiredKeypointConfidences.isNotEmpty()) {
            requiredKeypointConfidences.minOrNull() ?: 0f
        } else {
            0f // No valid keypoints found
        }
        
        // Use the minimum confidence for filtering decision - simple and consistent
        // If minimum is below threshold, at least one required keypoint is unreliable
        if (filteringConfidence < confidenceThreshold) {
            // Log which keypoints are low for debugging
            val lowConfidenceKeypoints = requiredKeypointTypes.mapNotNull { index ->
                if (index < keypoints.size) {
                    val kp = keypoints[index]
                    if (kp.confidence < confidenceThreshold) {
                        val keypointName = when (index) {
                            earIdx -> "${sideName}_ear"
                            shoulderIdx -> "${sideName}_shoulder"
                            hipIdx -> "${sideName}_hip"
                            kneeIdx -> "${sideName}_knee"
                            ankleIdx -> "${sideName}_ankle"
                            else -> "keypoint_$index"
                        }
                        "$keypointName (${"%.2f".format(kp.confidence)})"
                    } else null
                } else null
            }
            
            Log.d(TAG, "Low confidence keypoints: ${lowConfidenceKeypoints.joinToString(", ")}, " +
                       "min_conf=${"%.2f".format(filteringConfidence)}, threshold=${"%.2f".format(confidenceThreshold)}")
            
            return PostureResult(
                posture = "LOW_CONFIDENCE",
                confidence = filteringConfidence.coerceIn(0f, 1f),
                angles = null,
                message = "Full body not visible",
                score = 0,
                suggestions = listOf("Move back to show your full body", "Ensure good lighting", "Face the camera directly")
            )
        }
        
        // Extract keypoints from selected side
        val ear = getKeypointCoords(keypoints, earIdx)
        val shoulder = getKeypointCoords(keypoints, shoulderIdx)
        val hip = getKeypointCoords(keypoints, hipIdx)
        val knee = getKeypointCoords(keypoints, kneeIdx)
        val ankle = getKeypointCoords(keypoints, ankleIdx)
        
        // Check if all required keypoints are present
        if (ear == null || shoulder == null || hip == null || 
            knee == null || ankle == null) {
            val missing = mutableListOf<String>()
            if (ear == null) missing.add("${sideName}_ear")
            if (shoulder == null) missing.add("${sideName}_shoulder")
            if (hip == null) missing.add("${sideName}_hip")
            if (knee == null) missing.add("${sideName}_knee")
            if (ankle == null) missing.add("${sideName}_ankle")
            
            return PostureResult(
                posture = "INCOMPLETE",
                confidence = filteringConfidence.coerceIn(0f, 1f),
                angles = null,
                message = "Missing keypoints: ${missing.joinToString(", ")}",
                score = 0,
                suggestions = listOf("Ensure your full body is visible", "Adjust camera angle")
            )
        }
        
        // --- CALCULATE THE THREE ANGLES (exact same as Python) ---
        
        // 1. Legs angle (Ankle-Knee-Hip)
        val legsAngle = calculateAngle(ankle, knee, hip)
        
        // 2. Back angle (Knee-Hip-Shoulder)
        val backAngle = calculateAngle(knee, hip, shoulder)
        
        // 3. Neck angle (Hip-Shoulder-Ear)
        val neckAngle = calculateAngle(hip, shoulder, ear)
        
        val angles = PostureAngles(
            neckAngle = neckAngle,
            backAngle = backAngle,
            legsAngle = legsAngle
        )
        
        // Calculate posture score (0-100) using Python's method
        val postureScore = calculatePostureScore(neckAngle, backAngle, legsAngle)
        
        // Classify posture with tolerance-based ranges
        val classification = classifyPostureWithTolerance(neckAngle, backAngle, legsAngle, postureScore)
        
        return PostureResult(
            posture = classification.first,
            confidence = filteringConfidence.coerceIn(0f, 1f),
            score = postureScore.toInt(),
            angles = angles,
            message = classification.second,
            suggestions = classification.third
        )
    }
    
    /**
     * Calculate posture score (0-100) exactly like posture_corrector.py
     */
    private fun calculatePostureScore(neckAngle: Double, backAngle: Double, legsAngle: Double): Double {
        // Calculate squared errors
        val neckError = (neckAngle - idealNeckAngle).pow(2)
        val backError = (backAngle - idealBackAngle).pow(2)
        val legsError = (legsAngle - idealLegsAngle).pow(2)
        
        // Weighted total deviation
        val totalDeviation = (NECK_WEIGHT * neckError +
                             BACK_WEIGHT * backError +
                             LEGS_WEIGHT * legsError)
        
        // Avoid division by zero
        if (maxDeviationThreshold == 0.0) {
            return if (totalDeviation == 0.0) 100.0 else 0.0
        }
        
        // Calculate score percentage
        val scorePercentage = 1.0 - (totalDeviation / maxDeviationThreshold)
        return (scorePercentage * 100.0).coerceIn(0.0, 100.0)
    }
    
    /**
     * Classify posture using tolerance-based ranges (from posture_corrector.py)
     * Returns: Triple(posture_label, message, suggestions_list)
     * Uses EXACT messages from Python script
     */
    private fun classifyPostureWithTolerance(
        neckAngle: Double,
        backAngle: Double,
        legsAngle: Double,
        score: Double
    ): Triple<String, String, List<String>> {
        
        val suggestions = mutableListOf<String>()
        var neckStatus = "GOOD"
        var backStatus = "GOOD"
        var legsStatus = "GOOD"
        
        // Check neck angle - EXACT messages from Python
        when {
            neckAngle < idealNeckAngle - NECK_TOLERANCE -> {
                suggestions.add("FIX: Your neck is bent too far forward. Tuck your chin in.")
                neckStatus = "BAD"
            }
            neckAngle > idealNeckAngle + NECK_TOLERANCE -> {
                suggestions.add("FIX: Avoid tilting your head too far back.")
                neckStatus = "BAD"
            }
        }
        
        // Check back angle - EXACT messages from Python
        when {
            backAngle < idealBackAngle - BACK_TOLERANCE -> {
                suggestions.add("FIX: You are slouching. Sit up straight and engage your core.")
                backStatus = "BAD"
            }
            backAngle > idealBackAngle + BACK_TOLERANCE -> {
                suggestions.add("FIX: You are leaning back too far. Bring your torso upright.")
                backStatus = "BAD"
            }
        }
        
        // Check legs angle - EXACT messages from Python
        when {
            legsAngle < idealLegsAngle - LEGS_TOLERANCE -> {
                suggestions.add("FIX: Your knees are too bent. Lower your feet or raise your chair.")
                legsStatus = "BAD"
            }
            legsAngle > idealLegsAngle + LEGS_TOLERANCE -> {
                suggestions.add("FIX: Your legs are too extended. Place your feet flat on the floor.")
                legsStatus = "BAD"
            }
        }
        
        // Determine overall posture state using Python's classification logic
        val stateKey = Triple(neckStatus, backStatus, legsStatus)
        val (label, message) = when (stateKey) {
            Triple("GOOD", "GOOD", "GOOD") -> Pair("ALIGNED", "Aligned Posture")
            Triple("GOOD", "GOOD", "BAD") -> Pair("LEGS_MISALIGNMENT", "Legs Misalignment")
            Triple("GOOD", "BAD", "GOOD") -> Pair("BACK_MISALIGNMENT", "Back Misalignment")
            Triple("GOOD", "BAD", "BAD") -> Pair("BACK_LEGS_MISALIGNMENT", "Back & Legs Misalignment")
            Triple("BAD", "GOOD", "GOOD") -> Pair("NECK_MISALIGNMENT", "Neck Misalignment")
            Triple("BAD", "GOOD", "BAD") -> Pair("NECK_LEGS_MISALIGNMENT", "Neck & Legs Misalignment")
            Triple("BAD", "BAD", "GOOD") -> Pair("NECK_BACK_MISALIGNMENT", "Neck & Back Misalignment")
            Triple("BAD", "BAD", "BAD") -> Pair("FULL_BODY_MISALIGNMENT", "Full Body Misalignment")
            else -> Pair("UNKNOWN", "Unknown State")
        }
        
        return Triple(label, message, suggestions)
    }
    
    /**
     * Gets keypoint coordinates if confidence is sufficient.
     * Returns null if keypoint is not detected or has low confidence.
     */
    private fun getKeypointCoords(
        keypoints: List<Keypoint>,
        index: Int
    ): FloatArray? {
        if (index >= keypoints.size) return null
        val kp = keypoints[index]
        
        // Note: Confidence check commented out in Python model, so we do the same
        // But we still check if coordinates are valid
        if (kp.x == 0f && kp.y == 0f) return null
        
        return floatArrayOf(kp.x, kp.y)
    }
    
    /**
     * Data class to hold the three extracted angles
     */
    data class PostureAngles(
        val neckAngle: Double,
        val backAngle: Double,
        val legsAngle: Double
    )
    
    /**
     * Data class for posture analysis result (enhanced with score and suggestions)
     */
    data class PostureResult(
        val posture: String,
        val confidence: Float,
        val score: Int,  // 0-100 posture score
        val angles: PostureAngles?,
        val message: String,
        val suggestions: List<String>
    )
}
