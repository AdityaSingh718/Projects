package com.example.eswproject

import kotlin.math.*

/**
 * ML-based posture classifier that replicates the Python model's feature extraction
 * and classification logic. Uses the same 3-angle feature extraction as the trained model.
 */
class MLPostureClassifier {
    
    // These are the posture classes from your trained model
    private val postureClasses = arrayOf(
        "straight", "hunchback", "neck_bent", "recline", "neck_down"
        // Add other classes as they appear in your dataset
    )
    
    /**
     * Calculates the angle between three points in 2D space
     * Replicates the calculate_angle function from create_dataset.py
     */
    private fun calculateAngle(a: Pair<Float, Float>, b: Pair<Float, Float>, c: Pair<Float, Float>): Double {
        val ba = Pair(a.first - b.first, a.second - b.second)
        val bc = Pair(c.first - b.first, c.second - b.second)
        
        val dotProduct = ba.first * bc.first + ba.second * bc.second
        val magnitudeBA = sqrt(ba.first * ba.first + ba.second * ba.second)
        val magnitudeBC = sqrt(bc.first * bc.first + bc.second * bc.second)
        
        val cosineAngle = (dotProduct / (magnitudeBA * magnitudeBC + 1e-6)).coerceIn(-1.0, 1.0)
        val angle = acos(cosineAngle)
        
        return Math.toDegrees(angle)
    }
    
    /**
     * Extracts the 3 key features from keypoints that match your Python model
     */
    private fun extractFeatures(person: PersonDetection): Triple<Double, Double, Double>? {
        val keypoints = person.keypoints.associateBy { it.type }
        
        // Extract right-side keypoints (matching your Python model)
        val rightEar = keypoints[KeypointType.RIGHT_EAR]
        val rightShoulder = keypoints[KeypointType.RIGHT_SHOULDER]
        val rightHip = keypoints[KeypointType.RIGHT_HIP]
        val rightKnee = keypoints[KeypointType.RIGHT_KNEE]
        val rightAnkle = keypoints[KeypointType.RIGHT_ANKLE]
        
        // Check if all required keypoints are available
        if (listOf(rightEar, rightShoulder, rightHip, rightKnee, rightAnkle).any { it == null }) {
            return null
        }
        
        // Convert to coordinate pairs
        val earCoords = Pair(rightEar!!.x, rightEar.y)
        val shoulderCoords = Pair(rightShoulder!!.x, rightShoulder.y)
        val hipCoords = Pair(rightHip!!.x, rightHip.y)
        val kneeCoords = Pair(rightKnee!!.x, rightKnee.y)
        val ankleCoords = Pair(rightAnkle!!.x, rightAnkle.y)
        
        // Calculate the 3 angles exactly as in your Python model
        // 1. Knee angle: Ankle-Knee-Hip
        val kneeAngle = calculateAngle(ankleCoords, kneeCoords, hipCoords)
        
        // 2. Torso-Hip angle: Knee-Hip-Shoulder  
        val torsoHipAngle = calculateAngle(kneeCoords, hipCoords, shoulderCoords)
        
        // 3. Neck-Torso angle: Hip-Shoulder-Ear
        val neckTorsoAngle = calculateAngle(hipCoords, shoulderCoords, earCoords)
        
        return Triple(kneeAngle, torsoHipAngle, neckTorsoAngle)
    }
    
    /**
     * Classification using actual dataset feature ranges
     * Based on analysis of your posture_dataset_final.csv
     */
    private fun classifyFromFeatures(kneeAngle: Double, torsoHipAngle: Double, neckTorsoAngle: Double): String {
        // Calculate confidence scores for each posture class based on actual data ranges
        val straightScore = calculatePostureScore("straight", kneeAngle, torsoHipAngle, neckTorsoAngle)
        val reclineScore = calculatePostureScore("recline", kneeAngle, torsoHipAngle, neckTorsoAngle)
        val hunchbackScore = calculatePostureScore("hunchback", kneeAngle, torsoHipAngle, neckTorsoAngle)
        val neckBentScore = calculatePostureScore("neck_bent", kneeAngle, torsoHipAngle, neckTorsoAngle)
        val neckDownScore = calculatePostureScore("neck_down", kneeAngle, torsoHipAngle, neckTorsoAngle)
        
        // Find the posture with highest score, but require minimum confidence to avoid fluctuation
        val scores = mapOf(
            "straight" to straightScore,
            "recline" to reclineScore,
            "hunchback" to hunchbackScore,
            "neck_bent" to neckBentScore,
            "neck_down" to neckDownScore
        )
        
        val bestMatch = scores.maxByOrNull { it.value }
        return if (bestMatch != null && bestMatch.value > 0.3) {
            bestMatch.key
        } else {
            "unknown"
        }
    }
    
    /**
     * Calculate how well the features match a specific posture based on dataset statistics
     */
    private fun calculatePostureScore(posture: String, kneeAngle: Double, torsoHipAngle: Double, neckTorsoAngle: Double): Double {
        return when (posture) {
            "straight" -> {
                // Dataset ranges: knee 87-105°, torso 87-104°, neck 141-155°
                val kneeScore = if (kneeAngle in 85.0..107.0) 1.0 - abs(kneeAngle - 96.0) / 15.0 else 0.0
                val torsoScore = if (torsoHipAngle in 85.0..106.0) 1.0 - abs(torsoHipAngle - 95.5) / 12.0 else 0.0
                val neckScore = if (neckTorsoAngle in 140.0..157.0) 1.0 - abs(neckTorsoAngle - 148.0) / 10.0 else 0.0
                (kneeScore + torsoScore + neckScore) / 3.0
            }
            "recline" -> {
                // Dataset ranges: knee 109-167°, torso 111-150°, neck 113-157°
                val kneeScore = if (kneeAngle in 105.0..170.0) 1.0 - abs(kneeAngle - 130.0) / 25.0 else 0.0
                val torsoScore = if (torsoHipAngle in 108.0..155.0) 1.0 - abs(torsoHipAngle - 125.0) / 20.0 else 0.0
                val neckScore = if (neckTorsoAngle in 110.0..160.0) 1.0 - abs(neckTorsoAngle - 135.0) / 20.0 else 0.0
                (kneeScore + torsoScore + neckScore) / 3.0
            }
            "hunchback" -> {
                // Dataset ranges: knee 106-115°, torso 77-91°, neck 134-141°
                val kneeScore = if (kneeAngle in 104.0..118.0) 1.0 - abs(kneeAngle - 111.0) / 8.0 else 0.0
                val torsoScore = if (torsoHipAngle in 75.0..93.0) 1.0 - abs(torsoHipAngle - 84.0) / 8.0 else 0.0
                val neckScore = if (neckTorsoAngle in 132.0..143.0) 1.0 - abs(neckTorsoAngle - 137.5) / 6.0 else 0.0
                (kneeScore + torsoScore + neckScore) / 3.0
            }
            "neck_bent" -> {
                // Dataset ranges: knee 95-116°, torso 64-89°, neck 135-145°
                val kneeScore = if (kneeAngle in 93.0..118.0) 1.0 - abs(kneeAngle - 105.0) / 12.0 else 0.0
                val torsoScore = if (torsoHipAngle in 60.0..92.0) 1.0 - abs(torsoHipAngle - 76.0) / 15.0 else 0.0
                val neckScore = if (neckTorsoAngle in 133.0..147.0) 1.0 - abs(neckTorsoAngle - 140.0) / 7.0 else 0.0
                (kneeScore + torsoScore + neckScore) / 3.0
            }
            "neck_down" -> {
                // Dataset ranges: knee 92-107°, torso 62-82°, neck 128-140°
                val kneeScore = if (kneeAngle in 90.0..109.0) 1.0 - abs(kneeAngle - 99.5) / 10.0 else 0.0
                val torsoScore = if (torsoHipAngle in 60.0..84.0) 1.0 - abs(torsoHipAngle - 72.0) / 12.0 else 0.0
                val neckScore = if (neckTorsoAngle in 126.0..142.0) 1.0 - abs(neckTorsoAngle - 134.0) / 8.0 else 0.0
                (kneeScore + torsoScore + neckScore) / 3.0
            }
            else -> 0.0
        }.coerceIn(0.0, 1.0)
    }
    
    /**
     * Classifies posture from a PersonDetection object
     * Returns pair of (posture_label, confidence)
     */
    fun classify(person: PersonDetection): Pair<String, Float> {
        val features = extractFeatures(person) ?: return Pair("unknown", 0.0f)
        
        val (kneeAngle, torsoHipAngle, neckTorsoAngle) = features
        val posture = classifyFromFeatures(kneeAngle, torsoHipAngle, neckTorsoAngle)
        
        // Get the confidence score that was already calculated during classification
        val confidence = if (posture != "unknown") {
            calculatePostureScore(posture, kneeAngle, torsoHipAngle, neckTorsoAngle).toFloat()
        } else {
            0.0f
        }
        
        return Pair(posture, confidence)
    }
    
    /**
     * Get dynamic posture score (0-100) based on how well features match ideal ranges
     */
    fun getPostureScore(person: PersonDetection): Int {
        val features = extractFeatures(person) ?: return 60
        val (kneeAngle, torsoHipAngle, neckTorsoAngle) = features
        val posture = classifyFromFeatures(kneeAngle, torsoHipAngle, neckTorsoAngle)
        
        if (posture == "unknown") return 60
        
        val confidence = calculatePostureScore(posture, kneeAngle, torsoHipAngle, neckTorsoAngle)
        
        // Convert confidence to score based on posture type
        return when (posture) {
            "straight" -> (85 + confidence * 15).toInt() // 85-100 for straight
            "recline" -> (65 + confidence * 15).toInt()  // 65-80 for recline
            "hunchback" -> (45 + confidence * 15).toInt() // 45-60 for hunchback
            "neck_bent" -> (55 + confidence * 15).toInt() // 55-70 for neck bent
            "neck_down" -> (40 + confidence * 15).toInt() // 40-55 for neck down
            else -> 60
        }
    }
    

    
    /**
     * Debug method to get the raw feature values
     */
    fun getFeatures(person: PersonDetection): Map<String, Double>? {
        val features = extractFeatures(person) ?: return null
        return mapOf(
            "knee_angle" to features.first,
            "torso_hip_angle" to features.second,
            "neck_torso_angle" to features.third
        )
    }
}