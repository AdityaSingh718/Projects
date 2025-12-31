package com.example.eswproject

import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.max
import kotlin.math.min

object PostureHeuristics {

    data class Result(val label: String, val confidence: Float)

    fun derive(person: PersonDetection): String = deriveWithScore(person).label

    fun deriveWithScore(person: PersonDetection): Result {
        val m = person.keypoints.associateBy { it.type }
        val nose = m[KeypointType.NOSE]
        val ls = m[KeypointType.LEFT_SHOULDER]
        val rs = m[KeypointType.RIGHT_SHOULDER]
        val lh = m[KeypointType.LEFT_HIP]
        val rh = m[KeypointType.RIGHT_HIP]
        if (listOf(nose, ls, rs, lh, rh).any { it == null }) return Result("unknown", 0f)

        val shoulderCenterX = (ls!!.x + rs!!.x) / 2f
        val shoulderCenterY = (ls.y + rs.y) / 2f
        val hipCenterX = (lh!!.x + rh!!.x) / 2f
        val hipCenterY = (lh.y + rh.y) / 2f

        val torsoAngle = angleDeg(hipCenterX, hipCenterY, shoulderCenterX, shoulderCenterY) // 90 ~= upright
        val headForwardPx = nose!!.x - shoulderCenterX
        val headDropPx = nose.y - shoulderCenterY
        val shoulderWidth = distance(ls.x, ls.y, rs.x, rs.y).coerceAtLeast(1f)
        val torsoLength = distance(shoulderCenterX, shoulderCenterY, hipCenterX, hipCenterY).coerceAtLeast(1f)

        // Normalize by geometric measures to be robust to scale
        val headForward = headForwardPx / shoulderWidth
        val headDrop = headDropPx / torsoLength
        val torsoDeviation = (torsoAngle - 90f) // +ve leaning forward, -ve backward if coordinate origin top-left
        val torsoDeviationAbs = abs(torsoDeviation)
        val headForwardAbs = abs(headForward)
        val headBehind = headForward < -0.2f
        val forwardTorsoLean = torsoDeviation < -8f && !headBehind

        // Feature heuristics thresholds (empirical)
        // Straight: small forward bend & head offsets
        val straightCond = torsoDeviationAbs <= 18f && headForwardAbs <= 0.5f && headDrop in -0.1f..1.0f &&
            (torsoDeviationAbs <= 10f || headForwardAbs <= 0.35f)
        val neckDownCond = headDrop > 1.05f && headForwardAbs < 0.65f
        val neckBentCond = headForwardAbs >= 0.6f && headDrop < 1.3f
        val reclineCond = torsoDeviation < -18f && headDrop <= 0.3f && headBehind
        val forwardFoldDown = forwardTorsoLean && headDrop > 0.7f
        val forwardFoldBent = forwardTorsoLean && headDrop in 0.4f..0.7f
        val hunchCond = torsoDeviation > 16f || (headForward > 0.4f && headDrop in 0.4f..1.5f)

        val label = when {
            straightCond -> "straight"
            reclineCond -> "recline"
            neckDownCond || forwardFoldDown -> "neck down"
            neckBentCond || forwardFoldBent -> "neck bent"
            hunchCond -> "hunchback"
            else -> "hunchback"
        }

        // Confidence: ratio of distance to nearest conflicting threshold
        val straightConfidence = listOf(
            1f - (torsoDeviationAbs / 18f).coerceIn(0f, 1f),
            1f - (headForwardAbs / 0.5f).coerceIn(0f, 1f),
            1f - (abs(headDrop - 0.4f) / 0.9f).coerceIn(0f, 1f)
        ).average().toFloat()
        val rawConf = when (label) {
            "straight" -> straightConfidence
            "recline" -> ((-torsoDeviation - 18f) / 12f).coerceIn(0f,1f)
            "neck down" -> ((headDrop - 0.7f) / 1.3f).coerceIn(0f,1f)
            "neck bent" -> ((headForwardAbs - 0.5f) / 0.9f).coerceIn(0f,1f)
            "hunchback" -> (max(headForward - 0.4f, torsoDeviation - 16f) / 18f).coerceIn(0f,1f)
            else -> 0f
        }
        return Result(label, rawConf)
    }

    fun scoreFor(label: String): Int = when (label) {
        "straight" -> 95
        "hunchback" -> 55
        "neck_bent", "neck bent" -> 65
        "neck_down", "neck down" -> 50
        "recline" -> 75
        else -> 60
    }

    private fun angleDeg(x1: Float, y1: Float, x2: Float, y2: Float): Float {
        val dy = y1 - y2
        val dx = x2 - x1
        val rad = atan2(dy, dx)
        var deg = Math.toDegrees(rad.toDouble()).toFloat()
        if (deg < 0) deg += 360f
        return deg
    }

    private fun distance(x1: Float, y1: Float, x2: Float, y2: Float): Float {
        val dx = x2 - x1
        val dy = y2 - y1
        return kotlin.math.sqrt(dx * dx + dy * dy)
    }
}