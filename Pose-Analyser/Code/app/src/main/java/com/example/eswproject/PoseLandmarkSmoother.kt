package com.example.eswproject

import kotlin.math.abs
import kotlin.math.hypot

/**
 * Lightweight temporal smoothing for pose keypoints to reduce jitter in the skeleton overlay.
 * Applies an exponential moving average per keypoint and automatically resets if tracking jumps.
 */
class PoseLandmarkSmoother(
    private val alpha: Float = 0.35f,
    private val confidenceThreshold: Float = 0.2f,
    private val resetJumpThreshold: Float = 1.25f
) {
    private data class FilterState(val x: Float, val y: Float, val confidence: Float)

    private val state: MutableMap<KeypointType, FilterState> = mutableMapOf()
    private var lastBoundingBox: BoundingBox? = null
    private var lastImageSize: Pair<Int, Int>? = null

    fun smooth(person: PersonDetection): PersonDetection {
        maybeReset(person)

        val presentTypes = mutableSetOf<KeypointType>()
        val smoothedKeypoints = person.keypoints.map { keypoint ->
            presentTypes += keypoint.type
            if (keypoint.confidence < confidenceThreshold) {
                state.remove(keypoint.type)
                keypoint
            } else {
                val previous = state[keypoint.type]
                val next = if (previous == null) {
                    FilterState(keypoint.x, keypoint.y, keypoint.confidence)
                } else {
                    val beta = 1f - alpha
                    FilterState(
                        x = alpha * keypoint.x + beta * previous.x,
                        y = alpha * keypoint.y + beta * previous.y,
                        confidence = alpha * keypoint.confidence + beta * previous.confidence
                    )
                }
                state[keypoint.type] = next
                keypoint.copy(x = next.x, y = next.y, confidence = next.confidence)
            }
        }

        // Drop filters for keypoints that disappeared this frame
        state.keys.retainAll(presentTypes)

        lastBoundingBox = person.boundingBox
        lastImageSize = person.imageWidth to person.imageHeight
        return person.copy(keypoints = smoothedKeypoints)
    }

    fun smooth(persons: List<PersonDetection>): List<PersonDetection> = persons.map { smooth(it) }

    fun reset() {
        state.clear()
        lastBoundingBox = null
        lastImageSize = null
    }

    private fun maybeReset(person: PersonDetection) {
        val dims = person.imageWidth to person.imageHeight
        if (lastImageSize != null && lastImageSize != dims) {
            reset()
            return
        }

        val previousBounds = lastBoundingBox ?: return
        val prevCenterX = (previousBounds.left + previousBounds.right) / 2f
        val prevCenterY = (previousBounds.top + previousBounds.bottom) / 2f
        val prevWidth = abs(previousBounds.right - previousBounds.left).coerceAtLeast(1f)
        val prevHeight = abs(previousBounds.bottom - previousBounds.top).coerceAtLeast(1f)

        val currentBounds = person.boundingBox
        val currentCenterX = (currentBounds.left + currentBounds.right) / 2f
        val currentCenterY = (currentBounds.top + currentBounds.bottom) / 2f
        val dx = abs(currentCenterX - prevCenterX) / prevWidth
        val dy = abs(currentCenterY - prevCenterY) / prevHeight

        val distance = hypot(dx.toDouble(), dy.toDouble()).toFloat()
        if (distance > resetJumpThreshold) {
            reset()
        }
    }
}
