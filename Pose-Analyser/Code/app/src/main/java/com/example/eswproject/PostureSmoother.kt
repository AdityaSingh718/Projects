package com.example.eswproject

/**
 * Temporal smoothing for posture labels to reduce flicker.
 * Maintains a fixed-size circular buffer of recent (label, confidence) entries.
 * Produces a stable label via weighted vote. If top label weight margin small, keeps previous.
 */
class PostureSmoother(private val window: Int = 8) {
    private data class Entry(val label: String, val confidence: Float)
    private val buffer = ArrayDeque<Entry>()
    private var lastStable: String? = null

    fun add(label: String, confidence: Float) {
        if (label.equals("unknown", true)) return

        // Stability enhancement: require higher confidence for switching between similar postures
        val similarPostures = mapOf(
            "straight" to listOf("recline", "hunchback"),
            "recline" to listOf("straight", "hunchback"),
            "hunchback" to listOf("straight", "recline", "neck_bent"),
            "neck_bent" to listOf("hunchback", "neck_down"),
            "neck_down" to listOf("neck_bent")
        )
        val normalizedLabel = label.lowercase().replace(" ", "_")
        val normalizedStable = lastStable?.lowercase()?.replace(" ", "_")

        val isSimilar = normalizedStable != null &&
            similarPostures[normalizedStable]?.contains(normalizedLabel) == true

        val adjustedConfidence = if (isSimilar) {
            // Require higher confidence to switch between similar postures
            confidence * 0.75f
        } else {
            confidence
        }

        buffer.addLast(Entry(label, adjustedConfidence.coerceIn(0f, 1f)))
        while (buffer.size > window) buffer.removeFirst()
    }

    fun current(): String? {
        if (buffer.isEmpty()) return lastStable
        val weightMap = mutableMapOf<String, Float>()
        buffer.forEachIndexed { idx, e ->
            // Slight recency weighting (newer frames more weight)
            val recency = (idx + 1f) / buffer.size
            weightMap[e.label] = (weightMap[e.label] ?: 0f) + e.confidence * recency
        }
        val sorted = weightMap.entries.sortedByDescending { it.value }
        if (sorted.isEmpty()) return lastStable
        val top = sorted[0]
        val second = sorted.getOrNull(1)
        val margin = if (second == null) Float.MAX_VALUE else top.value - second.value
        // Require larger margin to switch, especially for similar postures
        val candidate = top.key
        val candidateCanonical = candidate.lowercase().replace(" ", "_")
        val stableCanonical = lastStable?.lowercase()?.replace(" ", "_")
        val similarCluster = setOf("straight", "recline", "hunchback")
        val minMargin = if (stableCanonical != null &&
            similarCluster.contains(stableCanonical) && similarCluster.contains(candidateCanonical)) {
            0.35f // Higher threshold for very similar postures
        } else {
            0.2f // Standard threshold
        }

        val shouldSwitch = lastStable == null || lastStable == candidate || margin > minMargin
        if (shouldSwitch) lastStable = candidate
        return lastStable
    }

    fun reset() { buffer.clear(); lastStable = null }
}
