package com.example.eswproject

import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.support.common.FileUtil
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PostureClassifier(private val context: Context) {
    private var interpreter: Interpreter? = null
    private val labels = listOf("Sitting Upright", "Slouching", "Neck Bent", "Leaning Left", "Leaning Right")

    fun load(modelAssetPath: String = "MODEL/posture_classifier.tflite"): Boolean = try {
        val buffer = FileUtil.loadMappedFile(context, modelAssetPath)
        interpreter = Interpreter(buffer)
        true
    } catch (e: Exception) {
        Log.e("PostureClassifier", "Model load failed: ${e.message}")
        false
    }

    fun classify(person: PersonDetection): Pair<String, Float> {
        val kp = person.keypoints.sortedBy { it.type.id }
        if (kp.size < 17) return "Unknown" to 0f
        val minX = kp.minOf { it.x }; val maxX = kp.maxOf { it.x }
        val minY = kp.minOf { it.y }; val maxY = kp.maxOf { it.y }
        val width = (maxX - minX).coerceAtLeast(1f); val height = (maxY - minY).coerceAtLeast(1f)
        val floats = FloatArray(34)
        kp.forEachIndexed { idx, k ->
            floats[idx * 2] = (k.x - minX) / width
            floats[idx * 2 + 1] = (k.y - minY) / height
        }
        val input = ByteBuffer.allocateDirect(floats.size * 4).order(ByteOrder.nativeOrder())
        floats.forEach { input.putFloat(it) }; input.rewind()
        val output = Array(1) { FloatArray(labels.size) }
        interpreter?.run(input, output)
        val probs = output[0]
        val best = probs.withIndex().maxByOrNull { it.value } ?: return "Unknown" to 0f
        return labels[best.index] to best.value
    }
}
