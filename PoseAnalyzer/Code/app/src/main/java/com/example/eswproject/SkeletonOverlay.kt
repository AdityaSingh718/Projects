package com.example.eswproject

import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke

private val skeletonConnections = listOf(
    KeypointType.NOSE to KeypointType.LEFT_EYE,
    KeypointType.NOSE to KeypointType.RIGHT_EYE,
    KeypointType.LEFT_EYE to KeypointType.LEFT_EAR,
    KeypointType.RIGHT_EYE to KeypointType.RIGHT_EAR,
    KeypointType.LEFT_SHOULDER to KeypointType.RIGHT_SHOULDER,
    KeypointType.LEFT_SHOULDER to KeypointType.LEFT_ELBOW,
    KeypointType.LEFT_ELBOW to KeypointType.LEFT_WRIST,
    KeypointType.RIGHT_SHOULDER to KeypointType.RIGHT_ELBOW,
    KeypointType.RIGHT_ELBOW to KeypointType.RIGHT_WRIST,
    KeypointType.LEFT_SHOULDER to KeypointType.LEFT_HIP,
    KeypointType.RIGHT_SHOULDER to KeypointType.RIGHT_HIP,
    KeypointType.LEFT_HIP to KeypointType.RIGHT_HIP,
    KeypointType.LEFT_HIP to KeypointType.LEFT_KNEE,
    KeypointType.LEFT_KNEE to KeypointType.LEFT_ANKLE,
    KeypointType.RIGHT_HIP to KeypointType.RIGHT_KNEE,
    KeypointType.RIGHT_KNEE to KeypointType.RIGHT_ANKLE
)

@Composable
fun SkeletonOverlay(
    persons: List<PersonDetection>,
    modifier: Modifier = Modifier,
    pointColor: Color = Color.Cyan,
    lineColor: Color = Color.Magenta,
    fillCenter: Boolean = true, // true -> mirror PreviewView default center-crop, false -> fit (letterbox)
    showDebugInfo: Boolean = false
) {
    /*
     * We receive keypoints in the sensor image coordinate space (width=imageWidth, height=imageHeight)
     * PreviewView may apply a center-crop or letterbox depending on its scale type. By default without
     * specifying scale type it behaves similar to FILL_CENTER. To robustly align, compute a uniform scale
     * that fits the camera buffer into the canvas while preserving aspect ratio, then center it and apply
     * offset. This assumes keypoints not yet rotated after ML Kit (we already used rotation in InputImage).
     */
    Canvas(modifier = modifier) {
        persons.forEach { person ->
            val iw = if (person.imageWidth > 0) person.imageWidth.toFloat() else size.width
            val ih = if (person.imageHeight > 0) person.imageHeight.toFloat() else size.height
            if (iw <= 0f || ih <= 0f) return@forEach
            val viewW = size.width
            val viewH = size.height
            val imageAspect = iw / ih
            val viewAspect = viewW / viewH
            val scale: Float
            val dx: Float
            val dy: Float
            if (fillCenter) {
                // Use max scale so image covers view (cropped)
                scale = if (imageAspect > viewAspect) {
                    // image wider -> scale by height, crop width sides
                    viewH / ih
                } else {
                    // image taller -> scale by width, crop top/bottom
                    viewW / iw
                }
                val drawnW = iw * scale
                val drawnH = ih * scale
                dx = (viewW - drawnW) / 2f
                dy = (viewH - drawnH) / 2f
            } else {
                // Fit entire image (letterbox) using min scale
                scale = if (imageAspect > viewAspect) {
                    viewW / iw
                } else {
                    viewH / ih
                }
                val drawnW = iw * scale
                val drawnH = ih * scale
                dx = (viewW - drawnW) / 2f
                dy = (viewH - drawnH) / 2f
            }
            drawScaledPerson(person, pointColor, lineColor, scale, scale, dx, dy)
            
            // Debug overlay to visualize scaling
            if (showDebugInfo) {
                val drawnW = iw * scale
                val drawnH = ih * scale
                // Draw the actual image bounds after scaling
                drawRect(
                    color = Color.Red,
                    topLeft = Offset(dx, dy),
                    size = androidx.compose.ui.geometry.Size(drawnW, drawnH),
                    style = Stroke(width = 4f)
                )
                // Draw canvas bounds
                drawRect(
                    color = Color.Green,
                    topLeft = Offset(0f, 0f),
                    size = androidx.compose.ui.geometry.Size(viewW, viewH),
                    style = Stroke(width = 2f)
                )
                // Simple debug info with circle
                drawCircle(
                    color = Color.White,
                    radius = 8f,
                    center = Offset(20f, 20f)
                )
            }
        }
    }
}

private fun DrawScope.drawScaledPerson(
    person: PersonDetection,
    pointColor: Color,
    lineColor: Color,
    sx: Float,
    sy: Float,
    dx: Float,
    dy: Float
) {
    val map = person.keypoints.associateBy { it.type }
    skeletonConnections.forEach { (a, b) ->
        val pa = map[a]; val pb = map[b]
        if (pa != null && pb != null && pa.confidence > 0.2f && pb.confidence > 0.2f) {
            drawLine(
                lineColor,
                Offset(pa.x * sx + dx, pa.y * sy + dy),
                Offset(pb.x * sx + dx, pb.y * sy + dy),
                6f,
                pathEffect = PathEffect.cornerPathEffect(8f)
            )
        }
    }
    map.values.filter { it.confidence > 0.2f }.forEach { kp ->
        drawCircle(
            pointColor,
            radius = 10f,
            center = Offset(kp.x * sx + dx, kp.y * sy + dy),
            style = Stroke(width = 4f)
        )
    }
}
