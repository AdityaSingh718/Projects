package com.example.eswproject

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import kotlinx.coroutines.*
import java.io.BufferedInputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Network video stream receiver for MJPEG streams
 * Connects to webcam streaming server and receives frames
 */
class NetworkVideoStreamReceiver(
    private val streamUrl: String,
    private val onFrameReceived: (Bitmap) -> Unit,
    private val onError: (String) -> Unit
) {
    
    private var isRunning = false
    private var receiveJob: Job? = null
    private var frameCount = 0
    
    companion object {
        private const val TAG = "NetworkVideoStream"
        private const val BOUNDARY = "frame"
    private const val CONNECTION_TIMEOUT = 5000 // 5 seconds
    private const val READ_TIMEOUT = 1500 // tighter read timeout keeps polling responsive
    }
    
    /**
     * Start receiving video stream
     */
    fun start() {
        if (isRunning) {
            Log.w(TAG, "Stream already running")
            return
        }
        
        isRunning = true
        receiveJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                connectAndReceive()
            } catch (e: Exception) {
                Log.e(TAG, "Error in stream reception", e)
                withContext(Dispatchers.Main) {
                    onError("Stream error: ${e.message}")
                }
                stop()
            }
        }
    }
    
    /**
     * Stop receiving video stream
     */
    fun stop() {
        isRunning = false
        receiveJob?.cancel()
        receiveJob = null
        Log.i(TAG, "Stream stopped. Total frames received: $frameCount")
    }
    
    /**
     * Connect to stream and receive frames
     */
    private suspend fun connectAndReceive() {
    val normalizedUrl = normalizeUrl(streamUrl)
    Log.i(TAG, "Connecting to stream: $normalizedUrl")
        
    val url = URL(normalizedUrl)
        val connection = url.openConnection() as HttpURLConnection
        
        try {
            connection.connectTimeout = CONNECTION_TIMEOUT
            connection.readTimeout = READ_TIMEOUT
            connection.requestMethod = "GET"
            connection.setRequestProperty("Connection", "Keep-Alive")
            connection.setRequestProperty("Cache-Control", "no-cache")
            connection.doInput = true
            connection.connect()
            
            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw Exception("HTTP error: $responseCode")
            }
            
            Log.i(TAG, "Connected successfully. Starting frame reception...")
            
            val inputStream = connection.inputStream
            readMJPEGStream(inputStream)
            
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Normalize user-provided stream URL.
     */
    private fun normalizeUrl(rawUrl: String): String {
        var urlString = rawUrl.trim()
        if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
            urlString = "http://$urlString"
        }
        return urlString
    }
    
    /**
     * Read MJPEG stream and extract frames
     */
    private suspend fun readMJPEGStream(inputStream: InputStream) {
        val bufferedStream = BufferedInputStream(inputStream, 16 * 1024)

        while (isRunning) {
            val boundaryLine = readLine(bufferedStream) ?: break
            if (!boundaryLine.contains(BOUNDARY)) {
                continue
            }

            var contentLength = -1
            while (true) {
                val headerLine = readLine(bufferedStream) ?: return
                if (headerLine.isEmpty()) {
                    break
                }
                if (headerLine.startsWith("Content-Length", ignoreCase = true)) {
                    contentLength = headerLine.substringAfter(":").trim().toIntOrNull() ?: -1
                }
            }

            if (contentLength <= 0) {
                continue
            }

            val frameData = ByteArray(contentLength)
            var bytesRead = 0
            while (bytesRead < contentLength) {
                val read = bufferedStream.read(frameData, bytesRead, contentLength - bytesRead)
                if (read == -1) {
                    return
                }
                bytesRead += read
            }

            processFrame(frameData)

            // Consume trailing CRLF after frame payload if present
            bufferedStream.mark(2)
            val first = bufferedStream.read()
            val second = bufferedStream.read()
            if (first == -1 || second == -1) {
                return
            }
            if (!(first == '\r'.code && second == '\n'.code)) {
                bufferedStream.reset()
            }
        }
    }

    private fun readLine(stream: BufferedInputStream): String? {
        val builder = StringBuilder()
        while (true) {
            val value = stream.read()
            if (value == -1) {
                return if (builder.isEmpty()) null else builder.toString()
            }
            if (value == '\n'.code) {
                return builder.toString()
            }
            if (value != '\r'.code) {
                builder.append(value.toChar())
            }
        }
    }
    
    /**
     * Process received frame
     */
    private suspend fun processFrame(frameData: ByteArray) {
        try {
            val bitmap = BitmapFactory.decodeByteArray(frameData, 0, frameData.size)
            if (bitmap != null) {
                frameCount++
                if (frameCount % 30 == 0) {
                    Log.d(TAG, "Frames received: $frameCount")
                }
                
                withContext(Dispatchers.Main) {
                    onFrameReceived(bitmap)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing frame", e)
        }
    }
    
    /**
     * Check if stream is currently active
     */
    fun isActive(): Boolean = isRunning
    
    /**
     * Get total frames received
     */
    fun getFrameCount(): Int = frameCount
}

/**
 * Factory for creating network stream receivers with predefined configurations
 */
object NetworkStreamFactory {
    
    /**
     * Create receiver for laptop webcam stream
     */
    fun createWebcamReceiver(
        serverIp: String,
        serverPort: Int = 5000,
        onFrameReceived: (Bitmap) -> Unit,
        onError: (String) -> Unit
    ): NetworkVideoStreamReceiver {
        val streamUrl = "http://$serverIp:$serverPort/video_feed"
        return NetworkVideoStreamReceiver(streamUrl, onFrameReceived, onError)
    }
    
    /**
     * Test connection to streaming server
     */
    suspend fun testConnection(serverIp: String, serverPort: Int = 5000): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL("http://$serverIp:$serverPort/health")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 3000
                connection.requestMethod = "GET"
                connection.connect()
                
                val responseCode = connection.responseCode
                connection.disconnect()
                
                responseCode == HttpURLConnection.HTTP_OK
            } catch (e: Exception) {
                Log.e("NetworkStreamFactory", "Connection test failed", e)
                false
            }
        }
    }
}
