package com.example.eswproject

import android.content.Context
import android.util.Log
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Personalized Posture Manager
 *
 * Bridges Android and the Python LightGBM personalized posture detector via Chaquopy.
 * Handles initialization, profile management, and prediction calls.
 */
class PersonalizedPostureManager(private val context: Context) {

    companion object {
        private const val TAG = "PersonalizedPostureManager"
        private const val PYTHON_MODULE = "personalized_posture_detector"
        private const val ERROR_NOT_INITIALIZED = "Personalized engine is not initialized"
    }

    private var pythonModule: PyObject? = null
    private var isInitialized = false
    private var currentUserId: String? = null

    @Volatile
    private var lastErrorMessage: String? = null

    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing Personalized Posture Manager...")

            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(context))
            }

            val python = Python.getInstance()
            pythonModule = python.getModule(PYTHON_MODULE)

            val assetsDir = getAssetsExtractionDir()
            val internalDir = context.filesDir.absolutePath

            val initResult = pythonModule?.callAttr("initialize", assetsDir, internalDir)
            isInitialized = initResult?.toBoolean() ?: false

            if (isInitialized) {
                lastErrorMessage = null
                Log.d(TAG, "Personalized Posture Manager initialized successfully")
            } else {
                lastErrorMessage = "Python module reported initialization failure"
                Log.e(TAG, "Failed to initialize Personalized Posture Manager")
            }

            isInitialized
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            isInitialized = false
            Log.e(TAG, "Error initializing Personalized Posture Manager", e)
            false
        }
    }

    fun getLastErrorMessage(): String? = lastErrorMessage

    private fun getAssetsExtractionDir(): String {
        val extractDir = File(context.filesDir, "assets_extracted")
        extractDir.mkdirs()

        copyAssetsToInternal()

        return extractDir.absolutePath
    }

    private fun copyAssetsToInternal() {
        try {
            val rootDir = File(context.filesDir, "assets_extracted")
            val lightGbmDir = File(rootDir, "lightGBM")
            val marker = File(lightGbmDir, ".extracted")

            if (marker.exists()) {
                Log.d(TAG, "lightGBM assets already extracted")
                return
            }

            lightGbmDir.mkdirs()

            copyAssetFile("lightGBM/reference_posture.json", lightGbmDir)

            val trainGbmDir = File(lightGbmDir, "trainGBM")
            trainGbmDir.mkdirs()

            val trainFiles = context.assets.list("lightGBM/trainGBM") ?: emptyArray()
            for (fileName in trainFiles) {
                copyAssetFile("lightGBM/trainGBM/$fileName", trainGbmDir)
            }

            marker.createNewFile()
            Log.d(TAG, "Extracted ${trainFiles.size} LightGBM training assets")
        } catch (e: Exception) {
            Log.e(TAG, "Error copying LightGBM assets", e)
        }
    }

    private fun copyAssetFile(assetPath: String, destDir: File) {
        try {
            val target = File(destDir, assetPath.substringAfterLast('/'))
            context.assets.open(assetPath).use { input ->
                target.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error copying asset $assetPath", e)
        }
    }

    suspend fun userExists(userId: String): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            lastErrorMessage = ERROR_NOT_INITIALIZED
            Log.e(TAG, ERROR_NOT_INITIALIZED)
            return@withContext false
        }

        try {
            val result = pythonModule?.callAttr("user_exists", userId)
            result?.toBoolean() ?: false
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            Log.e(TAG, "Error checking user existence", e)
            false
        }
    }

    suspend fun saveReferencePosture(
        userId: String,
        neckAngle: Double,
        backAngle: Double,
        legsAngle: Double
    ): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            lastErrorMessage = ERROR_NOT_INITIALIZED
            Log.e(TAG, ERROR_NOT_INITIALIZED)
            return@withContext false
        }

        try {
            Log.d(
                TAG,
                "Saving reference posture for user '$userId' neck=${"%.1f".format(neckAngle)}° " +
                    "back=${"%.1f".format(backAngle)}° legs=${"%.1f".format(legsAngle)}°"
            )

            val result = pythonModule?.callAttr(
                "save_reference_posture",
                userId,
                neckAngle,
                backAngle,
                legsAngle
            )

            val success = result?.toBoolean() ?: false
            if (success) {
                lastErrorMessage = null
            } else {
                lastErrorMessage = "Python module was unable to save the reference posture"
                Log.e(TAG, "Python module returned false while saving reference posture")
            }

            success
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            Log.e(TAG, "Error saving reference posture", e)
            false
        }
    }

    suspend fun trainModel(userId: String): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            lastErrorMessage = ERROR_NOT_INITIALIZED
            Log.e(TAG, ERROR_NOT_INITIALIZED)
            return@withContext false
        }

        try {
            Log.d(TAG, "Training personalized model for user '$userId'")
            val result = pythonModule?.callAttr("train_model", userId)
            val success = result?.toBoolean() ?: false

            if (success) {
                lastErrorMessage = null
                Log.d(TAG, "Model training completed for user '$userId'")
            } else {
                lastErrorMessage = "Python module could not train the personalized model"
                Log.e(TAG, "Model training failed for user '$userId'")
            }

            success
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            Log.e(TAG, "Error training personalized model", e)
            false
        }
    }

    suspend fun loadModel(userId: String): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            lastErrorMessage = ERROR_NOT_INITIALIZED
            Log.e(TAG, ERROR_NOT_INITIALIZED)
            return@withContext false
        }

        try {
            Log.d(TAG, "Loading personalized model for user '$userId'")
            val result = pythonModule?.callAttr("load_model", userId)
            val success = result?.toBoolean() ?: false

            if (success) {
                currentUserId = userId
                lastErrorMessage = null
                Log.d(TAG, "Model loaded for user '$userId'")
            } else {
                lastErrorMessage = "Personalized model not found for user"
                Log.e(TAG, "Failed to load model for user '$userId'")
            }

            success
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            Log.e(TAG, "Error loading personalized model", e)
            false
        }
    }

    suspend fun predict(
        neckAngle: Double,
        backAngle: Double,
        legsAngle: Double
    ): PersonalizedPostureResult? = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            lastErrorMessage = ERROR_NOT_INITIALIZED
            Log.e(TAG, ERROR_NOT_INITIALIZED)
            return@withContext null
        }

        if (currentUserId == null) {
            lastErrorMessage = "No personalized model loaded"
            Log.e(TAG, "No model loaded. Call loadModel() first.")
            return@withContext null
        }

        try {
            val result = pythonModule?.callAttr("predict", neckAngle, backAngle, legsAngle)
            val jsonString = result?.toString()

            if (jsonString.isNullOrBlank()) {
                lastErrorMessage = "Python module returned empty prediction"
                Log.e(TAG, "Prediction returned null or blank response")
                return@withContext null
            }

            val json = JSONObject(jsonString)

            val suggestionsArray = json.getJSONArray("suggestions")
            val suggestions = mutableListOf<String>()
            for (i in 0 until suggestionsArray.length()) {
                suggestions.add(suggestionsArray.getString(i))
            }

            lastErrorMessage = null

            PersonalizedPostureResult(
                mlPrediction = json.getString("ml_prediction"),
                manualLabel = json.getString("manual_label"),
                score = json.getInt("score"),
                suggestions = suggestions
            )
        } catch (e: Exception) {
            lastErrorMessage = e.localizedMessage ?: e.toString()
            Log.e(TAG, "Error predicting posture", e)
            null
        }
    }

    data class PersonalizedPostureResult(
        val mlPrediction: String,
        val manualLabel: String,
        val score: Int,
        val suggestions: List<String>
    )
}
