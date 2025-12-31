# Personalized LightGBM Posture Detection

This module implements a personalized machine learning pipeline for posture analysis using **LightGBM** (Light Gradient Boosting Machine). It trains custom models for each user based on their unique body geometry and neutral posture, enabling highly accurate posture classification.

## Overview

The system uses a multi-user architecture where each user gets their own personalized model trained on angle deviations from their reference posture. The pipeline combines rule-based posture analysis with ML classification to provide real-time feedback.

### Key Features

- **Personalized Reference Postures**: Each user has a unique neutral pose stored as a reference
- **Multi-User Support**: Manages separate models and training data for multiple users
- **Hybrid Analysis**: Combines rule-based thresholds with LightGBM classification
- **Real-Time Prediction**: Watches for new keypoint files and provides instant feedback
- **Incremental Training**: Optional augmentation of the baseline dataset with new captures
- **Angle-Based Features**: Uses neck, back, and leg angles as classification features

## Directory Structure

```
lightGBM/
├── lightGBM.py              # Main training and prediction script
├── README.md                # This file
├── trainGBM/                # Baseline training dataset (shared)
│   ├── reference_posture.json
│   └── *.json              # Raw keypoint captures
└── user_profiles/           # Per-user personalized data
    └── <user_id>/
        ├── reference_posture.json           # User's neutral posture
        ├── train_adjusted/                  # Adjusted training samples
        ├── lgbm_personalized_model.pkl      # Trained model
        ├── label_encoder_personalized.pkl   # Label encoder
        ├── predictBGM/                      # Prediction inbox
        └── profile.json                     # Training metadata
```

## How It Works

### 1. Reference Posture System

The system uses two reference postures:
- **Base Reference** (`trainGBM/reference_posture.json`): Shared baseline for the training dataset
- **Personal Reference** (`user_profiles/<user_id>/reference_posture.json`): User's unique neutral posture

**Angle Offsets** are calculated between these references to personalize the model:
```
offset[region] = personal_angle[region] - base_angle[region]
```

### 2. Feature Engineering

For each posture sample, the system calculates:
- **Neck Angle**: Between hip→shoulder→ear keypoints
- **Back Angle**: Between knee→hip→shoulder keypoints  
- **Leg Angle**: Between ankle→knee→hip keypoints

Features are **deviation from personal reference**:
```python
features = {
    'neck_deviation': current_neck - personal_neck,
    'back_deviation': current_back - personal_back,
    'legs_deviation': current_legs - personal_legs
}
```

### 3. Training Labels

Labels are generated using rule-based classification with configurable tolerances:

```python
POSTURE_TOLERANCE = {
    'neck': 10.0,   # degrees
    'back': 10.0,
    'legs': 10.0
}
```

8 posture states are classified:
- Aligned Posture ✅
- Neck Misalignment
- Back Misalignment
- Legs Misalignment
- Neck & Back Misalignment
- Neck & Legs Misalignment
- Back & Legs Misalignment
- Full Body Misalignment ❌

### 4. LightGBM Model Configuration

```python
model = lgb.LGBMClassifier(
    objective='multiclass',
    random_state=42,
    num_leaves=7,
    max_depth=3,
    min_data_in_leaf=5,
    min_gain_to_split=0.0,
)
```

- **Objective**: Multi-class classification
- **Architecture**: Shallow trees (depth=3) with 7 leaves to prevent overfitting
- **Training**: 80/20 train-test split with stratification

### 5. Prediction Pipeline

For each new keypoint file in `predictBGM/`:
1. Extract neck, back, leg angles
2. Calculate deviations from personal reference
3. Run LightGBM prediction
4. Run manual rule-based check
5. Output both predictions with suggestions
6. Optionally append adjusted sample to training corpus

## Usage

### Initial Setup

1. **Prepare Baseline Dataset**
   ```bash
   # Ensure baseline reference exists
   ls trainGBM/reference_posture.json
   
   # Add raw keypoint captures to trainGBM/
   cp path/to/captures/*.json trainGBM/
   ```

2. **Create User Reference**
   ```bash
   # Create user directory
   mkdir -p user_profiles/alice
   
   # Copy user's neutral posture capture
   cp alice_reference.json user_profiles/alice/reference_posture.json
   ```

### Training a Personalized Model

```bash
cd Model/lightGBM
python lightGBM.py
```

**Interactive Prompts:**
1. Enter user identifier (e.g., `alice`, `employee_07`)
2. Provide path to user's reference posture (if not already placed)
3. Choose whether to retrain or reuse existing model
4. Enable/disable incremental augmentation

**What Happens During Training:**
- Loads baseline training samples from `trainGBM/`
- Calculates angle offsets between base and personal references
- Generates adjusted samples aligned to user's reference
- Saves adjusted samples with personalization metadata
- Trains LightGBM classifier on deviation features
- Outputs confusion matrix and classification report
- Saves model, encoder, and metadata

### Real-Time Prediction

After training, the script automatically enters watch mode:

```bash
Watching folder: 'user_profiles/alice/predictBGM/'
```

**To use:**
1. Drop keypoint JSON files into the `predictBGM/` folder
2. Instant predictions appear in console
3. Press `Ctrl+C` to stop

**Sample Output:**
```
File: keypoints_20250927_000630.json
  ML Prediction : Back Misalignment
  Manual Label  : Back Misalignment  |  Score: 72.45
  Prediction Time : 3.24 ms
    - Neck : 145.3°  ->  GOOD
    - Back :  85.7°  ->  INCORRECT (Too Bent/Forward)
        Suggestion: FIX: You are slouching. Sit up straight and engage your core.
    - Legs : 120.4°  ->  GOOD
```

### Incremental Training

If enabled, new predictions are automatically re-projected into base-reference space and appended to `trainGBM/` as augmented samples:

```
↳ Augmented training sample saved to 'trainGBM/aug_alice_20251202T143052Z.json'
```

This allows the baseline dataset to grow with diverse user captures.

## Configuration

### Angle Thresholds

Edit `lightGBM.py` to customize:

```python
POSTURE_TOLERANCE = {'neck': 10.0, 'back': 10.0, 'legs': 10.0}  # Tolerance in degrees

ANGLE_WEIGHTS = {'neck': 1.0, 'back': 1.5, 'legs': 0.5}  # Importance weights

ANGLE_LIMITS = {  # Valid range for each region
    'neck': {'min': 125.19, 'max': 178.45},
    'back': {'min': 59.70, 'max': 145.25},
    'legs': {'min': 86.13, 'max': 164.73}
}

CONFIDENCE_THRESHOLD = 0.75  # Minimum keypoint confidence
```

### Posture Suggestions

Customize feedback messages in `POSTURE_SUGGESTIONS`:

```python
POSTURE_SUGGESTIONS = {
    'neck': {
        'low': 'FIX: Your neck is bent too far forward. Tuck your chin in.',
        'high': 'FIX: Avoid tilting your head too far back.'
    },
    'back': {
        'low': 'FIX: You are slouching. Sit up straight and engage your core.',
        'high': 'FIX: You are leaning back too far. Bring your torso upright.'
    },
    'legs': {
        'low': 'FIX: Your knees are too bent. Adjust your seating or footrest.',
        'high': 'FIX: Your legs are too extended. Place your feet flat on the floor.'
    }
}
```

## Key Functions

### `train_model_for_user(user_profile)`
Trains a personalized LightGBM model for the specified user using their reference posture and the baseline dataset.

### `watch_and_predict(user_profile, enable_incremental_training)`
Watches the user's `predictBGM/` folder for new keypoint files and provides real-time predictions.

### `prepare_adjusted_training_data(user_profile)`
Generates deviation-based training records aligned to the user's personalized reference.

### `run_manual_posture_check(current_angles, personal_angles)`
Performs rule-based posture analysis with tolerance thresholds.

### `get_angles_from_payload(data)`
Extracts neck, back, and leg angles from keypoint JSON payload.

### `calculate_angle(a, b, c)`
Computes angle at point `b` formed by points `a-b-c` using dot product:
```
angle = arccos((ba · bc) / (|ba| × |bc|))
```

## Keypoint Format

Input JSON files should contain pose keypoints with the following structure:

```json
{
  "keypoints": {
    "left_ear": {"x": 245.3, "y": 178.2, "confidence": 0.89},
    "left_shoulder": {"x": 252.1, "y": 245.7, "confidence": 0.95},
    "left_hip": {"x": 248.9, "y": 398.4, "confidence": 0.92},
    "left_knee": {"x": 243.6, "y": 524.3, "confidence": 0.88},
    "left_ankle": {"x": 239.8, "y": 641.1, "confidence": 0.85},
    "right_ear": {"x": 285.4, "y": 179.8, "confidence": 0.87},
    ...
  }
}
```

The system automatically selects the side (left/right) with higher ear confidence.

## Performance

- **Prediction Latency**: ~3-5ms per sample
- **Training Time**: 5-15 seconds for ~50-100 samples
- **Model Size**: ~50-100KB per user
- **Accuracy**: Typically 85-95% on test set (varies with training data quality)

## Troubleshooting

### "No personalized reference posture found"
→ Place `reference_posture.json` in `user_profiles/<user_id>/` or provide path when prompted

### "No JSON files found in trainGBM"
→ Populate `trainGBM/` with baseline keypoint captures

### "Could not load base reference file"
→ Ensure `trainGBM/reference_posture.json` exists and contains valid keypoints

### "Skipping training file with insufficient keypoints"
→ Some captures have low confidence or missing keypoints - they're automatically filtered

### Low accuracy
→ Increase training samples, adjust `POSTURE_TOLERANCE`, or recalibrate reference postures

## Advanced Features

### Coordinate-Based Adjustment
The system can apply coordinate offsets to keypoints (not just angles) for more precise personalization:

```python
keypoint_coordinate_offsets = compute_keypoint_coordinate_offsets(
    base_keypoints, 
    personal_keypoints
)
adjusted_payload = apply_keypoint_offsets_to_payload(
    raw_payload, 
    keypoint_coordinate_offsets
)
```

### Manual Scoring
In addition to classification, the system computes a continuous score (0-100) based on weighted deviations:

```python
score = 1 - (weighted_deviation / max_threshold) * 100
```

### Metadata Tracking
Each training run stores metadata in `profile.json`:
```json
{
  "user_id": "alice",
  "trained_at": "2025-12-02T14:30:52Z",
  "training_samples": 48,
  "test_samples": 12,
  "base_reference_file": "trainGBM/reference_posture.json",
  "personal_reference_file": "user_profiles/alice/reference_posture.json",
  "reference_offsets": {"neck": -5.2, "back": 3.8, "legs": 1.4}
}
```

## Integration with Main App

This LightGBM module is designed to work alongside the main Android posture detection app. The app can export keypoint data to `predictBGM/` folders for batch analysis or training data collection.

See `Model/README.md` for details on the overall posture analysis pipeline.
