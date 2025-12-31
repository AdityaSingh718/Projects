import os
import time
import glob
import json
import shutil
import copy
from dataclasses import dataclass
from datetime import datetime, UTC

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import joblib

# --- Configuration ---
RAW_TRAIN_FOLDER = 'trainGBM'
USER_PROFILES_ROOT = 'user_profiles'
# Baseline reference captured with the training dataset
BASE_REFERENCE_FILE = os.path.join(RAW_TRAIN_FOLDER, 'reference_posture.json')
# Optional default personalized reference source (can be overridden via env var)
DEFAULT_PERSONAL_REFERENCE_SOURCE = os.environ.get('PERSONAL_REFERENCE_FILE')

MODEL_FILENAME = 'lgbm_personalized_model.pkl'
ENCODER_FILENAME = 'label_encoder_personalized.pkl'
PROFILE_MANIFEST = 'profile.json'
USER_REFERENCE_FILENAME = 'reference_posture.json'
USER_ADJUSTED_SUBDIR = 'train_adjusted'
USER_PREDICT_SUBDIR = 'predictBGM'


@dataclass
class UserProfile:
    user_id: str
    root: str
    reference_path: str
    adjusted_folder: str
    model_path: str
    encoder_path: str
    predict_folder: str
    metadata_path: str


def build_user_profile(user_id: str) -> UserProfile:
    user_root = os.path.join(USER_PROFILES_ROOT, user_id)
    return UserProfile(
        user_id=user_id,
        root=user_root,
        reference_path=os.path.join(user_root, USER_REFERENCE_FILENAME),
        adjusted_folder=os.path.join(user_root, USER_ADJUSTED_SUBDIR),
        model_path=os.path.join(user_root, MODEL_FILENAME),
        encoder_path=os.path.join(user_root, ENCODER_FILENAME),
        predict_folder=os.path.join(user_root, USER_PREDICT_SUBDIR),
        metadata_path=os.path.join(user_root, PROFILE_MANIFEST),
    )


def ensure_user_reference(user_profile: UserProfile) -> bool:
    """Ensure a personalized reference posture exists for the user."""
    if os.path.exists(user_profile.reference_path):
        return True

    print(
        f"No personalized reference posture found for user '{user_profile.user_id}'."
        "\nPlease provide a JSON keypoint file that represents the user's neutral/reference posture."
    )

    suggested_source = DEFAULT_PERSONAL_REFERENCE_SOURCE
    while True:
        prompt = "Path to user reference JSON (or press Enter to re-check after placing the file): "
        candidate = suggested_source or input(prompt).strip()
        suggested_source = None  # only use env var once

        if not candidate:
            if os.path.exists(user_profile.reference_path):
                return True
            print("Reference file still missing. Please provide a valid path or copy the file into place.")
            continue

        if os.path.isfile(candidate):
            os.makedirs(user_profile.root, exist_ok=True)
            shutil.copyfile(candidate, user_profile.reference_path)
            print(f"Saved personalized reference to '{user_profile.reference_path}'.")
            return True

        print(f"File '{candidate}' not found. Try again.")


def load_user_metadata(user_profile: UserProfile):
    if not os.path.exists(user_profile.metadata_path):
        return None
    try:
        with open(user_profile.metadata_path, 'r') as handle:
            return json.load(handle)
    except Exception:
        return None


def save_user_metadata(user_profile: UserProfile, metadata: dict) -> None:
    os.makedirs(user_profile.root, exist_ok=True)
    with open(user_profile.metadata_path, 'w') as handle:
        json.dump(metadata, handle, indent=2)

CONFIDENCE_THRESHOLD = 0.75
POSTURE_TOLERANCE = {'neck': 10.0, 'back': 10.0, 'legs': 10.0}
ANGLE_WEIGHTS = {'neck': 1.0, 'back': 1.5, 'legs': 0.5}
ANGLE_LIMITS = {
    'neck': {'min': 125.19, 'max': 178.45},
    'back': {'min': 59.70, 'max': 145.25},
    'legs': {'min': 86.13, 'max': 164.73}
}
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

# --- Helper Functions ---

def calculate_angle(a, b, c):
    a, b, c = np.array(a), np.array(b), np.array(c)
    ba, bc = a - b, c - b
    dot_product = np.dot(ba, bc)
    magnitude_ba, magnitude_bc = np.linalg.norm(ba), np.linalg.norm(bc)
    cosine_angle = np.clip(dot_product / (magnitude_ba * magnitude_bc + 1e-6), -1.0, 1.0)
    return float(np.degrees(np.arccos(cosine_angle)))


def _normalise_keypoints(raw_keypoints):
    lookup = {}
    if isinstance(raw_keypoints, dict):
        for label, payload in raw_keypoints.items():
            if not isinstance(payload, (dict, list, tuple)):
                continue
            if isinstance(payload, dict):
                lookup[label] = payload
                continue
            if len(payload) >= 3:
                x_val, y_val, conf = payload[:3]
                lookup[label] = {'x': x_val, 'y': y_val, 'confidence': conf}
        return lookup

    if isinstance(raw_keypoints, list):
        for entry in raw_keypoints:
            if not isinstance(entry, dict):
                continue
            name = entry.get('part_name') or entry.get('name') or entry.get('part') or entry.get('id')
            if not name:
                continue
            position = entry.get('position') if isinstance(entry.get('position'), dict) else {}
            x_val = entry.get('x', position.get('x'))
            y_val = entry.get('y', position.get('y'))
            conf = entry.get('confidence', entry.get('score', entry.get('probability')))
            lookup[name] = {
                'x': x_val,
                'y': y_val,
                'confidence': conf,
                'visible': entry.get('visible', entry.get('is_visible', True))
            }
        return lookup

    return lookup


def _confidence(point):
    if not isinstance(point, dict):
        return 0.0
    if point.get('visible') is False:
        return 0.0
    conf = point.get('confidence')
    if conf is None:
        conf = point.get('score')
    if conf is None:
        conf = point.get('probability')
    try:
        return float(conf)
    except (TypeError, ValueError):
        return 0.0


def _build_keypoints_lookup(payload):
    if not isinstance(payload, dict):
        return {}

    persons = payload.get('persons') or payload.get('people')
    keypoints_lookup = {}

    if isinstance(persons, list) and persons:
        person_entry = persons[0]
        if isinstance(person_entry, dict):
            for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
                if candidate_key in person_entry:
                    keypoints_lookup = _normalise_keypoints(person_entry[candidate_key])
                    if keypoints_lookup:
                        break

    if not keypoints_lookup:
        for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
            if candidate_key in payload:
                keypoints_lookup = _normalise_keypoints(payload[candidate_key])
                if keypoints_lookup:
                    break

    return keypoints_lookup


def extract_keypoint_coordinates_from_payload(payload):
    lookup = _build_keypoints_lookup(payload)
    coords = {}
    for name, point in lookup.items():
        try:
            x_val = float(point.get('x'))
            y_val = float(point.get('y'))
        except (TypeError, ValueError):
            continue
        coords[name] = {'x': x_val, 'y': y_val}
    return coords


def load_keypoint_coordinates(filepath):
    try:
        with open(filepath, 'r') as handle:
            payload = json.load(handle)
    except Exception:
        return {}
    return extract_keypoint_coordinates_from_payload(payload)


def compute_keypoint_coordinate_offsets(base_map, personal_map):
    offsets = {}
    if not base_map or not personal_map:
        return offsets
    for name, base_point in base_map.items():
        personal_point = personal_map.get(name)
        if not personal_point:
            continue
        try:
            delta_x = float(personal_point['x']) - float(base_point['x'])
            delta_y = float(personal_point['y']) - float(base_point['y'])
        except (TypeError, ValueError, KeyError):
            continue
        offsets[name] = {'x': delta_x, 'y': delta_y}
    return offsets


def apply_keypoint_offsets_to_payload(payload, keypoint_offsets):
    if not isinstance(payload, dict) or not keypoint_offsets:
        return copy.deepcopy(payload) if isinstance(payload, dict) else payload

    adjusted = copy.deepcopy(payload)

    def _apply_delta(entry, name):
        delta = keypoint_offsets.get(name)
        if not delta or not isinstance(entry, dict):
            return
        for axis in ('x', 'y'):
            if axis in entry and entry[axis] is not None:
                try:
                    entry[axis] = float(entry[axis]) + delta.get(axis, 0.0)
                except (TypeError, ValueError):
                    continue
        position = entry.get('position') if isinstance(entry.get('position'), dict) else None
        if position:
            for axis in ('x', 'y'):
                if axis in position and position[axis] is not None:
                    try:
                        position[axis] = float(position[axis]) + delta.get(axis, 0.0)
                    except (TypeError, ValueError):
                        continue

    def _process_keypoints(container):
        if isinstance(container, list):
            for entry in container:
                if isinstance(entry, dict):
                    name = (
                        entry.get('name')
                        or entry.get('part_name')
                        or entry.get('part')
                        or entry.get('id')
                    )
                    if name:
                        _apply_delta(entry, name)
        elif isinstance(container, dict):
            for name, entry in container.items():
                if isinstance(entry, dict):
                    _apply_delta(entry, name)
                elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    delta = keypoint_offsets.get(name)
                    if not delta:
                        continue
                    try:
                        new_entry = list(entry)
                        new_entry[0] = float(new_entry[0]) + delta.get('x', 0.0)
                        new_entry[1] = float(new_entry[1]) + delta.get('y', 0.0)
                        container[name] = new_entry
                    except (TypeError, ValueError):
                        continue

    persons = adjusted.get('persons') or adjusted.get('people')
    if isinstance(persons, list):
        for person in persons:
            if not isinstance(person, dict):
                continue
            for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
                if candidate_key in person:
                    _process_keypoints(person[candidate_key])

    for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
        if candidate_key in adjusted:
            _process_keypoints(adjusted[candidate_key])

    return adjusted

def get_angles_from_payload(data):
    """Extract neck/back/legs angles from a parsed keypoint payload."""

    def _extract_angles(candidate):
        if not isinstance(candidate, dict):
            return None
        keys = ['neck', 'back', 'legs']
        if all(k in candidate for k in keys):
            return {k: float(candidate[k]) for k in keys}
        return None

    if isinstance(data, dict):
        for key in ('adjusted_angles', 'personalized_angles', 'angles'):
            angles = _extract_angles(data.get(key))
            if angles:
                return angles
        direct_angles = _extract_angles(data)
        if direct_angles:
            return direct_angles

    keypoints_lookup = _build_keypoints_lookup(data)
    if not keypoints_lookup:
        return None

    left_ear_conf = _confidence(keypoints_lookup.get('left_ear'))
    right_ear_conf = _confidence(keypoints_lookup.get('right_ear'))
    side = 'left' if left_ear_conf >= right_ear_conf else 'right'

    required_parts = {
        'ear': f'{side}_ear',
        'shoulder': f'{side}_shoulder',
        'hip': f'{side}_hip',
        'knee': f'{side}_knee',
        'ankle': f'{side}_ankle'
    }

    coords = {}
    for name, part_key in required_parts.items():
        point = keypoints_lookup.get(part_key)
        if _confidence(point) < CONFIDENCE_THRESHOLD:
            return None
        try:
            x_val = float(point.get('x'))
            y_val = float(point.get('y'))
        except (TypeError, ValueError):
            return None
        coords[name] = [x_val, y_val]

    return {
        'neck': calculate_angle(coords['hip'], coords['shoulder'], coords['ear']),
        'back': calculate_angle(coords['knee'], coords['hip'], coords['shoulder']),
        'legs': calculate_angle(coords['ankle'], coords['knee'], coords['hip'])
    }


def get_angles_from_keypoint_file(filepath):
    """Extract neck/back/legs angles from a raw keypoint JSON file."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except Exception:
        return None

    return get_angles_from_payload(data)


def build_manual_rules(personal_angles):
    rules = {}
    for region in ['neck', 'back', 'legs']:
        tolerance = POSTURE_TOLERANCE[region]
        rules[region] = {
            'min': personal_angles[region] - tolerance,
            'max': personal_angles[region] + tolerance,
            'low_suggestion': POSTURE_SUGGESTIONS[region]['low'],
            'high_suggestion': POSTURE_SUGGESTIONS[region]['high']
        }
    return rules


def compute_manual_max_deviation(personal_angles):
    threshold = 0.0
    for region, ideal in personal_angles.items():
        limits = ANGLE_LIMITS.get(region)
        if not limits:
            continue
        worst_angle = limits['min'] if abs(limits['min'] - ideal) > abs(limits['max'] - ideal) else limits['max']
        worst_diff = abs(worst_angle - ideal)
        weight = ANGLE_WEIGHTS.get(region, 1.0)
        threshold += weight * (worst_diff ** 2)
    return threshold


def calculate_manual_score(current_angles, personal_angles, max_threshold):
    deviations = {
        region: (current_angles[region] - personal_angles[region]) ** 2
        for region in ['neck', 'back', 'legs']
    }
    weighted_deviation = sum(ANGLE_WEIGHTS[region] * deviations[region] for region in ['neck', 'back', 'legs'])
    if max_threshold <= 0:
        return 100.0 if weighted_deviation <= 1e-6 else 0.0
    score = 1 - (weighted_deviation / max_threshold)
    return max(0.0, min(100.0, score * 100))


def run_manual_posture_check(current_angles, personal_angles):
    manual_rules = build_manual_rules(personal_angles)
    max_threshold = compute_manual_max_deviation(personal_angles)
    analysis_rows = []
    for region in ['neck', 'back', 'legs']:
        angle = current_angles[region]
        rule = manual_rules[region]
        status = 'GOOD'
        suggestion = 'No correction needed.'
        if angle < rule['min']:
            status = 'INCORRECT (Too Bent/Forward)'
            suggestion = rule['low_suggestion']
        elif angle > rule['max']:
            status = 'INCORRECT (Too Reclined/Extended)'
            suggestion = rule['high_suggestion']
        analysis_rows.append({
            'region': region,
            'angle': angle,
            'status': status,
            'suggestion': suggestion
        })

    manual_label = classify_posture_state(current_angles, manual_rules)
    manual_score = calculate_manual_score(current_angles, personal_angles, max_threshold)
    return {
        'label': manual_label,
        'score': manual_score,
        'details': analysis_rows
    }


def append_adjusted_sample_to_training(
    user_profile: UserProfile,
    source_file: str,
    current_angles: dict,
    offsets: dict,
    original_angles: dict | None = None,
) -> str:
    """Re-project a user capture into base-reference space and append to raw training folder."""
    base_aligned_angles = {
        axis: float(current_angles[axis] - offsets.get(axis, 0.0))
        for axis in ['neck', 'back', 'legs']
    }

    source_details = {
        'user_id': user_profile.user_id,
        'source_file': os.path.abspath(source_file),
        'captured_at': datetime.now(UTC).isoformat(),
        'offsets_applied': {k: float(offsets.get(k, 0.0)) for k in ['neck', 'back', 'legs']},
    }
    if original_angles:
        source_details['user_space_angles'] = {k: float(original_angles[k]) for k in ['neck', 'back', 'legs']}
    source_details['base_space_angles'] = base_aligned_angles

    data = {
        'timestamp': datetime.now(UTC).isoformat(),
        'angles': base_aligned_angles,
        'metadata': source_details,
    }

    timestamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    filename = f"aug_{user_profile.user_id}_{timestamp}.json"
    destination = os.path.join(RAW_TRAIN_FOLDER, filename)

    try:
        with open(destination, 'w') as handle:
            json.dump(data, handle, indent=2)
        print(f"    ↳ Augmented training sample saved to '{destination}'.")
    except OSError as exc:
        print(f"    ↳ Warning: Failed to save augmented training sample ({exc}).")
        destination = ''

    return destination

def classify_posture_state(angles, rules):
    """Generates a classification label for training data."""
    state = tuple("GOOD" if rules[r]['min'] <= angles[r] <= rules[r]['max'] else "BAD" for r in ['neck', 'back', 'legs'])
    posture_states = {
        ("GOOD", "GOOD", "GOOD"): "Aligned Posture", ("GOOD", "GOOD", "BAD"): "Legs Misalignment",
        ("GOOD", "BAD", "GOOD"): "Back Misalignment", ("GOOD", "BAD", "BAD"): "Back & Legs Misalignment",
        ("BAD", "GOOD", "GOOD"): "Neck Misalignment", ("BAD", "GOOD", "BAD"): "Neck & Legs Misalignment",
        ("BAD", "BAD", "GOOD"): "Neck & Back Misalignment", ("BAD", "BAD", "BAD"): "Full Body Misalignment",
    }
    return posture_states.get(state, "Unknown")


def resolve_reference_angles(base_reference_path=BASE_REFERENCE_FILE, personal_reference_path=None):
    """Load baseline and personalized reference postures, returning angles and offsets."""
    personal_reference_path = personal_reference_path or base_reference_path
    base_angles = get_angles_from_keypoint_file(base_reference_path)
    if not base_angles:
        print(f"Error: Could not load base reference file '{base_reference_path}'.")
        return None
    base_angles = {k: float(base_angles[k]) for k in ['neck', 'back', 'legs']}

    personal_angles = get_angles_from_keypoint_file(personal_reference_path)
    if not personal_angles:
        if personal_reference_path != base_reference_path:
            print(f"Warning: Personalized reference '{personal_reference_path}' not found. Falling back to base reference.")
        personal_angles = base_angles
        personal_reference_path = base_reference_path
    else:
        personal_angles = {k: float(personal_angles[k]) for k in ['neck', 'back', 'legs']}

    offsets = {k: float(personal_angles[k] - base_angles.get(k, personal_angles[k])) for k in ['neck', 'back', 'legs']}
    return base_angles, personal_angles, offsets, personal_reference_path


def prepare_adjusted_training_data(user_profile: UserProfile):
    """Generate deviation records aligned to a user's personalized reference and persist adjusted samples."""
    resolution = resolve_reference_angles(
        base_reference_path=BASE_REFERENCE_FILE,
        personal_reference_path=user_profile.reference_path,
    )
    if not resolution:
        return None
    base_angles, personal_angles, offsets, resolved_personal_path = resolution

    os.makedirs(user_profile.adjusted_folder, exist_ok=True)

    base_keypoints = load_keypoint_coordinates(BASE_REFERENCE_FILE)
    personal_keypoints = load_keypoint_coordinates(resolved_personal_path)
    keypoint_coordinate_offsets = compute_keypoint_coordinate_offsets(base_keypoints, personal_keypoints)

    # Clear out stale adjusted files to avoid mixing runs.
    for stale_file in glob.glob(os.path.join(user_profile.adjusted_folder, '*.json')):
        try:
            os.remove(stale_file)
        except OSError:
            pass

    excluded_paths = {
        os.path.abspath(BASE_REFERENCE_FILE),
        os.path.abspath(resolved_personal_path)
    }

    training_records = []
    raw_files = glob.glob(os.path.join(RAW_TRAIN_FOLDER, '*.json'))
    if not raw_files:
        print(f"Error: No JSON files found in '{RAW_TRAIN_FOLDER}'.")
        return None

    for filepath in raw_files:
        if os.path.abspath(filepath) in excluded_paths:
            continue

        try:
            with open(filepath, 'r') as source_handle:
                raw_payload = json.load(source_handle)
        except Exception as exc:
            print(
                f"Skipping training file due to JSON parse error: {os.path.basename(filepath)} ({exc})"
            )
            continue

        current_angles = get_angles_from_payload(raw_payload)
        if not current_angles:
            print(f"Skipping training file with insufficient keypoints: {os.path.basename(filepath)}")
            continue

        current_angles = {k: float(current_angles[k]) for k in ['neck', 'back', 'legs']}
        deviation_from_personal = {k: float(current_angles[k] - personal_angles[k]) for k in ['neck', 'back', 'legs']}
        adjusted_payload = apply_keypoint_offsets_to_payload(raw_payload, keypoint_coordinate_offsets)
        adjusted_payload_angles = get_angles_from_payload(adjusted_payload)
        if adjusted_payload_angles:
            adjusted_angles = {k: float(adjusted_payload_angles[k]) for k in ['neck', 'back', 'legs']}
        else:
            adjusted_angles = {k: float(current_angles[k] + offsets[k]) for k in ['neck', 'back', 'legs']}
        adjusted_deviation_from_personal = {
            k: float(adjusted_angles[k] - personal_angles[k]) for k in ['neck', 'back', 'legs']
        }
        manual_summary = run_manual_posture_check(adjusted_angles, personal_angles)
        manual_label = manual_summary['label']
        manual_score = manual_summary['score']

        record = {
            "user_id": user_profile.user_id,
            "source_file": os.path.basename(filepath),
            "base_reference_file": os.path.basename(BASE_REFERENCE_FILE),
            "personal_reference_file": os.path.basename(resolved_personal_path),
            "reference_offsets": {k: offsets[k] for k in ['neck', 'back', 'legs']},
            "original_angles": current_angles,
            "adjusted_angles": adjusted_angles,
            "deviation_from_personal": deviation_from_personal,
            "adjusted_deviation_from_personal": adjusted_deviation_from_personal,
            "manual_label": manual_label,
            "manual_score": manual_score,
        }
        training_records.append(record)

        personalization_block = {
            "user_id": user_profile.user_id,
            "base_reference_file": os.path.basename(BASE_REFERENCE_FILE),
            "personal_reference_file": os.path.basename(resolved_personal_path),
            "reference_offsets": {k: offsets[k] for k in ['neck', 'back', 'legs']},
            "original_angles": current_angles,
            "adjusted_angles": adjusted_angles,
            "deviation_from_personal": deviation_from_personal,
            "keypoint_coordinate_offsets": copy.deepcopy(keypoint_coordinate_offsets),
            "adjusted_at": datetime.now(UTC).isoformat(),
            "manual_label": manual_label,
            "manual_score": manual_score,
        }

        if isinstance(adjusted_payload, dict):
            augmented_payload = adjusted_payload
            augmented_payload["personalization_adjustment"] = personalization_block
        else:
            augmented_payload = {
                "personalization_adjustment": personalization_block,
                "raw_payload": adjusted_payload,
            }

        output_path = os.path.join(user_profile.adjusted_folder, os.path.basename(filepath))
        with open(output_path, 'w') as outfile:
            json.dump(augmented_payload, outfile, indent=2)

        record["adjusted_payload_path"] = output_path

    if not training_records:
        print("Error: No valid training data could be created after adjustment.")
        return None

    print(
        f"Prepared {len(training_records)} adjusted samples for user '{user_profile.user_id}' in "
        f"'{user_profile.adjusted_folder}' using personalized reference "
        f"'{os.path.basename(resolved_personal_path)}'."
    )
    if any(abs(offsets[k]) > 1e-6 for k in offsets):
        print(
            "Applied reference offsets (deg): "
            + ", ".join(f"{axis}={offsets[axis]:+.2f}" for axis in ['neck', 'back', 'legs'])
        )

    return {
        'base_angles': base_angles,
        'personal_angles': personal_angles,
        'offsets': offsets,
        'training_records': training_records,
        'personal_reference_path': resolved_personal_path,
    }

# --- Core Functions ---

def train_model_for_user(user_profile: UserProfile):
    """Train a LightGBM model on deviations from a user's personalized reference posture."""
    print(f"--- 1. Starting Personalized Model Training for '{user_profile.user_id}' ---")

    bundle = prepare_adjusted_training_data(user_profile)
    if not bundle:
        return None

    personal_angles = bundle['personal_angles']
    offsets = bundle['offsets']
    training_records = bundle['training_records']
    personal_reference_path = bundle['personal_reference_path']

    print(
        "Using personalized reference angles (deg): "
        f"Neck={personal_angles['neck']:.1f}, Back={personal_angles['back']:.1f}, Legs={personal_angles['legs']:.1f}"
        f" from '{os.path.basename(personal_reference_path)}'"
    )
    if any(abs(offsets[axis]) > 1e-6 for axis in offsets):
        print(
            "Reference shift relative to base (deg): "
            + ", ".join(f"{axis}={offsets[axis]:+.2f}" for axis in ['neck', 'back', 'legs'])
        )

    rules = {
        axis: {
            'min': personal_angles[axis] - POSTURE_TOLERANCE[axis],
            'max': personal_angles[axis] + POSTURE_TOLERANCE[axis]
        }
        for axis in ['neck', 'back', 'legs']
    }

    training_data = []
    for record in training_records:
        deviation = record.get('adjusted_deviation_from_personal') or record.get('deviation_from_personal')
        if not deviation:
            deviation = record['deviation_from_personal']
        label = record.get('manual_label') or classify_posture_state(record['adjusted_angles'], rules)
        training_data.append({
            'neck_deviation': deviation['neck'],
            'back_deviation': deviation['back'],
            'legs_deviation': deviation['legs'],
            'posture_state': label
        })

    if not training_data:
        print("Error: No valid training data could be created. Training failed.")
        return None

    df = pd.DataFrame(training_data)
    print(f"Successfully processed {len(df)} files. Training model on personalized deviation features...")

    feature_columns = ['neck_deviation', 'back_deviation', 'legs_deviation']
    X = df[feature_columns]
    y = df['posture_state']

    le = LabelEncoder()
    le.fit(y)

    stratify_labels = y if y.nunique() > 1 else None

    if len(df) >= 5 and stratify_labels is not None:
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=0.2,
                random_state=42,
                stratify=stratify_labels,
            )
        except ValueError as exc:
            print(
                "Warning: Stratified split failed (" + str(exc) + "). Falling back to random split without stratification."
            )
            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=0.2,
                random_state=42,
                stratify=None,
            )
    else:
        print("Warning: Not enough samples for a train/test split. Training on all data and skipping evaluation metrics.")
        X_train, y_train = X, y
        X_test = pd.DataFrame(columns=feature_columns)
        y_test = pd.Series(dtype=y.dtype)

    model = lgb.LGBMClassifier(
        objective='multiclass',
        random_state=42,
        num_leaves=7,
        max_depth=3,
        min_data_in_leaf=5,
        min_gain_to_split=0.0,
        verbose=-1,
    )

    y_train_encoded = le.transform(y_train)
    model.fit(X_train, y_train_encoded)

    if not X_test.empty:
        y_test_pred_encoded = model.predict(X_test)
        y_test_pred_labels = le.inverse_transform(y_test_pred_encoded)
        y_test_labels = y_test.values

        labels_order = le.classes_
        cm = confusion_matrix(y_test_labels, y_test_pred_labels, labels=labels_order)
        report = classification_report(y_test_labels, y_test_pred_labels, labels=labels_order, zero_division=0)

        print("\n--- Evaluation Metrics (20% hold-out) ---")
        print("Confusion Matrix (rows=true, cols=pred):")
        header = "          " + "  ".join(f"{label[:12]:>12}" for label in labels_order)
        print(header)
        for idx, row in enumerate(cm):
            row_label = f"{labels_order[idx][:12]:>10}"
            row_values = "  ".join(f"{int(val):>12}" for val in row)
            print(f"{row_label}  {row_values}")
        print("\nClassification Report:")
        print(report)
    else:
        print("Skipping evaluation metrics because no test split was created.")

    os.makedirs(user_profile.root, exist_ok=True)
    joblib.dump(model, user_profile.model_path)
    joblib.dump(le, user_profile.encoder_path)

    metadata = {
        "user_id": user_profile.user_id,
        "trained_at": datetime.now(UTC).isoformat(),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)) if not X_test.empty else 0,
        "base_reference_file": os.path.abspath(BASE_REFERENCE_FILE),
        "personal_reference_file": os.path.abspath(personal_reference_path),
        "reference_offsets": offsets,
        "adjusted_folder": os.path.abspath(user_profile.adjusted_folder),
        "model_path": os.path.abspath(user_profile.model_path),
        "encoder_path": os.path.abspath(user_profile.encoder_path),
    }
    save_user_metadata(user_profile, metadata)

    print(f"Training complete! Personalized model saved to '{user_profile.model_path}'. ✅\n")
    return bundle

def watch_and_predict(user_profile: UserProfile, enable_incremental_training: bool = False):
    """Watch a user's prediction folder and score new samples against their personalized reference."""
    print(f"--- 2. Starting Personalized Prediction Mode for '{user_profile.user_id}' ---")

    try:
        model = joblib.load(user_profile.model_path)
        le = joblib.load(user_profile.encoder_path)
    except FileNotFoundError:
        print(
            f"Error: Personalized model for user '{user_profile.user_id}' not found. "
            "Please train the model first."
        )
        return

    resolution = resolve_reference_angles(
        base_reference_path=BASE_REFERENCE_FILE,
        personal_reference_path=user_profile.reference_path,
    )
    if not resolution:
        print("FATAL: Could not resolve reference angles for prediction.")
        return

    _, personal_angles, offsets, resolved_personal_path = resolution

    os.makedirs(user_profile.predict_folder, exist_ok=True)
    print(
        f"Watching folder: '{user_profile.predict_folder}' with reference "
        f"'{os.path.basename(resolved_personal_path)}'."
    )
    if any(abs(offsets[axis]) > 1e-6 for axis in offsets):
        print(
            "Reference shift relative to base (deg): "
            + ", ".join(f"{axis}={offsets[axis]:+.2f}" for axis in ['neck', 'back', 'legs'])
        )
    if enable_incremental_training:
        print("Incremental augmentation is ENABLED: new captures will be aligned to the base reference and appended to the training corpus.")

    processed_files = set()
    while True:
        try:
            pending_files = set(glob.glob(os.path.join(user_profile.predict_folder, '*.json'))) - processed_files
            for file_path in pending_files:
                filename = os.path.basename(file_path)
                current_angles = get_angles_from_keypoint_file(file_path)

                if current_angles:
                    current_angles = {k: float(current_angles[k]) for k in ['neck', 'back', 'legs']}
                    start_time = time.perf_counter()
                    feature_vector = {
                        'neck_deviation': current_angles['neck'] - personal_angles['neck'],
                        'back_deviation': current_angles['back'] - personal_angles['back'],
                        'legs_deviation': current_angles['legs'] - personal_angles['legs']
                    }
                    features = pd.DataFrame([feature_vector])

                    prediction_encoded = model.predict(features)
                    prediction_label = le.inverse_transform(prediction_encoded)[0]

                    manual_summary = run_manual_posture_check(current_angles, personal_angles)
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                    print(f"File: {filename}")
                    print(f"  ML Prediction : {prediction_label}")
                    print(f"  Manual Label  : {manual_summary['label']}  |  Score: {manual_summary['score']:.2f}")
                    print(f"  Prediction Time : {elapsed_ms:.2f} ms")
                    for detail in manual_summary['details']:
                        print(
                            "    - {region:<5}: {angle:6.1f}°  ->  {status}".format(
                                region=detail['region'].capitalize(),
                                angle=detail['angle'],
                                status=detail['status']
                            )
                        )
                        if detail['status'] != 'GOOD':
                            print(f"        Suggestion: {detail['suggestion']}")

                    if enable_incremental_training:
                        append_adjusted_sample_to_training(
                            user_profile=user_profile,
                            source_file=file_path,
                            current_angles=current_angles,
                            offsets=offsets,
                            original_angles=current_angles,
                        )
                else:
                    print(f"File: {filename}  ->  Could not process (check keypoints).")

                processed_files.add(file_path)
            time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping prediction watcher.")
            break

def main():
    os.makedirs(RAW_TRAIN_FOLDER, exist_ok=True)
    if not os.path.exists(BASE_REFERENCE_FILE):
        print(
            f"FATAL: Base reference file '{BASE_REFERENCE_FILE}' not found. "
            "Create it before running personalized training."
        )
        return

    os.makedirs(USER_PROFILES_ROOT, exist_ok=True)

    user_id = input("Enter user identifier: ").strip()
    if not user_id:
        print("Aborted: user identifier is required.")
        return

    user_profile = build_user_profile(user_id)
    os.makedirs(user_profile.root, exist_ok=True)
    os.makedirs(user_profile.adjusted_folder, exist_ok=True)
    os.makedirs(user_profile.predict_folder, exist_ok=True)

    if not ensure_user_reference(user_profile):
        print("Cannot proceed without a personalized reference posture. Exiting.")
        return

    existing_metadata = load_user_metadata(user_profile)
    if existing_metadata:
        print(
            f"Found previous training for '{user_id}': "
            f"{existing_metadata.get('training_samples', 'unknown')} samples at "
            f"{existing_metadata.get('trained_at', 'unknown')}"
        )

    model_exists = (
        os.path.exists(user_profile.model_path) and
        os.path.exists(user_profile.encoder_path)
    )

    retrain = True
    if model_exists:
        choice = input("Reuse existing personalized model? [Y/n]: ").strip().lower()
        retrain = (choice == 'n')

    if retrain:
        bundle = train_model_for_user(user_profile)
        if not bundle:
            return
    else:
        print("Reusing existing personalized model.")

    incremental_choice = input(
        "Enable incremental augmentation (append processed captures to base training set)? [y/N]: "
    ).strip().lower()
    incremental_enabled = incremental_choice == 'y'

    watch_and_predict(user_profile, enable_incremental_training=incremental_enabled)


if __name__ == "__main__":
    main()