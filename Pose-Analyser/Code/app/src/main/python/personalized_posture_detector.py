"""
Personalized Posture Detection Module for Android
This module provides GradientBoosting-based personalized posture detection with user calibration.
Adapted from Model/lightGBM/lightGBM.py for Chaquopy integration.
Uses scikit-learn's GradientBoostingClassifier instead of LightGBM for Android compatibility.
"""

import os
import json
import glob
import copy
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
from datetime import datetime

# Configuration
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


class PersonalizedPostureDetector:
    """
    Personalized posture detector using Gradient Boosting model trained on user's reference posture.
    Uses scikit-learn for Android compatibility (no native dependencies).
    """
    
    def __init__(self, assets_dir, internal_dir):
        """
        Initialize the personalized posture detector.
        
        Args:
            assets_dir: Path to app's assets directory (read-only, contains trainGBM baseline data)
            internal_dir: Path to app's internal storage (read-write, for user profiles)
        """
        self.assets_dir = assets_dir
        self.internal_dir = internal_dir
        self.base_train_folder = os.path.join(assets_dir, 'lightGBM', 'trainGBM')
        self.base_reference_file = os.path.join(assets_dir, 'lightGBM', 'reference_posture.json')
        self.user_profiles_root = os.path.join(internal_dir, 'user_profiles')
        
        self.model = None
        self.encoder = None
        self.personal_angles = None
        self.current_user_id = None
        self.reference_offsets = None
        
    def get_user_profile_path(self, user_id):
        """Get the path for a user's profile directory."""
        return os.path.join(self.user_profiles_root, user_id)
    
    def user_exists(self, user_id):
        """Check if a user profile exists."""
        user_path = self.get_user_profile_path(user_id)
        model_path = os.path.join(user_path, 'gradient_boost_model.pkl')
        encoder_path = os.path.join(user_path, 'label_encoder.pkl')
        reference_path = os.path.join(user_path, 'reference_posture.json')
        return os.path.exists(model_path) and os.path.exists(encoder_path) and os.path.exists(reference_path)
    
    def save_reference_posture(self, user_id, angles_dict):
        """
        Save user's reference posture (when sitting straight).
        
        Args:
            user_id: User identifier
            angles_dict: Dictionary with 'neck', 'back', 'legs' angles
        
        Returns:
            bool: True if successful
        """
        try:
            print(f"[PersonalizedPosture] Saving reference for user: {user_id}")
            print(f"[PersonalizedPosture] Angles: {angles_dict}")
            print(f"[PersonalizedPosture] Internal dir: {self.internal_dir}")
            
            user_path = self.get_user_profile_path(user_id)
            print(f"[PersonalizedPosture] User path: {user_path}")
            
            os.makedirs(user_path, exist_ok=True)
            print(f"[PersonalizedPosture] Directory created/verified")
            
            reference_path = os.path.join(user_path, 'reference_posture.json')
            print(f"[PersonalizedPosture] Reference path: {reference_path}")
            
            reference_data = {
                'angles': angles_dict,
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id
            }
            
            with open(reference_path, 'w') as f:
                json.dump(reference_data, f, indent=2)
            
            print(f"[PersonalizedPosture] Reference posture saved successfully!")
            return True
        except Exception as e:
            print(f"[PersonalizedPosture] ERROR saving reference posture: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _calculate_angle(self, a, b, c):
        """Calculate the angle ABC (in degrees) given three 2D points."""
        a, b, c = np.array(a, dtype=float), np.array(b, dtype=float), np.array(c, dtype=float)
        ba = a - b
        bc = c - b
        denom = (np.linalg.norm(ba) * np.linalg.norm(bc)) + 1e-6
        cosine = np.clip(np.dot(ba, bc) / denom, -1.0, 1.0)
        return float(np.degrees(np.arccos(cosine)))

    def _normalise_keypoints(self, raw_keypoints):
        lookup = {}
        if isinstance(raw_keypoints, dict):
            for label, payload in raw_keypoints.items():
                if isinstance(payload, dict):
                    lookup[label] = payload
                elif isinstance(payload, (list, tuple)) and len(payload) >= 3:
                    lookup[label] = {
                        'x': payload[0],
                        'y': payload[1],
                        'confidence': payload[2]
                    }
            return lookup

        if isinstance(raw_keypoints, list):
            for entry in raw_keypoints:
                if not isinstance(entry, dict):
                    continue
                name = (
                    entry.get('part_name')
                    or entry.get('name')
                    or entry.get('part')
                    or entry.get('id')
                )
                if not name:
                    continue
                position = entry.get('position') if isinstance(entry.get('position'), dict) else {}
                lookup[name] = {
                    'x': entry.get('x', position.get('x')),
                    'y': entry.get('y', position.get('y')),
                    'confidence': entry.get('confidence', entry.get('score', entry.get('probability'))),
                    'visible': entry.get('visible', entry.get('is_visible', True))
                }
        return lookup

    def _confidence(self, point):
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

    def _build_keypoints_lookup(self, payload):
        if not isinstance(payload, dict):
            return {}

        persons = payload.get('persons') or payload.get('people')
        keypoints_lookup = {}

        if isinstance(persons, list) and persons:
            person_entry = persons[0]
            if isinstance(person_entry, dict):
                for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
                    if candidate_key in person_entry:
                        keypoints_lookup = self._normalise_keypoints(person_entry[candidate_key])
                        if keypoints_lookup:
                            break

        if not keypoints_lookup:
            for candidate_key in ('keypoints', 'pose_keypoints', 'pose_keypoints_2d'):
                if candidate_key in payload:
                    keypoints_lookup = self._normalise_keypoints(payload[candidate_key])
                    if keypoints_lookup:
                        break

        return keypoints_lookup

    def _extract_keypoint_coordinates_from_payload(self, payload):
        lookup = self._build_keypoints_lookup(payload)
        coords = {}
        for name, point in lookup.items():
            try:
                coords[name] = {
                    'x': float(point.get('x')),
                    'y': float(point.get('y'))
                }
            except (TypeError, ValueError):
                continue
        return coords

    def load_keypoint_coordinates(self, filepath):
        try:
            with open(filepath, 'r') as handle:
                payload = json.load(handle)
        except Exception:
            return {}
        return self._extract_keypoint_coordinates_from_payload(payload)

    def compute_keypoint_coordinate_offsets(self, base_map, personal_map):
        offsets = {}
        if not base_map or not personal_map:
            return offsets
        for name, base_point in base_map.items():
            personal_point = personal_map.get(name)
            if not personal_point:
                continue
            try:
                offsets[name] = {
                    'x': float(personal_point['x']) - float(base_point['x']),
                    'y': float(personal_point['y']) - float(base_point['y'])
                }
            except (TypeError, ValueError, KeyError):
                continue
        return offsets

    def apply_keypoint_offsets_to_payload(self, payload, keypoint_offsets):
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

    def get_angles_from_payload(self, data):
        def _extract_angles(candidate):
            if not isinstance(candidate, dict):
                return None
            keys = ['neck', 'back', 'legs']
            if all(k in candidate for k in keys):
                try:
                    return {k: float(candidate[k]) for k in keys}
                except (TypeError, ValueError):
                    return None
            return None

        if isinstance(data, dict):
            for key in ('adjusted_angles', 'personalized_angles', 'angles', 'reference_angles'):
                angles = _extract_angles(data.get(key))
                if angles:
                    return angles
            direct = _extract_angles(data)
            if direct:
                return direct

        keypoints_lookup = self._build_keypoints_lookup(data)
        if not keypoints_lookup:
            return None

        left_conf = self._confidence(keypoints_lookup.get('left_ear'))
        right_conf = self._confidence(keypoints_lookup.get('right_ear'))
        side = 'left' if left_conf >= right_conf else 'right'

        required_parts = {
            'ear': f'{side}_ear',
            'shoulder': f'{side}_shoulder',
            'hip': f'{side}_hip',
            'knee': f'{side}_knee',
            'ankle': f'{side}_ankle'
        }

        coords = {}
        for label, part_key in required_parts.items():
            point = keypoints_lookup.get(part_key)
            if self._confidence(point) < CONFIDENCE_THRESHOLD:
                return None
            try:
                coords[label] = [float(point.get('x')), float(point.get('y'))]
            except (TypeError, ValueError):
                return None

        return {
            'neck': self._calculate_angle(coords['hip'], coords['shoulder'], coords['ear']),
            'back': self._calculate_angle(coords['knee'], coords['hip'], coords['shoulder']),
            'legs': self._calculate_angle(coords['ankle'], coords['knee'], coords['hip'])
        }

    def _extract_angles_from_data(self, data):
        """
        Extract neck/back/legs angles from various JSON payload formats.
        Supports direct angle storage as well as raw keypoint dumps.
        """
        return self.get_angles_from_payload(data)

    def load_reference_angles(self, reference_path):
        """Load angles from a reference posture JSON or raw keypoint file."""
        try:
            with open(reference_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error loading reference angles from {reference_path}: {e}")
            return None

        angles = self._extract_angles_from_data(data)
        if angles is None:
            print(f"Warning: Unable to extract angles from {reference_path}")
            return None
        return angles
    
    def build_manual_rules(self, personal_angles):
        """Build tolerance-based rules for posture classification."""
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
    
    def classify_posture_state(self, angles, rules):
        """Generate a classification label based on tolerance rules."""
        state = tuple(
            "GOOD" if rules[r]['min'] <= angles[r] <= rules[r]['max'] else "BAD"
            for r in ['neck', 'back', 'legs']
        )
        
        posture_states = {
            ("GOOD", "GOOD", "GOOD"): "Aligned Posture",
            ("GOOD", "GOOD", "BAD"): "Legs Misalignment",
            ("GOOD", "BAD", "GOOD"): "Back Misalignment",
            ("GOOD", "BAD", "BAD"): "Back & Legs Misalignment",
            ("BAD", "GOOD", "GOOD"): "Neck Misalignment",
            ("BAD", "GOOD", "BAD"): "Neck & Legs Misalignment",
            ("BAD", "BAD", "GOOD"): "Neck & Back Misalignment",
            ("BAD", "BAD", "BAD"): "Full Body Misalignment",
        }
        return posture_states.get(state, "Unknown")
    
    def compute_manual_max_deviation(self, personal_angles):
        """Calculate maximum possible weighted deviation for scoring."""
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
    
    def calculate_manual_score(self, current_angles, personal_angles, max_threshold):
        """Calculate posture score (0-100) based on weighted deviation."""
        deviations = {
            region: (current_angles[region] - personal_angles[region]) ** 2
            for region in ['neck', 'back', 'legs']
        }
        weighted_deviation = sum(ANGLE_WEIGHTS[region] * deviations[region] for region in ['neck', 'back', 'legs'])
        
        if max_threshold <= 0:
            return 100.0 if weighted_deviation <= 1e-6 else 0.0
        
        score = 1 - (weighted_deviation / max_threshold)
        return max(0.0, min(100.0, score * 100))
    
    def run_manual_posture_check(self, current_angles, personal_angles):
        """Perform rule-based posture analysis."""
        manual_rules = self.build_manual_rules(personal_angles)
        max_threshold = self.compute_manual_max_deviation(personal_angles)
        
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
        
        manual_label = self.classify_posture_state(current_angles, manual_rules)
        manual_score = self.calculate_manual_score(current_angles, personal_angles, max_threshold)
        
        return {
            'label': manual_label,
            'score': manual_score,
            'details': analysis_rows
        }
    
    def resolve_reference_angles(self, user_reference_path):
        """Resolve baseline and personalized reference posture angles and compute offsets."""
        base_angles = self.load_reference_angles(self.base_reference_file)
        if not base_angles:
            print(f"Error: Could not load base reference from {self.base_reference_file}")
            return None

        base_angles = {axis: float(base_angles[axis]) for axis in ['neck', 'back', 'legs']}

        personal_path = user_reference_path if os.path.exists(user_reference_path) else None
        personal_angles = self.load_reference_angles(personal_path) if personal_path else None

        if not personal_angles:
            if personal_path:
                print(f"Warning: Personalized reference '{personal_path}' not found. Falling back to base reference.")
            personal_angles = base_angles
            personal_path = self.base_reference_file
        else:
            personal_angles = {axis: float(personal_angles[axis]) for axis in ['neck', 'back', 'legs']}

        offsets = {
            axis: float(personal_angles[axis] - base_angles.get(axis, personal_angles[axis]))
            for axis in ['neck', 'back', 'legs']
        }

        return base_angles, personal_angles, offsets, personal_path

    def prepare_training_data(self, user_id):
        """
        Prepare adjusted training data for a user based on their reference posture.
        
        Args:
            user_id: User identifier
        
        Returns:
            Dictionary with training data and metadata, or None if failed
        """
        try:
            user_path = self.get_user_profile_path(user_id)
            user_reference_path = os.path.join(user_path, 'reference_posture.json')
            adjusted_folder = os.path.join(user_path, 'train_adjusted')

            resolution = self.resolve_reference_angles(user_reference_path)
            if not resolution:
                return None

            base_angles, personal_angles, offsets, resolved_personal_path = resolution

            os.makedirs(adjusted_folder, exist_ok=True)

            base_keypoints = self.load_keypoint_coordinates(self.base_reference_file)
            personal_keypoints = self.load_keypoint_coordinates(resolved_personal_path)
            keypoint_coordinate_offsets = self.compute_keypoint_coordinate_offsets(base_keypoints, personal_keypoints)

            # Clear previously adjusted files to avoid stale data.
            for stale_file in glob.glob(os.path.join(adjusted_folder, '*.json')):
                try:
                    os.remove(stale_file)
                except OSError:
                    pass

            train_files = glob.glob(os.path.join(self.base_train_folder, '*.json'))
            if not train_files:
                print(f"Error: No training files found in {self.base_train_folder}")
                return None

            excluded_paths = {
                os.path.abspath(self.base_reference_file),
                os.path.abspath(resolved_personal_path)
            }

            training_records = []
            for filepath in train_files:
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

                current_angles = self.get_angles_from_payload(raw_payload)
                if not current_angles:
                    print(f"Skipping training file with insufficient keypoints: {os.path.basename(filepath)}")
                    continue

                current_angles = {axis: float(current_angles[axis]) for axis in ['neck', 'back', 'legs']}
                deviation_from_personal = {
                    axis: float(current_angles[axis] - personal_angles[axis])
                    for axis in ['neck', 'back', 'legs']
                }

                adjusted_payload = self.apply_keypoint_offsets_to_payload(raw_payload, keypoint_coordinate_offsets)
                adjusted_payload_angles = self.get_angles_from_payload(adjusted_payload)
                if adjusted_payload_angles:
                    adjusted_angles = {
                        axis: float(adjusted_payload_angles[axis])
                        for axis in ['neck', 'back', 'legs']
                    }
                else:
                    adjusted_angles = {
                        axis: float(current_angles[axis] + offsets[axis])
                        for axis in ['neck', 'back', 'legs']
                    }

                adjusted_deviation_from_personal = {
                    axis: float(adjusted_angles[axis] - personal_angles[axis])
                    for axis in ['neck', 'back', 'legs']
                }

                manual_summary = self.run_manual_posture_check(adjusted_angles, personal_angles)
                manual_label = manual_summary['label']
                manual_score = manual_summary['score']

                record = {
                    'user_id': user_id,
                    'source_file': os.path.basename(filepath),
                    'base_reference_file': os.path.basename(self.base_reference_file),
                    'personal_reference_file': os.path.basename(resolved_personal_path),
                    'reference_offsets': {axis: offsets[axis] for axis in ['neck', 'back', 'legs']},
                    'original_angles': current_angles,
                    'adjusted_angles': adjusted_angles,
                    'deviation_from_personal': deviation_from_personal,
                    'adjusted_deviation_from_personal': adjusted_deviation_from_personal,
                    'manual_label': manual_label,
                    'manual_score': manual_score
                }

                training_records.append(record)

                personalization_block = {
                    'user_id': user_id,
                    'base_reference_file': os.path.basename(self.base_reference_file),
                    'personal_reference_file': os.path.basename(resolved_personal_path),
                    'reference_offsets': {axis: offsets[axis] for axis in ['neck', 'back', 'legs']},
                    'original_angles': current_angles,
                    'adjusted_angles': adjusted_angles,
                    'deviation_from_personal': deviation_from_personal,
                    'keypoint_coordinate_offsets': copy.deepcopy(keypoint_coordinate_offsets),
                    'adjusted_at': datetime.now().isoformat(),
                    'manual_label': manual_label,
                    'manual_score': manual_score
                }

                if isinstance(adjusted_payload, dict):
                    augmented_payload = adjusted_payload
                    augmented_payload['personalization_adjustment'] = personalization_block
                else:
                    augmented_payload = {
                        'personalization_adjustment': personalization_block,
                        'raw_payload': adjusted_payload
                    }

                try:
                    output_path = os.path.join(adjusted_folder, os.path.basename(filepath))
                    with open(output_path, 'w') as handle:
                        json.dump(augmented_payload, handle, indent=2)
                    record['adjusted_payload_path'] = output_path
                except Exception as exc:
                    print(f"Warning: Unable to persist adjusted record for {filepath}: {exc}")

            if not training_records:
                print("Error: No valid training data could be created after adjustment")
                return None

            print(
                f"Prepared {len(training_records)} adjusted samples for user '{user_id}' in '{adjusted_folder}'."
            )
            if any(abs(offsets[axis]) > 1e-6 for axis in offsets):
                offsets_str = ", ".join(f"{axis}={offsets[axis]:+.2f}" for axis in ['neck', 'back', 'legs'])
                print(f"Applied reference offsets (deg): {offsets_str}")

            return {
                'base_angles': base_angles,
                'personal_angles': personal_angles,
                'offsets': offsets,
                'training_records': training_records,
                'personal_reference_path': resolved_personal_path,
                'adjusted_folder': adjusted_folder,
                'keypoint_coordinate_offsets': keypoint_coordinate_offsets
            }
        except Exception as e:
            print(f"Error preparing training data: {e}")
            return None
    
    def train_model(self, user_id):
        """
        Train a personalized LightGBM model for a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            bool: True if training successful
        """
        try:
            print(f"Starting personalized model training for user '{user_id}'...")
            
            bundle = self.prepare_training_data(user_id)
            if not bundle:
                return False
            
            personal_angles = bundle['personal_angles']
            offsets = bundle['offsets']
            training_records = bundle['training_records']
            adjusted_folder = bundle['adjusted_folder']
            personal_reference_path = bundle['personal_reference_path']
            keypoint_coordinate_offsets = bundle.get('keypoint_coordinate_offsets')

            rules = {
                axis: {
                    'min': personal_angles[axis] - POSTURE_TOLERANCE[axis],
                    'max': personal_angles[axis] + POSTURE_TOLERANCE[axis]
                }
                for axis in ['neck', 'back', 'legs']
            }

            processed_rows = []
            for record in training_records:
                deviation = record.get('adjusted_deviation_from_personal') or record['deviation_from_personal']
                label = record.get('manual_label') or self.classify_posture_state(record['adjusted_angles'], rules)
                processed_rows.append({
                    'neck_deviation': deviation['neck'],
                    'back_deviation': deviation['back'],
                    'legs_deviation': deviation['legs'],
                    'posture_state': label
                })

            if not processed_rows:
                print("Error: No valid training data could be created. Training failed.")
                return False

            df = pd.DataFrame(processed_rows)
            print(f"Training on {len(df)} personalized deviation samples...")

            feature_columns = ['neck_deviation', 'back_deviation', 'legs_deviation']
            X = df[feature_columns]
            y = df['posture_state']

            le = LabelEncoder()
            le.fit(y)
            encoded_y = le.transform(y)

            X_train = X
            y_train = y
            X_test = None
            y_test = None

            if len(le.classes_) < 2:
                model = DummyClassifier(strategy='most_frequent')
                model.fit(X, encoded_y)
                training_sample_count = len(X)
            else:
                if len(df) >= 5:
                    try:
                        X_train, X_test, y_train, y_test = train_test_split(
                            X, y, test_size=0.2, random_state=42, stratify=y
                        )
                    except ValueError:
                        X_train, y_train = X, y
                        X_test = None
                        y_test = None
                else:
                    X_train, y_train = X, y
                    X_test = None
                    y_test = None

                model = GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=3,
                    min_samples_leaf=5,
                    random_state=42,
                    verbose=0
                )

                y_train_encoded = le.transform(y_train)
                model.fit(X_train, y_train_encoded)
                training_sample_count = len(X_train)

                if X_test is not None and y_test is not None and not X_test.empty:
                    y_pred_encoded = model.predict(X_test)
                    y_pred = le.inverse_transform(y_pred_encoded)
                    print("Evaluation split summary:")
                    unique, counts = np.unique(y_pred, return_counts=True)
                    summary = ", ".join(f"{label}:{count}" for label, count in zip(unique, counts))
                    print(f"  Predictions by class -> {summary}")

            # Save model and encoder
            user_path = self.get_user_profile_path(user_id)
            os.makedirs(user_path, exist_ok=True)
            
            model_path = os.path.join(user_path, 'gradient_boost_model.pkl')
            encoder_path = os.path.join(user_path, 'label_encoder.pkl')
            
            joblib.dump(model, model_path)
            joblib.dump(le, encoder_path)
            
            # Cache personalized context in memory for immediate predictions
            self.model = model
            self.encoder = le
            self.personal_angles = personal_angles
            self.reference_offsets = offsets
            self.current_user_id = user_id

            # Save metadata
            metadata = {
                'user_id': user_id,
                'trained_at': datetime.now().isoformat(),
                'training_samples': int(training_sample_count),
                'base_reference_file': os.path.abspath(self.base_reference_file),
                'personal_reference_file': os.path.abspath(personal_reference_path),
                'adjusted_folder': os.path.abspath(adjusted_folder),
                'personal_angles': personal_angles,
                'reference_offsets': offsets,
                'keypoint_coordinate_offsets': keypoint_coordinate_offsets
            }
            
            metadata_path = os.path.join(user_path, 'profile.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"Training complete! Model saved to {model_path}")
            return True
            
        except Exception as e:
            print(f"Error training model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_model(self, user_id):
        """
        Load a trained model for a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            bool: True if model loaded successfully
        """
        try:
            user_path = self.get_user_profile_path(user_id)
            model_path = os.path.join(user_path, 'gradient_boost_model.pkl')
            encoder_path = os.path.join(user_path, 'label_encoder.pkl')
            reference_path = os.path.join(user_path, 'reference_posture.json')
            
            if not os.path.exists(model_path) or not os.path.exists(encoder_path):
                print(f"Model not found for user '{user_id}'")
                return False
            
            self.model = joblib.load(model_path)
            self.encoder = joblib.load(encoder_path)

            metadata_path = os.path.join(user_path, 'profile.json')
            personal_angles = None
            reference_offsets = None

            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r') as handle:
                        metadata = json.load(handle)
                    stored_angles = metadata.get('personal_angles')
                    if isinstance(stored_angles, dict):
                        personal_angles = {
                            axis: float(stored_angles[axis])
                            for axis in ['neck', 'back', 'legs']
                            if axis in stored_angles
                        }
                    stored_offsets = metadata.get('reference_offsets')
                    if isinstance(stored_offsets, dict):
                        reference_offsets = {
                            axis: float(stored_offsets.get(axis, 0.0))
                            for axis in ['neck', 'back', 'legs']
                        }
                except Exception as exc:
                    print(f"Warning: Unable to read metadata for user '{user_id}': {exc}")

            if personal_angles is None:
                fallback_angles = self.load_reference_angles(reference_path)
                if fallback_angles:
                    personal_angles = {
                        axis: float(fallback_angles[axis])
                        for axis in ['neck', 'back', 'legs']
                        if axis in fallback_angles
                    }

            if personal_angles is None:
                print(f"Error: Could not load personalized reference angles for user '{user_id}'")
                return False

            self.personal_angles = personal_angles
            self.reference_offsets = reference_offsets
            self.current_user_id = user_id
            
            print(f"Model loaded for user '{user_id}'")
            return True
            
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict(self, angles_dict):
        """
        Predict posture state for given angles using the loaded model.
        
        Args:
            angles_dict: Dictionary with 'neck', 'back', 'legs' angles
        
        Returns:
            Dictionary with prediction results, or None if error
        """
        try:
            if self.model is None or self.encoder is None or self.personal_angles is None:
                print("Error: Model not loaded. Call load_model() first.")
                return None
            
            current_angles = {
                'neck': float(angles_dict['neck']),
                'back': float(angles_dict['back']),
                'legs': float(angles_dict['legs'])
            }
            
            # Calculate deviations
            feature_vector = {
                'neck_deviation': current_angles['neck'] - self.personal_angles['neck'],
                'back_deviation': current_angles['back'] - self.personal_angles['back'],
                'legs_deviation': current_angles['legs'] - self.personal_angles['legs']
            }
            
            features = pd.DataFrame([feature_vector])
            
            # ML prediction
            prediction_encoded = self.model.predict(features)
            prediction_label = self.encoder.inverse_transform(prediction_encoded)[0]
            
            # Manual posture check
            manual_summary = self.run_manual_posture_check(current_angles, self.personal_angles)
            
            # Collect suggestions
            suggestions = []
            for detail in manual_summary['details']:
                if detail['status'] != 'GOOD':
                    suggestions.append(detail['suggestion'])
            
            return {
                'ml_prediction': prediction_label,
                'manual_label': manual_summary['label'],
                'score': int(manual_summary['score']),
                'suggestions': suggestions,
                'angles': current_angles,
                'details': manual_summary['details']
            }
            
        except Exception as e:
            print(f"Error predicting: {e}")
            import traceback
            traceback.print_exc()
            return None


# Standalone functions for Chaquopy interface
_detector = None


def initialize(assets_dir, internal_dir):
    """Initialize the personalized detector with Android directories."""
    global _detector
    _detector = PersonalizedPostureDetector(assets_dir, internal_dir)
    return True


def user_exists(user_id):
    """Check if a user profile exists."""
    if _detector is None:
        return False
    return _detector.user_exists(user_id)


def save_reference_posture(user_id, neck_angle, back_angle, legs_angle):
    """Save user's reference posture."""
    if _detector is None:
        return False
    angles = {'neck': neck_angle, 'back': back_angle, 'legs': legs_angle}
    return _detector.save_reference_posture(user_id, angles)


def train_model(user_id):
    """Train model for user."""
    if _detector is None:
        return False
    return _detector.train_model(user_id)


def load_model(user_id):
    """Load trained model for user."""
    if _detector is None:
        return False
    return _detector.load_model(user_id)


def predict(neck_angle, back_angle, legs_angle):
    """Predict posture state."""
    if _detector is None:
        return None
    angles = {'neck': neck_angle, 'back': back_angle, 'legs': legs_angle}
    result = _detector.predict(angles)
    if result is None:
        return None
    # Convert to JSON string for Chaquopy
    return json.dumps(result)
