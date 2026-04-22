"""
Training script for the ransomware detection ML model.
Generates synthetic training data if real samples are not available.
Run this once before starting the system for ML-based detection.

Usage: python train_model.py
"""

import os
import sys
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    import joblib
except ImportError:
    print("ERROR: scikit-learn is required. Install it with: pip install scikit-learn")
    sys.exit(1)

from ml_model import RansomwareMLModel


def generate_synthetic_data(n_samples=2000):
    """
    Generate synthetic training data that simulates PE file features.
    In production, replace this with real malware/benign sample features.
    """
    np.random.seed(42)
    n_malware = n_samples // 2
    n_benign = n_samples - n_malware

    # --- BENIGN samples ---
    benign = np.zeros((n_benign, 30))
    benign[:, 0] = np.random.lognormal(mean=13, sigma=1.5, size=n_benign)   # file_size
    benign[:, 1] = np.random.normal(loc=5.5, scale=0.8, size=n_benign)      # entropy
    benign[:, 2] = np.random.randint(3, 8, size=n_benign)                    # num_sections
    benign[:, 3] = np.random.normal(loc=5.0, scale=0.7, size=n_benign)      # avg_section_entropy
    benign[:, 4] = np.random.normal(loc=6.5, scale=0.5, size=n_benign)      # max_section_entropy
    benign[:, 5] = np.random.normal(loc=2.0, scale=1.0, size=n_benign)      # min_section_entropy
    benign[:, 6] = np.random.randint(50, 500, size=n_benign)                 # num_imports
    benign[:, 7] = np.random.randint(3, 20, size=n_benign)                   # num_dlls
    benign[:, 8] = np.random.binomial(1, 0.15, size=n_benign)               # has_crypto (rare in benign)
    benign[:, 9] = np.random.binomial(1, 0.3, size=n_benign)                # has_network
    benign[:, 10] = np.random.binomial(1, 0.8, size=n_benign)               # has_file
    benign[:, 11] = np.random.binomial(1, 0.4, size=n_benign)               # has_process
    benign[:, 12] = np.random.binomial(1, 0.3, size=n_benign)               # has_registry
    benign[:, 13] = np.random.binomial(1, 0.05, size=n_benign)              # has_anti_debug (very rare)
    benign[:, 14] = np.random.binomial(1, 0.1, size=n_benign)               # has_tls
    benign[:, 15] = np.random.binomial(1, 0.8, size=n_benign)               # has_resources
    benign[:, 16] = np.random.binomial(1, 0.5, size=n_benign)               # has_debug
    benign[:, 17] = np.random.binomial(1, 0.6, size=n_benign)               # has_signature
    benign[:, 18] = np.random.randint(1000, 100000, size=n_benign)           # entry_point
    benign[:, 19] = np.random.lognormal(mean=15, sigma=1, size=n_benign)     # image_size
    benign[:, 20] = np.full(n_benign, 16)                                    # num_rva_and_sizes
    benign[:, 21] = np.random.normal(loc=6.0, scale=0.5, size=n_benign)      # text_section_entropy
    benign[:, 22] = np.random.normal(loc=3.5, scale=1.0, size=n_benign)      # data_section_entropy
    benign[:, 23] = np.zeros(n_benign)                                       # suspicious_section_count
    benign[:, 24] = np.random.binomial(1, 0.1, size=n_benign)               # zero_size_sections
    benign[:, 25] = np.zeros(n_benign)                                       # packed_indicator
    benign[:, 26] = np.random.binomial(1, 0.05, size=n_benign)              # timestamp_suspicious
    benign[:, 27] = np.random.poisson(0.2, size=n_benign)                    # string_ransom_count
    benign[:, 28] = np.random.poisson(0.3, size=n_benign)                    # string_crypto_count
    benign[:, 29] = np.random.poisson(1.0, size=n_benign)                    # string_extension_count

    # --- MALWARE samples ---
    malware = np.zeros((n_malware, 30))
    malware[:, 0] = np.random.lognormal(mean=12, sigma=1.5, size=n_malware)  # file_size (often smaller)
    malware[:, 1] = np.random.normal(loc=7.2, scale=0.5, size=n_malware)     # entropy (higher)
    malware[:, 2] = np.random.randint(1, 6, size=n_malware)                  # num_sections (fewer/packed)
    malware[:, 3] = np.random.normal(loc=6.8, scale=0.5, size=n_malware)     # avg_section_entropy
    malware[:, 4] = np.random.normal(loc=7.5, scale=0.3, size=n_malware)     # max_section_entropy
    malware[:, 5] = np.random.normal(loc=5.0, scale=1.0, size=n_malware)     # min_section_entropy
    malware[:, 6] = np.random.randint(5, 200, size=n_malware)                # num_imports (fewer if packed)
    malware[:, 7] = np.random.randint(2, 15, size=n_malware)                 # num_dlls
    malware[:, 8] = np.random.binomial(1, 0.75, size=n_malware)              # has_crypto (very common)
    malware[:, 9] = np.random.binomial(1, 0.6, size=n_malware)               # has_network
    malware[:, 10] = np.random.binomial(1, 0.9, size=n_malware)              # has_file
    malware[:, 11] = np.random.binomial(1, 0.7, size=n_malware)              # has_process
    malware[:, 12] = np.random.binomial(1, 0.5, size=n_malware)              # has_registry
    malware[:, 13] = np.random.binomial(1, 0.4, size=n_malware)              # has_anti_debug
    malware[:, 14] = np.random.binomial(1, 0.3, size=n_malware)              # has_tls
    malware[:, 15] = np.random.binomial(1, 0.4, size=n_malware)              # has_resources
    malware[:, 16] = np.random.binomial(1, 0.1, size=n_malware)              # has_debug (rare)
    malware[:, 17] = np.random.binomial(1, 0.05, size=n_malware)             # has_signature (rarely signed)
    malware[:, 18] = np.random.randint(1000, 100000, size=n_malware)         # entry_point
    malware[:, 19] = np.random.lognormal(mean=14, sigma=1.5, size=n_malware) # image_size
    malware[:, 20] = np.full(n_malware, 16)                                  # num_rva_and_sizes
    malware[:, 21] = np.random.normal(loc=7.0, scale=0.4, size=n_malware)    # text_section_entropy
    malware[:, 22] = np.random.normal(loc=5.5, scale=1.0, size=n_malware)    # data_section_entropy
    malware[:, 23] = np.random.poisson(1.0, size=n_malware)                  # suspicious_section_count
    malware[:, 24] = np.random.poisson(0.5, size=n_malware)                  # zero_size_sections
    malware[:, 25] = np.random.binomial(1, 0.4, size=n_malware)              # packed_indicator
    malware[:, 26] = np.random.binomial(1, 0.3, size=n_malware)              # timestamp_suspicious
    malware[:, 27] = np.random.poisson(3.0, size=n_malware)                  # string_ransom_count
    malware[:, 28] = np.random.poisson(2.0, size=n_malware)                  # string_crypto_count
    malware[:, 29] = np.random.poisson(5.0, size=n_malware)                  # string_extension_count

    # Clip entropy values
    benign[:, 1] = np.clip(benign[:, 1], 0, 8)
    malware[:, 1] = np.clip(malware[:, 1], 0, 8)
    benign[:, 3] = np.clip(benign[:, 3], 0, 8)
    malware[:, 3] = np.clip(malware[:, 3], 0, 8)

    X = np.vstack([benign, malware])
    y = np.hstack([np.zeros(n_benign), np.ones(n_malware)])

    # Shuffle
    indices = np.random.permutation(len(y))
    X = X[indices]
    y = y[indices]

    return X, y


def main():
    print("=" * 60)
    print("  Ransomware Detection - ML Model Training")
    print("=" * 60)

    # Generate training data
    print("\n[1/4] Generating synthetic training data...")
    X, y = generate_synthetic_data(n_samples=3000)
    print(f"  Total samples: {len(y)}")
    print(f"  Benign: {int(sum(y == 0))}")
    print(f"  Malware: {int(sum(y == 1))}")

    # Split data
    print("\n[2/4] Splitting into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Training set: {len(y_train)} samples")
    print(f"  Test set: {len(y_test)} samples")

    # Train model
    print("\n[3/4] Training model...")
    model = RansomwareMLModel()
    
    model.scaler = StandardScaler()
    X_train_scaled = model.scaler.fit_transform(X_train)
    X_test_scaled = model.scaler.transform(X_test)

    model.model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.8
    )
    model.model.fit(X_train_scaled, y_train)

    # Evaluate
    print("\n[4/4] Evaluating model...")
    train_score = model.model.score(X_train_scaled, y_train)
    test_score = model.model.score(X_test_scaled, y_test)

    y_pred = model.model.predict(X_test_scaled)

    print(f"\n  Training Accuracy: {train_score:.4f}")
    print(f"  Testing Accuracy:  {test_score:.4f}")

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))

    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    True Negatives:  {cm[0][0]}")
    print(f"    False Positives: {cm[0][1]}")
    print(f"    False Negatives: {cm[1][0]}")
    print(f"    True Positives:  {cm[1][1]}")

    # Cross-validation
    print("\n  Cross-validation scores:")
    cv_scores = cross_val_score(model.model, X_train_scaled, y_train, cv=5)
    print(f"    Scores: {cv_scores}")
    print(f"    Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # Feature importance
    print("\n  Top 10 Feature Importances:")
    importances = model.model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for i in range(min(10, len(indices))):
        idx = indices[i]
        print(f"    {i+1}. {model.FEATURE_NAMES[idx]}: {importances[idx]:.4f}")

    # Save model
    model.save_model()
    print(f"\n  Model saved to: {model.model_path}")
    print("\n" + "=" * 60)
    print("  Training Complete! You can now start the server.")
    print("=" * 60)


if __name__ == '__main__':
    main()