"""
Machine Learning Model for Ransomware Detection
Uses features extracted from PE files to classify malware vs benign
"""

import os
import math
import json
import logging
import hashlib
from collections import Counter
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn not installed. ML model disabled.")


class RansomwareMLModel:
    """ML-based ransomware detection model"""

    FEATURE_NAMES = [
        'file_size',
        'entropy',
        'num_sections',
        'avg_section_entropy',
        'max_section_entropy',
        'min_section_entropy',
        'num_imports',
        'num_dlls',
        'has_crypto_imports',
        'has_network_imports',
        'has_file_imports',
        'has_process_imports',
        'has_registry_imports',
        'has_anti_debug_imports',
        'has_tls',
        'has_resources',
        'has_debug',
        'has_signature',
        'entry_point',
        'image_size',
        'num_rva_and_sizes',
        'text_section_entropy',
        'data_section_entropy',
        'suspicious_section_count',
        'zero_size_sections',
        'packed_indicator',
        'timestamp_suspicious',
        'string_ransom_count',
        'string_crypto_count',
        'string_extension_count',
    ]

    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'models'
        )
        os.makedirs(self.model_path, exist_ok=True)

    def extract_features(self, filepath):
        """Extract numerical features from a file for ML classification"""
        features = np.zeros(len(self.FEATURE_NAMES))

        try:
            file_size = os.path.getsize(filepath)
            features[0] = file_size

            # Read file data
            with open(filepath, 'rb') as f:
                data = f.read()

            # Overall entropy
            features[1] = self._calculate_entropy(data)

            if not HAS_PEFILE:
                return features

            try:
                pe = pefile.PE(filepath)
            except pefile.PEFormatError:
                return features

            # Number of sections
            features[2] = pe.FILE_HEADER.NumberOfSections

            # Section entropies
            section_entropies = []
            text_entropy = 0
            data_entropy = 0
            suspicious_sections = 0
            zero_size_sections = 0

            suspicious_names = {'.UPX', 'UPX0', 'UPX1', '.aspack', '.adata',
                              '.themida', '.vmp0', '.vmp1', '.petite', '.packed', '.nsp'}

            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                ent = section.get_entropy()
                section_entropies.append(ent)

                if name in suspicious_names:
                    suspicious_sections += 1
                if section.SizeOfRawData == 0:
                    zero_size_sections += 1
                if '.text' in name.lower():
                    text_entropy = ent
                if '.data' in name.lower() or '.rdata' in name.lower():
                    data_entropy = ent

            if section_entropies:
                features[3] = np.mean(section_entropies)
                features[4] = max(section_entropies)
                features[5] = min(section_entropies)
            
            features[21] = text_entropy
            features[22] = data_entropy
            features[23] = suspicious_sections
            features[24] = zero_size_sections

            # Packed indicator (high entropy + few imports)
            features[25] = 1 if (features[1] > 7.0 and features[2] <= 3) else 0

            # Import analysis
            num_imports = 0
            num_dlls = 0
            has_crypto = 0
            has_network = 0
            has_file = 0
            has_process = 0
            has_registry = 0
            has_anti_debug = 0

            crypto_funcs = {'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptDeriveKey',
                           'BCryptEncrypt', 'BCryptDecrypt', 'CryptAcquireContextA'}
            network_funcs = {'InternetOpenA', 'InternetOpenW', 'HttpSendRequestA',
                            'URLDownloadToFileA', 'WSAStartup', 'connect', 'send', 'recv'}
            file_funcs = {'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile',
                         'DeleteFileA', 'DeleteFileW', 'FindFirstFileA', 'FindFirstFileW'}
            process_funcs = {'CreateProcessA', 'CreateProcessW', 'ShellExecuteA',
                            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'}
            registry_funcs = {'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA'}
            antidebug_funcs = {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                              'NtQueryInformationProcess'}

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    num_dlls += 1
                    for imp in entry.imports:
                        if imp.name:
                            num_imports += 1
                            func = imp.name.decode('utf-8', errors='ignore')
                            if func in crypto_funcs:
                                has_crypto = 1
                            if func in network_funcs:
                                has_network = 1
                            if func in file_funcs:
                                has_file = 1
                            if func in process_funcs:
                                has_process = 1
                            if func in registry_funcs:
                                has_registry = 1
                            if func in antidebug_funcs:
                                has_anti_debug = 1

            features[6] = num_imports
            features[7] = num_dlls
            features[8] = has_crypto
            features[9] = has_network
            features[10] = has_file
            features[11] = has_process
            features[12] = has_registry
            features[13] = has_anti_debug

            # Other PE features
            features[14] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
            features[15] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
            features[16] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
            features[17] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0
            features[18] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features[19] = pe.OPTIONAL_HEADER.SizeOfImage
            features[20] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

            # Timestamp analysis
            ts = pe.FILE_HEADER.TimeDateStamp
            features[26] = 1 if (ts == 0 or ts > 2000000000) else 0

            pe.close()

            # String analysis features
            data_lower = data.lower()
            
            ransom_keywords = [b'encrypt', b'decrypt', b'ransom', b'bitcoin', b'btc',
                             b'your files', b'locked', b'payment', b'.onion']
            crypto_keywords = [b'aes', b'rsa', b'rijndael', b'cryptoapi', b'cipher']
            ext_keywords = [b'.doc', b'.pdf', b'.jpg', b'.xlsx', b'.pptx', b'.zip',
                          b'.sql', b'.mdb', b'.psd', b'.mp3', b'.mp4']

            features[27] = sum(1 for kw in ransom_keywords if kw in data_lower)
            features[28] = sum(1 for kw in crypto_keywords if kw in data_lower)
            features[29] = sum(1 for ext in ext_keywords if ext in data_lower)

        except Exception as e:
            logger.error(f"Feature extraction error: {e}")

        return features

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        byte_counts = Counter(data)
        length = len(data)
        entropy = 0
        for count in byte_counts.values():
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def load_model(self):
        """Load trained model from disk"""
        model_file = os.path.join(self.model_path, 'ransomware_model.joblib')
        scaler_file = os.path.join(self.model_path, 'feature_scaler.joblib')

        if os.path.exists(model_file) and os.path.exists(scaler_file):
            self.model = joblib.load(model_file)
            self.scaler = joblib.load(scaler_file)
            logger.info("ML model loaded successfully")
            return True
        else:
            logger.warning("No trained model found. Using heuristic fallback.")
            return False

    def save_model(self):
        """Save model to disk"""
        if self.model and self.scaler:
            joblib.dump(self.model, os.path.join(self.model_path, 'ransomware_model.joblib'))
            joblib.dump(self.scaler, os.path.join(self.model_path, 'feature_scaler.joblib'))
            logger.info("Model saved successfully")

    def train(self, X, y):
        """Train the model"""
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn is not installed")

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            min_samples_split=5,
            min_samples_leaf=2
        )
        self.model.fit(X_scaled, y)
        self.save_model()

        accuracy = self.model.score(X_scaled, y)
        logger.info(f"Model trained with accuracy: {accuracy:.4f}")
        return accuracy

    def predict(self, filepath):
        """Predict if a file is ransomware"""
        features = self.extract_features(filepath)

        # If model is loaded, use it
        if self.model is not None and self.scaler is not None:
            try:
                features_scaled = self.scaler.transform(features.reshape(1, -1))
                prediction = self.model.predict(features_scaled)[0]
                probability = self.model.predict_proba(features_scaled)[0]

                return {
                    'is_malware': bool(prediction == 1),
                    'confidence': float(max(probability)),
                    'probability_benign': float(probability[0]),
                    'probability_malware': float(probability[1]),
                    'method': 'ml_model'
                }
            except Exception as e:
                logger.error(f"ML prediction error: {e}")

        # Fallback: heuristic-based scoring
        return self._heuristic_predict(features)

    def _heuristic_predict(self, features):
        """Heuristic fallback when no ML model is available"""
        score = 0

        # High entropy
        if features[1] > 7.0:
            score += 25
        elif features[1] > 6.5:
            score += 10

        # Crypto imports
        if features[8] == 1:
            score += 15

        # File system + crypto combo
        if features[10] == 1 and features[8] == 1:
            score += 20

        # Network imports
        if features[9] == 1:
            score += 5

        # Anti-debug
        if features[13] == 1:
            score += 10

        # Packed indicator
        if features[25] == 1:
            score += 15

        # Ransom strings
        if features[27] >= 3:
            score += 25
        elif features[27] >= 1:
            score += 10

        # Crypto strings
        if features[28] >= 2:
            score += 10

        # Many target extensions
        if features[29] >= 5:
            score += 15
        elif features[29] >= 3:
            score += 5

        # Suspicious sections
        if features[23] > 0:
            score += 10

        # Suspicious timestamp
        if features[26] == 1:
            score += 5

        confidence = min(score / 100.0, 1.0)
        is_malware = confidence >= 0.5

        return {
            'is_malware': is_malware,
            'confidence': confidence,
            'probability_benign': 1 - confidence,
            'probability_malware': confidence,
            'method': 'heuristic'
        }