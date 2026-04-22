"""
Flask API Server for Ransomware Detection System
Handles file uploads, scanning, and returns results
"""

import os
import sys
import json
import time
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import our custom modules
from scanner import RansomwareScanner
from ml_model import RansomwareMLModel

# ============================================================
# Configuration
# ============================================================
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'msi', 'scr', 'pif', 'com', 'bin', 'sys', 'drv'}
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create uploads directory
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scanner.log')
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# Initialize Scanner and ML Model
# ============================================================
scanner = None
ml_model = None
scan_history = []

def initialize_system():
    """Initialize the scanner and ML model"""
    global scanner, ml_model
    try:
        scanner = RansomwareScanner()
        logger.info("Scanner initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize scanner: {e}")
        scanner = RansomwareScanner(use_yara=False)

    try:
        ml_model = RansomwareMLModel()
        ml_model.load_model()
        logger.info("ML Model loaded successfully")
    except Exception as e:
        logger.warning(f"ML Model not available: {e}")
        ml_model = None

initialize_system()

# ============================================================
# Helper Functions
# ============================================================
def allowed_file(filename):
    """Check if file extension is allowed for scanning"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ============================================================
# API Routes
# ============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'scanner_ready': scanner is not None,
        'ml_model_ready': ml_model is not None,
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """
    Main endpoint: Upload and scan a file for ransomware
    Returns detailed scan results
    """
    start_time = time.time()
    
    # --- Validate request ---
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided in request'}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename:
        return jsonify({'error': 'Invalid filename'}), 400

    # --- Save file temporarily ---
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        file_hash = get_file_hash(filepath)
        logger.info(f"File saved for scanning: {filename} ({file_size} bytes)")

        # --- Run all scans ---
        results = {
            'filename': filename,
            'file_size': file_size,
            'file_hash_sha256': file_hash,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_details': {},
            'threats_found': [],
            'risk_score': 0,
            'verdict': 'clean',
            'scan_duration': 0
        }

        total_risk = 0
        threat_count = 0

        # 1) Static Analysis (PE header analysis)
        try:
            static_result = scanner.static_analysis(filepath)
            results['scan_details']['static_analysis'] = static_result
            if static_result.get('is_suspicious', False):
                total_risk += static_result.get('risk_score', 0)
                threat_count += 1
                results['threats_found'].append({
                    'type': 'Static Analysis',
                    'description': static_result.get('reason', 'Suspicious PE characteristics'),
                    'severity': static_result.get('severity', 'medium'),
                    'details': static_result.get('indicators', [])
                })
        except Exception as e:
            logger.error(f"Static analysis error: {e}")
            results['scan_details']['static_analysis'] = {'error': str(e)}

        # 2) YARA Rule Matching
        try:
            yara_result = scanner.yara_scan(filepath)
            results['scan_details']['yara_scan'] = yara_result
            if yara_result.get('matches'):
                total_risk += 40
                threat_count += 1
                for match in yara_result['matches']:
                    results['threats_found'].append({
                        'type': 'YARA Rule Match',
                        'description': f"Matched rule: {match['rule']}",
                        'severity': 'high',
                        'details': match.get('meta', {})
                    })
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            results['scan_details']['yara_scan'] = {'error': str(e)}

        # 3) Hash-based Detection (Known Signatures)
        try:
            hash_result = scanner.hash_lookup(file_hash)
            results['scan_details']['hash_lookup'] = hash_result
            if hash_result.get('found', False):
                total_risk += 100
                threat_count += 1
                results['threats_found'].append({
                    'type': 'Known Malware Hash',
                    'description': f"File matches known ransomware: {hash_result.get('malware_name', 'Unknown')}",
                    'severity': 'critical',
                    'details': hash_result
                })
        except Exception as e:
            logger.error(f"Hash lookup error: {e}")
            results['scan_details']['hash_lookup'] = {'error': str(e)}

        # 4) Entropy Analysis
        try:
            entropy_result = scanner.entropy_analysis(filepath)
            results['scan_details']['entropy_analysis'] = entropy_result
            if entropy_result.get('is_suspicious', False):
                total_risk += entropy_result.get('risk_score', 0)
                threat_count += 1
                results['threats_found'].append({
                    'type': 'High Entropy',
                    'description': 'File has unusually high entropy (possible encryption/packing)',
                    'severity': 'medium',
                    'details': {
                        'entropy': entropy_result.get('entropy', 0),
                        'packed_sections': entropy_result.get('packed_sections', [])
                    }
                })
        except Exception as e:
            logger.error(f"Entropy analysis error: {e}")
            results['scan_details']['entropy_analysis'] = {'error': str(e)}

        # 5) String Analysis
        try:
            string_result = scanner.string_analysis(filepath)
            results['scan_details']['string_analysis'] = string_result
            if string_result.get('is_suspicious', False):
                total_risk += string_result.get('risk_score', 0)
                threat_count += 1
                results['threats_found'].append({
                    'type': 'Suspicious Strings',
                    'description': 'File contains ransomware-related strings',
                    'severity': string_result.get('severity', 'medium'),
                    'details': {
                        'suspicious_strings': string_result.get('suspicious_strings', []),
                        'crypto_apis': string_result.get('crypto_apis', []),
                        'ransom_indicators': string_result.get('ransom_indicators', [])
                    }
                })
        except Exception as e:
            logger.error(f"String analysis error: {e}")
            results['scan_details']['string_analysis'] = {'error': str(e)}

        # 6) Import Table Analysis
        try:
            import_result = scanner.import_analysis(filepath)
            results['scan_details']['import_analysis'] = import_result
            if import_result.get('is_suspicious', False):
                total_risk += import_result.get('risk_score', 0)
                threat_count += 1
                results['threats_found'].append({
                    'type': 'Suspicious Imports',
                    'description': 'File imports suspicious API functions',
                    'severity': import_result.get('severity', 'medium'),
                    'details': {
                        'suspicious_imports': import_result.get('suspicious_imports', [])
                    }
                })
        except Exception as e:
            logger.error(f"Import analysis error: {e}")
            results['scan_details']['import_analysis'] = {'error': str(e)}

        # 7) ML Model Prediction
        if ml_model is not None:
            try:
                ml_result = ml_model.predict(filepath)
                results['scan_details']['ml_prediction'] = ml_result
                if ml_result.get('is_malware', False):
                    ml_confidence = ml_result.get('confidence', 0)
                    total_risk += int(ml_confidence * 50)
                    threat_count += 1
                    results['threats_found'].append({
                        'type': 'ML Detection',
                        'description': f"Machine learning model flagged as malware ({ml_confidence*100:.1f}% confidence)",
                        'severity': 'high' if ml_confidence > 0.8 else 'medium',
                        'details': ml_result
                    })
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
                results['scan_details']['ml_prediction'] = {'error': str(e)}

        # --- Calculate final risk score and verdict ---
        if threat_count > 0:
            results['risk_score'] = min(100, total_risk)
        else:
            results['risk_score'] = 0

        if results['risk_score'] >= 80:
            results['verdict'] = 'malicious'
        elif results['risk_score'] >= 50:
            results['verdict'] = 'suspicious'
        elif results['risk_score'] >= 20:
            results['verdict'] = 'potentially_unwanted'
        else:
            results['verdict'] = 'clean'

        results['threats_count'] = threat_count
        results['scan_duration'] = round(time.time() - start_time, 3)

        # Save to history
        scan_history.append({
            'filename': filename,
            'verdict': results['verdict'],
            'risk_score': results['risk_score'],
            'threats_count': threat_count,
            'timestamp': results['scan_timestamp'],
            'file_hash': file_hash
        })

        logger.info(f"Scan complete: {filename} -> {results['verdict']} (risk: {results['risk_score']})")
        return jsonify(results)

    except Exception as e:
        logger.error(f"Scan failed for {filename}: {e}")
        return jsonify({
            'error': f'Scan failed: {str(e)}',
            'filename': filename
        }), 500

    finally:
        # Clean up uploaded file
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    """Quick hash-only scan"""
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({'error': 'No hash provided'}), 400

    file_hash = data['hash']
    result = scanner.hash_lookup(file_hash)
    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    return jsonify({
        'history': scan_history[-50:],  # Last 50 scans
        'total_scans': len(scan_history)
    })

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    """Clear scan history"""
    global scan_history
    scan_history = []
    return jsonify({'message': 'History cleared'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scanning statistics"""
    if not scan_history:
        return jsonify({
            'total_scans': 0,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'detection_rate': 0
        })

    verdicts = [s['verdict'] for s in scan_history]
    return jsonify({
        'total_scans': len(scan_history),
        'malicious': verdicts.count('malicious'),
        'suspicious': verdicts.count('suspicious'),
        'potentially_unwanted': verdicts.count('potentially_unwanted'),
        'clean': verdicts.count('clean'),
        'detection_rate': round(
            (verdicts.count('malicious') + verdicts.count('suspicious')) / len(verdicts) * 100, 1
        ),
        'avg_risk_score': round(
            sum(s['risk_score'] for s in scan_history) / len(scan_history), 1
        )
    })

@app.route('/api/supported-formats', methods=['GET'])
def supported_formats():
    """Return list of supported file formats"""
    return jsonify({
        'formats': list(ALLOWED_EXTENSIONS),
        'max_file_size_mb': MAX_CONTENT_LENGTH // (1024 * 1024)
    })

# ============================================================
# Error Handlers
# ============================================================
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 100 MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("  RANSOMWARE DETECTION SYSTEM - Backend Server")
    print("=" * 60)
    print(f"  Scanner Ready: {scanner is not None}")
    print(f"  ML Model Ready: {ml_model is not None}")
    print(f"  Upload Folder: {UPLOAD_FOLDER}")
    print(f"  Supported Formats: {', '.join(ALLOWED_EXTENSIONS)}")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)