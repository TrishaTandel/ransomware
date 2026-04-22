# Getting Started with Create React App

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).



# 🚀 STEP-BY-STEP: HOW TO RUN THE SYSTEM
Prerequisites to Install
```
Software Required:
Software	Version	Download Link
Python	3.9 or higher	https://www.python.org/downloads/
Node.js	18.x or higher	https://nodejs.org/
Git	Latest	https://git-scm.com/
Visual Studio Code	Latest	https://code.visualstudio.com/
VS Code Extensions to Install
Open VS Code → Click Extensions icon (Ctrl+Shift+X) → Search and install each:
```

#	Extension Name	Extension ID	Purpose
```
1	Python	ms-python.python	Python language support
2	Pylance	ms-python.vscode-pylance	Python IntelliSense
3	Python Debugger	ms-python.debugpy	Debug Python
4	ES7+ React/Redux Snippets	dsznajder.es7-react-js-snippets	React snippets
5	Prettier	esbenp.prettier-vscode	Code formatter
6	ESLint	dbaeumer.vscode-eslint	JavaScript linting
7	JavaScript (ES6) code snippets	xabikos.JavaScriptSnippets	JS snippets
8	REST Client	humao.rest-client	Test API endpoints
9	GitLens	eamodio.gitlens	Git integration
10	Material Icon Theme	pkief.material-icon-theme	File icons
11	Thunder Client	rangav.vscode-thunder-client	API testing
12	Auto Rename Tag	formulahendry.auto-rename-tag	HTML/JSX tags
13	Bracket Pair Color	Built-in (enable in settings)	Bracket matching
14	Path Intellisense	christian-kohler.path-intellisense	File path completion
```
# Step-by-Step Instructions
STEP 1: Clone or Create the Project
Bash

Create fresh (if starting from scratch)
```
mkdir ransomware-detection-system
cd ransomware-detection-system
mkdir backend
mkdir frontend
```
Now copy ALL the files above into their correct locations.

# STEP 2: Setup Backend (Python)
Bash
```
# Navigate to backend folder
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

# You should see (venv) in your terminal prompt

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install flask==3.0.0
pip install flask-cors==4.0.0
pip install werkzeug==3.0.1
pip install pefile==2023.2.7
pip install scikit-learn==1.3.2
pip install numpy==1.26.2
pip install joblib==1.3.2
pip install requests==2.31.0

# Install YARA (may require build tools)
# On Windows:
pip install yara-python==4.5.0

# If yara-python fails on Windows, try:
pip install yara-python-wheel

# Or install without YARA (system will still work):
# The system falls back to non-YARA scanning
If yara-python installation fails:
```

# STEP 3: Train the ML Model
Bash
```
# Make sure you're in the backend folder with venv activated
cd backend

# Run the training script
python train_model.py
```
## Expected output:
```
text

============================================================
  Ransomware Detection - ML Model Training
============================================================

[1/4] Generating synthetic training data...
  Total samples: 3000
  Benign: 1500
  Malware: 1500

[2/4] Splitting into train/test sets...
  Training set: 2400 samples
  Test set: 600 samples

[3/4] Training model...

[4/4] Evaluating model...

  Training Accuracy: 0.9975
  Testing Accuracy:  0.9617

  Classification Report:
              precision    recall  f1-score   support
      Benign       0.96      0.97      0.96       300
     Malware       0.97      0.96      0.96       300
    accuracy                           0.96       600

  Model saved to: /path/to/backend/models

============================================================
  Training Complete! You can now start the server.
============================================================
```
# STEP 4: Start the Backend Server
Bash
```
# Make sure you're in backend folder with venv activated
cd backend
python app.py
```
## Expected output:

text
```
============================================================
  RANSOMWARE DETECTION SYSTEM - Backend Server
============================================================
  Scanner Ready: True
  ML Model Ready: True
  Upload Folder: /path/to/backend/uploads
  Supported Formats: exe, dll, bat, cmd, ps1, vbs, js, msi, scr, pif, com, bin, sys, drv
============================================================
 * Running on http://0.0.0.0:5000
Leave this terminal running! Open a NEW terminal for the frontend.
```

# STEP 5: Setup Frontend (React)
Bash
```
# Open a NEW terminal window
cd frontend

# Install Node.js dependencies
npm install
If npm install shows warnings, that's normal. Only errors matter.
```

# STEP 6: Start the Frontend
Bash
```
# Still in frontend folder
npm start
```
## Expected output:

text
```
Compiled successfully!

You can now view ransomware-detection-frontend in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.x.x:3000
Your browser should open automatically to http://localhost:3000
```

# STEP 7: Test the System
```
Open browser: Go to http://localhost:3000
Check status: Top right should show "System Online" with green dot
Upload a file:
Click the upload area or drag-and-drop an .exe file
Click "🔍 Start Scan"
View results: See the detailed analysis with verdict, risk score, and threats
Testing with Sample Files
```
## To test ransomware detection, you can:

Option A: Create a Test File (Harmless)
Bash

# Create a test file that will trigger some detections
```
python -c "
data = b'MZ' + b'\x00'*58 + b'\x80\x00\x00\x00'  # PE header start
data += b'your files have been encrypted'
data += b'send bitcoin to'
data += b'CryptEncrypt'
data += b'vssadmin delete shadows'
data += b'.doc.docx.xls.xlsx.pdf.jpg.png.zip.rar.sql.mdb.psd'
with open('test_ransomware.exe', 'wb') as f:
    f.write(data + b'\x00' * 1000)
print('Test file created: test_ransomware.exe')
"
```
Option B: Download EICAR Test File
text
```
Download from: https://www.eicar.org/download-anti-malware-testfile/
This is a standard anti-malware test file (completely harmless)
```
Option C: Use Any .exe File
Scan any legitimate .exe file to verify it comes back as "clean"
Example: Copy notepad.exe from C:\Windows\notepad.exe
# 🔍 HOW THE DETECTION WORKS
text
```
┌─────────────────────────────────────────────┐
│              FILE UPLOADED                    │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌────────┐  ┌─────────┐  ┌──────────┐
│ Static │  │  YARA   │  │  Hash    │
│Analysis│  │ Rules   │  │ Lookup   │
│(PE hdr)│  │Matching │  │(Known DB)│
└───┬────┘  └────┬────┘  └────┬─────┘
    │            │             │
    ▼            ▼             ▼
┌────────┐  ┌─────────┐  ┌──────────┐
│Entropy │  │ String  │  │ Import   │
│Analysis│  │Analysis │  │ Table    │
│        │  │         │  │ Analysis │
└───┬────┘  └────┬────┘  └────┬─────┘
    │            │             │
    └────────────┼─────────────┘
                 │
                 ▼
        ┌────────────────┐
        │  ML Model      │
        │  Prediction    │
        └───────┬────────┘
                │
                ▼
        ┌────────────────┐
        │ FINAL VERDICT  │
        │ + Risk Score   │
        └────────────────┘
```
Scan Layer	What It Checks
Static Analysis	PE headers, sections, timestamps, packing indicators
YARA Rules	20+ rules matching known ransomware families (WannaCry, Petya, Locky, etc.)
Hash Lookup	SHA-256 hash against database of known ransomware hashes
Entropy Analysis	Shannon entropy - high entropy = possible encryption/packing
String Analysis	Ransom notes, Bitcoin addresses, Tor URLs, crypto API names
Import Analysis	Windows API calls (crypto + file ops = ransomware indicator)
ML Model	30-feature gradient boosting classifier trained on PE characteristics
⚠️ Troubleshooting
Problem	Solution
python not found	Install Python 3.9+, check "Add to PATH" during installation
npm not found	Install Node.js 18+ from https://nodejs.org
yara-python fails to install	Install Visual Studio Build Tools, or skip YARA (system works without it)
CORS error in browser	Make sure backend runs on port 5000 and frontend on port 3000
Connection refused	Make sure backend is running (python app.py)
Module not found	Activate virtual environment: venv\Scripts\activate (Windows)
Port 5000 in use	Kill existing process: `netstat -ano
Port 3000 in use	Type Y when React asks to use different port
ML model not found	Run python train_model.py before starting the server
Summary of Commands (Quick Reference)
Bash

# === FIRST TIME SETUP ===
```
# Terminal 1 - Backend

cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install flask flask-cors pefile scikit-learn numpy joblib werkzeug requests
pip install yara-python        # Optional
python train_model.py          # Train ML model (run once)
python app.py                  # Start server

# Terminal 2 - Frontend
cd frontend
npm install                    # Install packages (run once)
npm start                      # Start React app
```
# === DAILY USE ===
# Terminal 1
cd backend && venv\Scripts\activate && python app.py

# Terminal 2
cd frontend && npm start

