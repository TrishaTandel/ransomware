import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { scanFile } from '../services/api';
import './FileUpload.css';

function FileUpload({ onScanComplete, onScanStart, onScanError, isScanning, serverStatus }) {
  const [uploadProgress, setUploadProgress] = useState(0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      setSelectedFile(acceptedFiles[0]);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: {
      'application/x-msdownload': ['.exe'],
      'application/x-dosexec': ['.exe'],
      'application/octet-stream': ['.exe', '.dll', '.bin', '.sys', '.drv', '.scr', '.pif', '.com'],
      'application/x-msi': ['.msi'],
      'application/x-bat': ['.bat', '.cmd'],
      'text/vbscript': ['.vbs'],
      'application/javascript': ['.js'],
      'application/x-powershell': ['.ps1'],
    },
    disabled: isScanning || serverStatus !== 'online',
  });

  const handleScan = async () => {
    if (!selectedFile) return;
    if (serverStatus !== 'online') {
      onScanError('Server is offline. Please start the backend server.');
      return;
    }

    onScanStart();
    setUploadProgress(0);

    try {
      const response = await scanFile(selectedFile, (progressEvent) => {
        const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setUploadProgress(progress);
      });

      onScanComplete(response.data);
    } catch (error) {
      const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
      onScanError(errorMessage);
    } finally {
      setUploadProgress(0);
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="file-upload-container">
      <div
        {...getRootProps()}
        className={`dropzone ${isDragActive ? 'drag-active' : ''} ${isScanning ? 'disabled' : ''} ${serverStatus !== 'online' ? 'server-offline' : ''}`}
      >
        <input {...getInputProps()} />
        <div className="dropzone-content">
          {isScanning ? (
            <>
              <div className="scan-animation">
                <div className="scan-ring"></div>
                <div className="scan-icon">🔍</div>
              </div>
              <h3>Scanning in progress...</h3>
              {uploadProgress > 0 && uploadProgress < 100 && (
                <div className="upload-progress">
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${uploadProgress}%` }}></div>
                  </div>
                  <span>{uploadProgress}% uploaded</span>
                </div>
              )}
              {uploadProgress >= 100 && <p>Analyzing file... Please wait.</p>}
            </>
          ) : (
            <>
              <div className="upload-icon">📁</div>
              <h3>Drop your file here or click to browse</h3>
              <p>Supports: EXE, DLL, BAT, CMD, PS1, VBS, JS, MSI, SCR, BIN, SYS</p>
              <p className="size-limit">Maximum file size: 100 MB</p>
            </>
          )}
        </div>
      </div>

      {selectedFile && !isScanning && (
        <div className="selected-file">
          <div className="file-info">
            <span className="file-icon">📄</span>
            <div className="file-details">
              <span className="file-name">{selectedFile.name}</span>
              <span className="file-size">{formatFileSize(selectedFile.size)}</span>
            </div>
            <button className="remove-file" onClick={handleRemoveFile}>✕</button>
          </div>
          <button
            className="scan-button"
            onClick={handleScan}
            disabled={serverStatus !== 'online'}
          >
            {serverStatus !== 'online' ? '⚠️ Server Offline' : '🔍 Start Scan'}
          </button>
        </div>
      )}

      {serverStatus === 'offline' && (
        <div className="server-warning">
          ⚠️ Backend server is offline. Start the server first with: <code>python app.py</code>
        </div>
      )}
    </div>
  );
}

export default FileUpload;