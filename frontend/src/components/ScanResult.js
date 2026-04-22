import React, { useState } from 'react';
import './ScanResult.css';

function ScanResult({ result }) {
  const [expandedSections, setExpandedSections] = useState({});

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const getVerdictConfig = (verdict) => {
    const configs = {
      malicious: {
        color: '#ff5252',
        bg: 'rgba(255, 82, 82, 0.1)',
        border: 'rgba(255, 82, 82, 0.3)',
        icon: '🚨',
        label: 'MALICIOUS',
        description: 'This file has been identified as ransomware/malware!'
      },
      suspicious: {
        color: '#ffab40',
        bg: 'rgba(255, 171, 64, 0.1)',
        border: 'rgba(255, 171, 64, 0.3)',
        icon: '⚠️',
        label: 'SUSPICIOUS',
        description: 'This file shows suspicious behavior patterns.'
      },
      potentially_unwanted: {
        color: '#ffd740',
        bg: 'rgba(255, 215, 64, 0.1)',
        border: 'rgba(255, 215, 64, 0.3)',
        icon: '🔶',
        label: 'POTENTIALLY UNWANTED',
        description: 'This file shows some concerning characteristics.'
      },
      clean: {
        color: '#00e676',
        bg: 'rgba(0, 230, 118, 0.1)',
        border: 'rgba(0, 230, 118, 0.3)',
        icon: '✅',
        label: 'CLEAN',
        description: 'No threats detected in this file.'
      }
    };
    return configs[verdict] || configs.clean;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ff1744',
      high: '#ff5252',
      medium: '#ffab40',
      low: '#ffd740',
    };
    return colors[severity] || '#8a8aaa';
  };

  const verdictConfig = getVerdictConfig(result.verdict);

  const getRiskGradient = (score) => {
    if (score >= 80) return 'linear-gradient(135deg, #ff1744, #ff5252)';
    if (score >= 50) return 'linear-gradient(135deg, #ff5252, #ffab40)';
    if (score >= 20) return 'linear-gradient(135deg, #ffab40, #ffd740)';
    return 'linear-gradient(135deg, #00e676, #69f0ae)';
  };

  return (
    <div className="scan-result">
      {/* Verdict Banner */}
      <div
        className="verdict-banner"
        style={{
          background: verdictConfig.bg,
          borderColor: verdictConfig.border
        }}
      >
        <div className="verdict-main">
          <span className="verdict-icon">{verdictConfig.icon}</span>
          <div className="verdict-info">
            <h2 style={{ color: verdictConfig.color }}>{verdictConfig.label}</h2>
            <p>{verdictConfig.description}</p>
          </div>
        </div>
        <div className="risk-score-circle" style={{ background: getRiskGradient(result.risk_score) }}>
          <span className="risk-number">{result.risk_score}</span>
          <span className="risk-label">Risk</span>
        </div>
      </div>

      {/* File Info */}
      <div className="result-section file-info-section">
        <h3 onClick={() => toggleSection('fileInfo')}>
          📄 File Information {expandedSections.fileInfo === false ? '▶' : '▼'}
        </h3>
        {expandedSections.fileInfo !== false && (
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Filename</span>
              <span className="info-value mono">{result.filename}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Size</span>
              <span className="info-value">{(result.file_size / 1024).toFixed(2)} KB</span>
            </div>
            <div className="info-item">
              <span className="info-label">SHA-256</span>
              <span className="info-value mono hash">{result.file_hash_sha256}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Scan Duration</span>
              <span className="info-value">{result.scan_duration}s</span>
            </div>
            <div className="info-item">
              <span className="info-label">Threats Found</span>
              <span className="info-value" style={{ color: result.threats_count > 0 ? '#ff5252' : '#00e676' }}>
                {result.threats_count || 0}
              </span>
            </div>
            <div className="info-item">
              <span className="info-label">Scan Time</span>
              <span className="info-value">{new Date(result.scan_timestamp).toLocaleString()}</span>
            </div>
          </div>
        )}
      </div>

      {/* Threats */}
      {result.threats_found && result.threats_found.length > 0 && (
        <div className="result-section threats-section">
          <h3 onClick={() => toggleSection('threats')}>
            🚨 Threats Detected ({result.threats_found.length}) {expandedSections.threats === false ? '▶' : '▼'}
          </h3>
          {expandedSections.threats !== false && (
            <div className="threats-list">
              {result.threats_found.map((threat, index) => (
                <div
                  key={index}
                  className="threat-item"
                  style={{ borderLeftColor: getSeverityColor(threat.severity) }}
                >
                  <div className="threat-header">
                    <span className="threat-type">{threat.type}</span>
                    <span
                      className="threat-severity"
                      style={{
                        background: getSeverityColor(threat.severity) + '20',
                        color: getSeverityColor(threat.severity)
                      }}
                    >
                      {threat.severity?.toUpperCase()}
                    </span>
                  </div>
                  <p className="threat-description">{threat.description}</p>
                  {threat.details && typeof threat.details === 'object' && (
                    <div className="threat-details">
                      {Object.entries(threat.details).map(([key, value]) => {
                        if (!value || (Array.isArray(value) && value.length === 0)) return null;
                        return (
                          <div key={key} className="detail-item">
                            <span className="detail-key">{key.replace(/_/g, ' ')}:</span>
                            <span className="detail-value mono">
                              {Array.isArray(value) ? value.join(', ') : String(value)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Scan Details */}
      {result.scan_details && (
        <div className="result-section details-section">
          <h3 onClick={() => toggleSection('details')}>
            🔬 Detailed Analysis {expandedSections.details ? '▼' : '▶'}
          </h3>
          {expandedSections.details && (
            <div className="details-content">
              {Object.entries(result.scan_details).map(([key, value]) => (
                <div key={key} className="detail-module">
                  <h4>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</h4>
                  <pre className="mono">
                    {JSON.stringify(value, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ScanResult;