import React from 'react';
import { clearHistory } from '../services/api';
import './ScanHistory.css';

function ScanHistory({ history, onRefresh }) {
  const handleClear = async () => {
    try {
      await clearHistory();
      onRefresh();
    } catch (error) {
      console.error('Failed to clear history:', error);
    }
  };

  const getVerdictBadge = (verdict) => {
    const configs = {
      malicious: { color: '#ff5252', bg: 'rgba(255,82,82,0.15)', icon: '🚨' },
      suspicious: { color: '#ffab40', bg: 'rgba(255,171,64,0.15)', icon: '⚠️' },
      potentially_unwanted: { color: '#ffd740', bg: 'rgba(255,215,64,0.15)', icon: '🔶' },
      clean: { color: '#00e676', bg: 'rgba(0,230,118,0.15)', icon: '✅' },
    };
    const config = configs[verdict] || configs.clean;
    return (
      <span
        className="verdict-badge"
        style={{ color: config.color, background: config.bg }}
      >
        {config.icon} {verdict.replace(/_/g, ' ').toUpperCase()}
      </span>
    );
  };

  if (!history || history.length === 0) {
    return (
      <div className="scan-history">
        <div className="history-empty">
          <span className="empty-icon">📋</span>
          <h3>No Scan History</h3>
          <p>Scanned files will appear here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="scan-history">
      <div className="history-header">
        <h2>📋 Scan History ({history.length})</h2>
        <div className="history-actions">
          <button className="refresh-btn" onClick={onRefresh}>🔄 Refresh</button>
          <button className="clear-btn" onClick={handleClear}>🗑️ Clear</button>
        </div>
      </div>

      <div className="history-table-wrapper">
        <table className="history-table">
          <thead>
            <tr>
              <th>File</th>
              <th>Verdict</th>
              <th>Risk Score</th>
              <th>Threats</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {history.slice().reverse().map((item, index) => (
              <tr key={index} className={`history-row ${item.verdict}`}>
                <td className="filename-cell mono">{item.filename}</td>
                <td>{getVerdictBadge(item.verdict)}</td>
                <td>
                  <span className={`risk-badge risk-${item.risk_score >= 80 ? 'critical' : item.risk_score >= 50 ? 'high' : item.risk_score >= 20 ? 'medium' : 'low'}`}>
                    {item.risk_score}
                  </span>
                </td>
                <td>{item.threats_count}</td>
                <td className="time-cell">{new Date(item.timestamp).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default ScanHistory;