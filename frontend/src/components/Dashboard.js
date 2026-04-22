import React from 'react';
import './Dashboard.css';

function Dashboard({ stats }) {
  if (!stats || stats.total_scans === 0) {
    return (
      <div className="dashboard">
        <div className="dashboard-empty">
          <span className="empty-icon">📊</span>
          <h3>No Scan Data Yet</h3>
          <p>Start scanning files to see statistics here.</p>
        </div>
      </div>
    );
  }

  const cards = [
    {
      label: 'Total Scans',
      value: stats.total_scans,
      icon: '🔍',
      color: '#667eea'
    },
    {
      label: 'Malicious',
      value: stats.malicious,
      icon: '🚨',
      color: '#ff5252'
    },
    {
      label: 'Suspicious',
      value: stats.suspicious,
      icon: '⚠️',
      color: '#ffab40'
    },
    {
      label: 'Clean',
      value: stats.clean,
      icon: '✅',
      color: '#00e676'
    },
    {
      label: 'Detection Rate',
      value: `${stats.detection_rate}%`,
      icon: '🎯',
      color: '#764ba2'
    },
    {
      label: 'Avg Risk Score',
      value: stats.avg_risk_score,
      icon: '📈',
      color: '#f093fb'
    }
  ];

  return (
    <div className="dashboard">
      <h2 className="dashboard-title">📊 Scanning Statistics</h2>
      <div className="stats-grid">
        {cards.map((card, index) => (
          <div key={index} className="stat-card">
            <div className="stat-icon" style={{ background: card.color + '20' }}>
              {card.icon}
            </div>
            <div className="stat-info">
              <span className="stat-value" style={{ color: card.color }}>{card.value}</span>
              <span className="stat-label">{card.label}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Detection Distribution */}
      <div className="distribution-section">
        <h3>Detection Distribution</h3>
        <div className="distribution-bar">
          {stats.malicious > 0 && (
            <div
              className="dist-segment malicious"
              style={{ width: `${(stats.malicious / stats.total_scans) * 100}%` }}
              title={`Malicious: ${stats.malicious}`}
            >
              {((stats.malicious / stats.total_scans) * 100).toFixed(0)}%
            </div>
          )}
          {stats.suspicious > 0 && (
            <div
              className="dist-segment suspicious"
              style={{ width: `${(stats.suspicious / stats.total_scans) * 100}%` }}
              title={`Suspicious: ${stats.suspicious}`}
            >
              {((stats.suspicious / stats.total_scans) * 100).toFixed(0)}%
            </div>
          )}
          {stats.clean > 0 && (
            <div
              className="dist-segment clean"
              style={{ width: `${(stats.clean / stats.total_scans) * 100}%` }}
              title={`Clean: ${stats.clean}`}
            >
              {((stats.clean / stats.total_scans) * 100).toFixed(0)}%
            </div>
          )}
        </div>
        <div className="distribution-legend">
          <span className="legend-item"><span className="dot malicious"></span> Malicious</span>
          <span className="legend-item"><span className="dot suspicious"></span> Suspicious</span>
          <span className="legend-item"><span className="dot clean"></span> Clean</span>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;