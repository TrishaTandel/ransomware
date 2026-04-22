import React from 'react';
import './Header.css';

function Header({ serverStatus }) {
  const statusColor = {
    online: '#00e676',
    offline: '#ff5252',
    checking: '#ffab40'
  };

  const statusText = {
    online: 'System Online',
    offline: 'System Offline',
    checking: 'Checking...'
  };

  return (
    <header className="header">
      <div className="header-content">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <div className="logo-text">
              <h1>Ransomware Detection System</h1>
              <p className="subtitle">AI-Powered Malware Analysis Engine</p>
            </div>
          </div>
        </div>
        <div className="header-right">
          <div className="server-status">
            <span
              className="status-dot"
              style={{ backgroundColor: statusColor[serverStatus] }}
            ></span>
            <span className="status-text">{statusText[serverStatus]}</span>
          </div>
        </div>
      </div>
    </header>
  );
}

export default Header;