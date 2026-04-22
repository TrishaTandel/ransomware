import React, { useState, useEffect } from 'react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import Header from './components/Header';
import FileUpload from './components/FileUpload';
import ScanResult from './components/ScanResult';
import Dashboard from './components/Dashboard';
import ScanHistory from './components/ScanHistory';
import { checkHealth, getStats, getHistory } from './services/api';
import './App.css';

function App() {
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [serverStatus, setServerStatus] = useState('checking');
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('scanner');

  useEffect(() => {
    checkServerHealth();
    loadStats();
    loadHistory();
    
    const interval = setInterval(checkServerHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const checkServerHealth = async () => {
    try {
      const response = await checkHealth();
      if (response.data.status === 'online') {
        setServerStatus('online');
      } else {
        setServerStatus('offline');
      }
    } catch (error) {
      setServerStatus('offline');
    }
  };

  const loadStats = async () => {
    try {
      const response = await getStats();
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const loadHistory = async () => {
    try {
      const response = await getHistory();
      setHistory(response.data.history || []);
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  };

  const handleScanComplete = (result) => {
    setScanResult(result);
    setIsScanning(false);
    loadStats();
    loadHistory();

    if (result.verdict === 'malicious') {
      toast.error(`⚠️ THREAT DETECTED: ${result.filename} is malicious!`, {
        position: "top-right",
        autoClose: 8000,
      });
    } else if (result.verdict === 'suspicious') {
      toast.warn(`🔍 ${result.filename} is suspicious. Review results.`, {
        position: "top-right",
        autoClose: 6000,
      });
    } else {
      toast.success(`✅ ${result.filename} appears clean.`, {
        position: "top-right",
        autoClose: 4000,
      });
    }
  };

  const handleScanStart = () => {
    setIsScanning(true);
    setScanResult(null);
  };

  const handleScanError = (error) => {
    setIsScanning(false);
    toast.error(`Scan failed: ${error}`, {
      position: "top-right",
      autoClose: 5000,
    });
  };

  return (
    <div className="app">
      <Header serverStatus={serverStatus} />
      
      <main className="main-content">
        <nav className="tab-nav">
          <button
            className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            🔍 Scanner
          </button>
          <button
            className={`tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            📊 Dashboard
          </button>
          <button
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            📋 History
          </button>
        </nav>

        <div className="tab-content">
          {activeTab === 'scanner' && (
            <div className="scanner-tab">
              <FileUpload
                onScanComplete={handleScanComplete}
                onScanStart={handleScanStart}
                onScanError={handleScanError}
                isScanning={isScanning}
                serverStatus={serverStatus}
              />
              {scanResult && <ScanResult result={scanResult} />}
            </div>
          )}

          {activeTab === 'dashboard' && (
            <Dashboard stats={stats} />
          )}

          {activeTab === 'history' && (
            <ScanHistory history={history} onRefresh={loadHistory} />
          )}
        </div>
      </main>

      <ToastContainer
        theme="dark"
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
    </div>
  );
}

export default App;