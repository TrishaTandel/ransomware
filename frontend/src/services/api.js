import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_URL,
  timeout: 120000,  // 2 minute timeout for large files
  headers: {
    'Accept': 'application/json',
  }
});

export const scanFile = (file, onUploadProgress) => {
  const formData = new FormData();
  formData.append('file', file);

  return api.post('/scan', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: onUploadProgress,
  });
};

export const quickScan = (hash) => {
  return api.post('/scan/quick', { hash });
};

export const checkHealth = () => {
  return api.get('/health');
};

export const getStats = () => {
  return api.get('/stats');
};

export const getHistory = () => {
  return api.get('/history');
};

export const clearHistory = () => {
  return api.post('/history/clear');
};

export const getSupportedFormats = () => {
  return api.get('/supported-formats');
};

export default api;