import axios from 'axios';

// Resolve backend API URL:
// 1. In production on Vercel, if VITE_API_URL is configured (e.g. https://zenith-backend.onrender.com),
//    it directly calls the Render backend.
// 2. If VITE_API_URL is not set, it defaults to relative '/api' (proxied by Vite in local dev
//    or by vercel.json rewrites in production).
const resolveBaseURL = () => {
  const envUrl = import.meta.env?.VITE_API_URL;
  if (envUrl && typeof envUrl === 'string' && envUrl.trim().length > 0) {
    const cleaned = envUrl.trim().replace(/\/+$/, '');
    return cleaned.endsWith('/api') ? cleaned : cleaned + '/api';
  }
  return '/api';
};

const api = axios.create({ baseURL: resolveBaseURL() });

export const getGraph = (dataset = null) =>
  api.get('/graph', { params: dataset ? { dataset } : {} }).then((r) => r.data);

export const getPaths = (from, to, dataset = null) =>
  api.get('/paths', { params: { from, to, ...(dataset ? { dataset } : {}) } }).then((r) => r.data);

export const getBlastRadius = (nodeId, dataset = null) =>
  api.get('/blast-radius/' + encodeURIComponent(nodeId), { params: dataset ? { dataset } : {} }).then((r) => r.data);

export const simulateRemediation = (from, to, excludeRelId, dataset = null) =>
  api.post('/simulate-remediation', { from, to, excludeRelId, ...(dataset ? { dataset } : {}) }).then((r) => r.data);

export const explainPath = (from, to, path, apiKey = null) => {
  const activeKey = apiKey || (typeof window !== 'undefined' ? localStorage.getItem('zenith_nvidia_api_key') : null);
  const headers = activeKey ? { 'x-nvidia-api-key': activeKey } : {};
  return api.post('/explain-path', { from, to, path }, { headers }).then((r) => r.data);
};

export const injectRelationship = (from, to, relationshipType, dataset = null) =>
  api.post('/inject', { from, to, relationshipType, ...(dataset ? { dataset } : {}) }).then((r) => r.data);

export const getRelationshipTypes = () =>
  api.get('/relationship-types').then((r) => r.data);

export const importAdsynth = (path) =>
  api.post('/adsynth/import', { path }).then((r) => r.data);

export const testAdsynth = (path) =>
  api.post('/adsynth/test', { path }).then((r) => r.data);

export const seedDefault = () =>
  api.post('/seed/default').then((r) => r.data);

export default api;
