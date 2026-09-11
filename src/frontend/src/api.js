import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:4000/api' });

export const getGraph = (dataset = null) =>
  api.get('/graph', { params: dataset ? { dataset } : {} }).then((r) => r.data);

export const getPaths = (from, to, dataset = null) =>
  api.get('/paths', { params: { from, to, ...(dataset ? { dataset } : {}) } }).then((r) => r.data);

export const getBlastRadius = (nodeId, dataset = null) =>
  api.get(`/blast-radius/${nodeId}`, { params: dataset ? { dataset } : {} }).then((r) => r.data);

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

