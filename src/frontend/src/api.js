import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:4000/api' });

export const getGraph = () => api.get('/graph').then((r) => r.data);

export const getPaths = (from, to) =>
  api.get('/paths', { params: { from, to } }).then((r) => r.data);

export const getBlastRadius = (nodeId) =>
  api.get(`/blast-radius/${nodeId}`).then((r) => r.data);

export const simulateRemediation = (from, to, excludeRelId) =>
  api.post('/simulate-remediation', { from, to, excludeRelId }).then((r) => r.data);

export const explainPath = (from, to, path, apiKey = null) => {
  const activeKey = apiKey || (typeof window !== 'undefined' ? localStorage.getItem('zenith_nvidia_api_key') : null);
  const headers = activeKey ? { 'x-nvidia-api-key': activeKey } : {};
  return api.post('/explain-path', { from, to, path }, { headers }).then((r) => r.data);
};

export const injectRelationship = (from, to, relationshipType) =>
  api.post('/inject', { from, to, relationshipType }).then((r) => r.data);

export const getRelationshipTypes = () =>
  api.get('/relationship-types').then((r) => r.data);

export default api;

