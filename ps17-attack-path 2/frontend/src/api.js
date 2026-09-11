import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:4000/api' });

export const getGraph = () => api.get('/graph').then((r) => r.data);

export const getPaths = (from, to) =>
  api.get('/paths', { params: { from, to } }).then((r) => r.data);

export const getBlastRadius = (nodeId) =>
  api.get(`/blast-radius/${nodeId}`).then((r) => r.data);

export const simulateRemediation = (from, to, excludeRelId) =>
  api.post('/simulate-remediation', { from, to, excludeRelId }).then((r) => r.data);

export default api;
