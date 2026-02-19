import { api } from './client';

export const endpoints = {
  login: (data: { email: string; password: string }) => api.post('/api/auth/login', data),
  register: (data: Record<string, string>) => api.post('/api/auth/register', data),
  me: () => api.get('/api/me'),
  overview: () => api.get('/api/overview'),
  agents: () => api.get('/api/agents'),
  agent: (id: string) => api.get(`/api/agents/${id}`),
  servers: () => api.get('/api/servers'),
  server: (id: string) => api.get(`/api/servers/${id}`),
  apps: () => api.get('/api/apps'),
  app: (id: string) => api.get(`/api/apps/${id}`),
  logs: (params: Record<string, string>) => api.get('/api/logs', { params }),
  alerts: () => api.get('/api/alerts'),
  threats: () => api.get('/api/threats'),
  runThreatScan: () => api.post('/api/threats/scan'),
  agentToken: () => api.post('/api/agents/tokens'),
  agentInstall: () => api.get('/api/agents/install')
};
