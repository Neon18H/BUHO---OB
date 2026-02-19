import axios from 'axios';

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_BUHO_API_URL,
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('buho_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (e) => {
    if (typeof window !== 'undefined' && e.response?.status === 401) {
      localStorage.removeItem('buho_token');
      if (!location.pathname.startsWith('/auth')) location.href = '/auth/login';
    }
    return Promise.reject(e);
  },
);
