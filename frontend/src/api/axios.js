/**
 * Axios instance pre-configured with base URL and JWT auth interceptors.
 * Automatically attaches Bearer token and handles 401 token refresh.
 */
import axios from 'axios';

const rawBase = import.meta.env.VITE_API_BASE_URL;
const envFull = import.meta.env.VITE_API_URL;
const PROD_BACKEND_URL = 'https://taskmanager-backend-g0dy.onrender.com';
const isLocalHost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

const normalizeBaseUrl = (value) => value?.replace(/\/+$/, '');
const isLocalApiUrl = (value) => /localhost|127\.0\.0\.1/.test(value || '');

const preferredEnvUrl = normalizeBaseUrl(rawBase || envFull);
const safeEnvUrl = preferredEnvUrl && (!isLocalApiUrl(preferredEnvUrl) || isLocalHost)
  ? preferredEnvUrl
  : null;

const resolvedBaseUrl = normalizeBaseUrl(
  safeEnvUrl || (isLocalHost ? 'http://localhost:8000' : PROD_BACKEND_URL)
);

const API_URL = resolvedBaseUrl.endsWith('/api/v1')
  ? resolvedBaseUrl
  : `${resolvedBaseUrl}/api/v1`;

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000,
});

// ── Request interceptor: attach JWT access token ──────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: auto-refresh token on 401 ──────────────────────────
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) prom.reject(error);
    else prom.resolve(token);
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        isRefreshing = false;
        localStorage.clear();
        window.location.href = '/login';
        return Promise.reject(error);
      }

      try {
        const { data } = await axios.post(`${API_URL}/auth/token/refresh/`, {
          refresh: refreshToken,
        });
        const newAccessToken = data.access;
        localStorage.setItem('accessToken', newAccessToken);
        api.defaults.headers['Authorization'] = `Bearer ${newAccessToken}`;
        processQueue(null, newAccessToken);
        originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (err) {
        processQueue(err, null);
        localStorage.clear();
        window.location.href = '/login';
        return Promise.reject(err);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;
