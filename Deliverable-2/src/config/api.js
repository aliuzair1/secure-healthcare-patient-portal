/**
 * Axios instance — all requests route through the Nginx reverse proxy,
 * which forwards traffic through the custom WAF before reaching the backend.
 *
 * Pipeline: Client → Nginx proxy → Custom WAF → Backend / Supabase
 *
 * VITE_API_URL must point to the Nginx proxy address in every environment.
 * Direct calls to Supabase or any backend that bypass this pipeline are
 * intentionally avoided here.
 *
 * The Supabase client (src/lib/supabaseClient.js) is the only exception —
 * it handles auth session management internally (token refresh, persistence).
 * All data-fetching API calls go through this Axios instance.
 */
import axios from 'axios';
import { API_BASE_URL } from './constants';
import { supabase } from '../lib/supabaseClient';

const api = axios.create({
  baseURL: API_BASE_URL,  // Nginx proxy URL — set via VITE_API_URL
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  },
  withCredentials: true,
});

// Request interceptor: attach the live Supabase JWT so the WAF and backend
// can validate the caller on every request.
api.interceptors.request.use(
  async (config) => {
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) {
      config.headers.Authorization = `Bearer ${session.access_token}`;
    }
    return config;
  },
  (error) => Promise.reject(sanitizeError(error))
);

// Response interceptor: sanitize errors — never expose internals to the client.
api.interceptors.response.use(
  (response) => response,
  (error) => Promise.reject(sanitizeError(error))
);

function sanitizeError(error) {
  const status = error.response?.status;
  const safeMessages = {
    400: 'Invalid request. Please check your input.',
    401: 'Your session has expired. Please log in again.',
    403: 'You do not have permission to perform this action.',
    404: 'The requested resource was not found.',
    409: 'A conflict occurred. Please try again.',
    422: 'The provided data is invalid.',
    429: 'Too many requests. Please wait before trying again.',
    500: 'An unexpected error occurred. Please try again later.',
    502: 'Service is temporarily unavailable.',
    503: 'Service is under maintenance. Please try again later.',
  };
  return {
    message: safeMessages[status] || 'An unexpected error occurred. Please try again.',
    status: status || 0,
    isNetworkError: !error.response,
  };
}

export default api;
