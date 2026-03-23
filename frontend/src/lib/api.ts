import axios from 'axios'
import type { AnalysisDetail, DashboardStats, HistoryResponse, UploadResult, User } from '@/types'

const api = axios.create({
  baseURL: 'http://127.0.0.1:8000/api',
  timeout: 120000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('pg_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('pg_token')
      localStorage.removeItem('pg_user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authApi = {
  login: async (username: string, password: string) => {
    const res = await api.post('/auth/login', { username, password })
    return res.data as { access_token: string; user: User }
  },

  logout: () => api.post('/auth/logout'),

  me: async () => {
    const res = await api.get('/auth/me')
    return res.data as User
  },
}

export const analysisApi = {
  analyzeEmail: async (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData()
    form.append('file', file, file.name)

    const res = await api.post('/analyze/email', form, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (e) => {
        if (onProgress && e.total) {
          onProgress(Math.round((e.loaded / e.total) * 100))
        }
      },
    })

    return res.data as UploadResult
  },

  analyzeFile: async (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData()
    form.append('file', file, file.name)

    const res = await api.post('/analyze/file', form, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (e) => {
        if (onProgress && e.total) {
          onProgress(Math.round((e.loaded / e.total) * 100))
        }
      },
    })

    return res.data as UploadResult
  },
}

export const threatIntelApi = {
  searchVirusTotal: async (query_type: 'url' | 'domain' | 'ip' | 'hash', query: string) => {
    const res = await api.post('/analyze/virustotal-search', { query_type, query })
    return res.data
  },
}

export const sandboxApi = {
  checkAnyRun: async (hash: string) => {
    const res = await api.post('/analyze/anyrun', { hash })
    return res.data
  },
}

export const reportApi = {
  getReport: async (id: string) => {
    const res = await api.get(`/report/${id}`)
    return res.data as AnalysisDetail
  },

  updateNotes: async (id: string, notes: string) => {
    const res = await api.patch(`/report/${id}/notes`, { notes })
    return res.data
  },

  downloadJson: async (id: string) => {
    return api.get(`/report/${id}/json`, { responseType: 'blob' })
  },

  deleteReport: async (id: string) => {
    const res = await api.delete(`/report/${id}`)
    return res.data as { message: string }
  },
}

export const historyApi = {
  getHistory: async (params: {
    page?: number
    page_size?: number
    verdict?: string
    search?: string
  }) => {
    const res = await api.get('/history', { params })
    return res.data as HistoryResponse
  },

  getDashboard: async () => {
    const res = await api.get('/dashboard')
    return res.data as DashboardStats
  },
}

export default api