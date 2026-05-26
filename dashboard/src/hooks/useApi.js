// src/hooks/useApi.js
// Thin wrapper around fetch — handles loading/error state consistently
import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || 'http://192.168.56.102:8000'

export const api = axios.create({ baseURL: API })

export function useApi(path, deps = []) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  const fetch = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get(path)
      setData(res.data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [path])

  useEffect(() => { fetch() }, [fetch, ...deps])

  return { data, loading, error, refetch: fetch }
}

// Auto-refresh hook
export function usePolling(path, intervalMs = 30000) {
  const result = useApi(path)

  useEffect(() => {
    const id = setInterval(result.refetch, intervalMs)
    return () => clearInterval(id)
  }, [result.refetch, intervalMs])

  return result
}
