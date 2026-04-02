export const EXAMPLE_API_URL = window.__ENV?.VITE_EXAMPLE_API_URL ?? import.meta.env.VITE_EXAMPLE_API_URL

export const enabledExampleApi = !!EXAMPLE_API_URL

export async function apiFetch(url, options = {}) {
  return fetch(url, options)
}
