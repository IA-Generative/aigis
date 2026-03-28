export const EXAMPLE_API_URL = import.meta.env.VITE_EXAMPLE_API_URL
// export const EXAMPLE_API_URL = import.meta.env.PROXY_CALL === 'true' 
//   ? import.meta.env.VITE_EXAMPLE_API_URL 
//   : 'http://localhost:5173/example-api'

export const enabledExampleApi = !!EXAMPLE_API_URL

export async function apiFetch(url, options = {}) {
  return fetch(url, options)
}
