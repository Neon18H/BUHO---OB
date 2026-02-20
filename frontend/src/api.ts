export function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? decodeURIComponent(match[2]) : '';
}

export async function apiClient(url: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('X-CSRFToken', getCookie('csrftoken'));
  if (!headers.has('Content-Type') && options.body) headers.set('Content-Type', 'application/json');

  return fetch(url, {
    ...options,
    credentials: 'include',
    headers
  });
}
