import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BrowserHttpClient } from '../../../src/providers/http.js';

describe('BrowserHttpClient', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.clearAllMocks();
  });

  describe('credentials control', () => {
    it('should default to credentials: omit', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ success: true }),
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient();
      await client.fetch('https://example.com/api');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api',
        expect.objectContaining({
          credentials: 'omit',
        })
      );
    });

    it('should allow overriding credentials in constructor', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ success: true }),
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient({ credentials: 'include' });
      await client.fetch('https://example.com/api');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api',
        expect.objectContaining({
          credentials: 'include',
        })
      );
    });

    it('should allow overriding credentials per request', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ success: true }),
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient({ credentials: 'omit' });
      await client.fetch('https://example.com/api', { credentials: 'include' });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api',
        expect.objectContaining({
          credentials: 'include',
        })
      );
    });
  });

  describe('response handling', () => {
    it('should parse JSON response', async () => {
      const mockData = { id: 1, name: 'test' };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockData,
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient();
      const response = await client.fetch('https://example.com/api');

      expect(response.data).toEqual(mockData);
      expect(response.ok).toBe(true);
      expect(response.status).toBe(200);
    });

    it('should handle text response', async () => {
      const mockText = 'Hello, World!';
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: async () => mockText,
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient();
      const response = await client.fetch('https://example.com/api');

      expect(response.data).toEqual(mockText);
    });

    it('should convert headers to Record<string, string>', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({
          'content-type': 'application/json',
          'x-custom-header': 'custom-value',
        }),
        json: async () => ({}),
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient();
      const response = await client.fetch('https://example.com/api');

      expect(response.headers['content-type']).toBe('application/json');
      expect(response.headers['x-custom-header']).toBe('custom-value');
    });
  });

  describe('timeout handling', () => {
    it('should pass AbortSignal to fetch', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ success: true }),
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient();
      await client.fetch('https://example.com/api');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api',
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should abort on timeout', async () => {
      let abortController: AbortController | undefined;
      const mockFetch = vi.fn().mockImplementation((url, options) => {
        // Capture the signal
        abortController = new AbortController();
        return new Promise((resolve, reject) => {
          options?.signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        });
      });
      globalThis.fetch = mockFetch;

      const client = new BrowserHttpClient({ timeout: 100 }); // Short timeout for test
      const fetchPromise = client.fetch('https://example.com/api');

      // Wait for timeout
      await expect(fetchPromise).rejects.toThrow();
    }, 5000);
  });
});
