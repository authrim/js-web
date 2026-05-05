import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HandoffAuthImpl, HANDOFF_STORAGE_KEYS } from '../../../src/direct-auth/handoff';
import type { BrowserHttpClient } from '../../../src/providers/http';

function createStorageMock() {
  const store = new Map<string, string>();
  return {
    getItem: vi.fn((key: string) => store.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store.set(key, value);
    }),
    removeItem: vi.fn((key: string) => {
      store.delete(key);
    }),
    clear: vi.fn(() => {
      store.clear();
    }),
  };
}

const sessionStorageMock = createStorageMock();

Object.defineProperty(globalThis, 'sessionStorage', {
  value: sessionStorageMock,
  configurable: true,
});

describe('HandoffAuthImpl', () => {
  let http: BrowserHttpClient;
  let saveAccessToken: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorageMock.clear();
    http = {
      fetch: vi.fn(),
    } as unknown as BrowserHttpClient;
    saveAccessToken = vi.fn();
  });

  function createHandoff() {
    return new HandoffAuthImpl(
      'https://issuer.example.com',
      'client-123',
      http,
      saveAccessToken,
    );
  }

  it('uses a pure token response by default and attaches the DPoP proof header', async () => {
    vi.mocked(http.fetch).mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        token_type: 'DPoP',
        access_token: 'rp-access-token',
        expires_in: 3600,
      },
    });

    const result = await createHandoff().verifyToken('handoff-token', 'state-123', 'client-123', {
      dpopProof: 'dpop-proof',
    });

    expect(result).toEqual({
      token_type: 'DPoP',
      access_token: 'rp-access-token',
      expires_in: 3600,
    });
    const [url, init] = vi.mocked(http.fetch).mock.calls[0];
    expect(new URL(String(url)).searchParams.has('include')).toBe(false);
    expect(init?.headers).toMatchObject({
      'Content-Type': 'application/json',
      DPoP: 'dpop-proof',
    });
  });

  it('maps include=session,user to the wire query parameter', async () => {
    vi.mocked(http.fetch).mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        token_type: 'DPoP',
        access_token: 'rp-access-token',
        expires_in: 3600,
        session: {
          id: 'rp-access-token',
          userId: 'user-123',
          createdAt: '2026-05-06T00:00:00.000Z',
          expiresAt: '2026-05-06T01:00:00.000Z',
        },
        user: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Example User',
          emailVerified: true,
        },
      },
    });

    await createHandoff().verifyToken('handoff-token', 'state-123', 'client-123', {
      include: 'session,user',
      dpopProof: 'dpop-proof',
    });

    const [url] = vi.mocked(http.fetch).mock.calls[0];
    expect(new URL(String(url)).searchParams.get('include')).toBe('session,user');
  });

  it('verifyAndSave requests session/user extensions and stores the token through the session policy', async () => {
    sessionStorageMock.setItem(HANDOFF_STORAGE_KEYS.STATE, 'state-123');
    vi.mocked(http.fetch).mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        token_type: 'DPoP',
        access_token: 'rp-access-token',
        expires_in: 3600,
        session: {
          id: 'rp-access-token',
          userId: 'user-123',
          createdAt: '2026-05-06T00:00:00.000Z',
          expiresAt: '2026-05-06T01:00:00.000Z',
        },
        user: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Example User',
          emailVerified: true,
        },
      },
    });

    const result = await createHandoff().verifyAndSave('handoff-token', 'state-123', {
      dpopProof: 'dpop-proof',
    });

    expect(result.session.id).toBe('rp-access-token');
    expect(result.user.id).toBe('user-123');
    expect(saveAccessToken).toHaveBeenCalledWith('rp-access-token');
    const [url, init] = vi.mocked(http.fetch).mock.calls[0];
    expect(new URL(String(url)).searchParams.get('include')).toBe('session,user');
    expect(init?.headers).toMatchObject({ DPoP: 'dpop-proof' });
    expect(sessionStorageMock.removeItem).toHaveBeenCalledWith(HANDOFF_STORAGE_KEYS.STATE);
  });
});
