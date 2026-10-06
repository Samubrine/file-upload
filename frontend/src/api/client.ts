import type {
  ErrorResponse,
  FileDetail,
  Grant,
  GrantSet,
  MetadataPage,
  Notice,
  OwnerFile,
  OwnerPage,
  Profile,
  Quota,
  Registry,
  Session,
  SharedPage,
} from './types';

let inMemoryCSRFToken: string | null = null;

export function setCSRFToken(token: string | null) {
  inMemoryCSRFToken = token;
}

export function getCSRFToken(): string | null {
  return inMemoryCSRFToken;
}

export class ApiError extends Error {
  status: number;
  code: string;
  requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<{ data: T; etag?: string }> {
  const headers = new Headers(options.headers || {});

  // Inject CSRF token on mutating methods
  const method = (options.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && inMemoryCSRFToken) {
    headers.set('X-CSRF-Token', inMemoryCSRFToken);
  }

  const res = await fetch(path, {
    ...options,
    headers,
    credentials: 'same-origin',
  });

  const etag = res.headers.get('ETag') || undefined;

  if (res.status === 204) {
    return { data: null as unknown as T, etag };
  }

  const contentType = res.headers.get('Content-Type') || '';
  if (!res.ok) {
    let errCode = 'HTTP_ERROR';
    let errMsg = 'Request failed with status ' + res.status;
    let reqId: string | undefined;

    if (contentType.includes('application/json')) {
      try {
        const errJson = (await res.json()) as ErrorResponse;
        errCode = errJson.code || errCode;
        errMsg = errJson.message || errMsg;
        reqId = errJson.request_id;
      } catch {
        // Fallback
      }
    }
    throw new ApiError(res.status, errCode, errMsg, reqId);
  }

  if (contentType.includes('application/json')) {
    const data = (await res.json()) as T;
    return { data, etag };
  }

  return { data: (await res.blob()) as unknown as T, etag };
}

export const api = {
  async getNotice(): Promise<Notice> {
    const res = await request<Notice>('/notice');
    return res.data;
  },

  async register(body: {
    full_name: string;
    username: string;
    email: string;
    birthday?: string | null;
    password: string;
    notice_version: string;
    notice_acknowledged: boolean;
  }): Promise<Session> {
    const res = await request<Session>('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    setCSRFToken(res.data.csrf_token);
    return res.data;
  },

  async login(body: { username: string; password: string }): Promise<Session> {
    const res = await request<Session>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    setCSRFToken(res.data.csrf_token);
    return res.data;
  },

  async getSession(): Promise<Session> {
    const res = await request<Session>('/auth/session');
    if (res.data.csrf_token) {
      setCSRFToken(res.data.csrf_token);
    }
    return res.data;
  },

  async logout(): Promise<void> {
    await request<void>('/auth/logout', { method: 'POST' });
    setCSRFToken(null);
  },

  async getMe(): Promise<{ profile: Profile; etag: string }> {
    const res = await request<Profile>('/me');
    return { profile: res.data, etag: res.etag || '' };
  },

  async patchMe(
    body: { full_name: string; email: string; birthday?: string | null; current_password: string },
    etag: string
  ): Promise<{ profile: Profile; etag: string }> {
    const res = await request<Profile>('/me', {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify(body),
    });
    return { profile: res.data, etag: res.etag || '' };
  },

  async deleteMe(current_password: string, etag: string): Promise<void> {
    await request<void>('/me', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify({ current_password }),
    });
    setCSRFToken(null);
  },

  async putPassword(current_password: string, new_password: string, etag: string): Promise<void> {
    await request<void>('/me/password', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify({ current_password, new_password }),
    });
  },

  async exportMe(): Promise<Profile> {
    const res = await request<Profile>('/me/export');
    return res.data;
  },

  async getQuota(): Promise<Quota> {
    const res = await request<Quota>('/me/quota');
    return res.data;
  },

  async uploadFile(formData: FormData): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files', {
      method: 'POST',
      body: formData,
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async getMine(offset = 0, limit = 20): Promise<OwnerPage> {
    const res = await request<OwnerPage>('/files/mine?offset=' + offset + '&limit=' + limit);
    return res.data;
  },

  async getShared(offset = 0, limit = 20): Promise<SharedPage> {
    const res = await request<SharedPage>('/files/shared?offset=' + offset + '&limit=' + limit);
    return res.data;
  },

  async getListed(offset = 0, limit = 20): Promise<MetadataPage> {
    const res = await request<MetadataPage>('/files/listed?offset=' + offset + '&limit=' + limit);
    return res.data;
  },

  async getFile(id: string): Promise<{ file: FileDetail; etag: string }> {
    const res = await request<FileDetail>('/files/' + id);
    return { file: res.data, etag: res.etag || '' };
  },

  async renameFile(id: string, filename: string, etag: string): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files/' + id, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify({ filename }),
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async deleteFile(id: string, etag: string): Promise<void> {
    await request<void>('/files/' + id, {
      method: 'DELETE',
      headers: { 'If-Match': etag },
    });
  },

  async replaceFile(id: string, formData: FormData, etag: string): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files/' + id + '/content', {
      method: 'PUT',
      headers: { 'If-Match': etag },
      body: formData,
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async setListing(id: string, listed: boolean, etag: string): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files/' + id + '/listing', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify({ listed }),
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async getGrants(fileId: string): Promise<Grant[]> {
    const res = await request<Grant[]>('/files/' + fileId + '/grants');
    return res.data;
  },

  async putGrant(fileId: string, username: string, grantSet: GrantSet, etag: string): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files/' + fileId + '/grants/' + username, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'If-Match': etag,
      },
      body: JSON.stringify(grantSet),
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async deleteGrant(fileId: string, username: string, etag: string): Promise<{ file: OwnerFile; etag: string }> {
    const res = await request<OwnerFile>('/files/' + fileId + '/grants/' + username, {
      method: 'DELETE',
      headers: { 'If-Match': etag },
    });
    return { file: res.data, etag: res.etag || '' };
  },

  async getVariants(): Promise<Registry> {
    const res = await request<Registry>('/crypto/variants');
    return res.data;
  },

  async downloadFile(fileId: string, filename: string, variant = 'aes-256-ctr'): Promise<void> {
    const url = '/files/' + fileId + '/download?variant=' + variant;
    const res = await fetch(url, { credentials: 'same-origin' });
    if (!res.ok) {
      throw new Error('Download failed: ' + res.statusText);
    }
    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
  },
};

