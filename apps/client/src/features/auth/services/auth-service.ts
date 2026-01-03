import Keycloak from 'keycloak-js';
import type { KeycloakInstance, KeycloakTokenParsed } from 'keycloak-js';

declare global {
  interface Window {
    __KEYCLOAK__?: KeycloakInstance;
    __KC_INITIALIZED__?: boolean;
    __KC_TIMER_STARTED__?: boolean;
    __KC_ACTIVITY_LISTENERS__?: boolean;
  }
}

let _kc: KeycloakInstance;

if (window.__KEYCLOAK__) {
  _kc = window.__KEYCLOAK__;
} else {
  _kc = new Keycloak({
    url: import.meta.env.VITE_KEYCLOAK_BASE_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
  });
  window.__KEYCLOAK__ = _kc;
}

let _kcInitialized = false;
let _initPromise: Promise<boolean> | null = null;

interface AuthUser {
  userId: string;
  email?: string;
  name?: string;
  preferredUsername?: string;
  roles?: string[];
  firstName?: string;
  lastName?: string;
}

const initKeycloak = (onAuthenticatedCallback?: () => void): Promise<boolean> => {
  if (_initPromise) {
    return _initPromise.then(() => {
      onAuthenticatedCallback?.();
      return _kc.authenticated || false;
    });
  }

  if (_kcInitialized) {
    onAuthenticatedCallback?.();
    return Promise.resolve(_kc.authenticated || false);
  }

  const isLoginRedirect =
    window.location.href.includes('code=') || window.location.href.includes('session_state=');

  _initPromise = _kc
    .init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      scope: 'openid profile email',
      silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
      checkLoginIframe: false,
    })
    .then((authenticated) => {
      _kcInitialized = true;
      window.__KC_INITIALIZED__ = true;

      _kc.onAuthSuccess = () => window.dispatchEvent(new CustomEvent('kc-auth-success'));

      if (isLoginRedirect) {
        const url = new URL(window.location.href);
        url.search = '';
        const cleanUrl = url.toString().replace(/\?$/, '');
        window.history.replaceState({}, '', cleanUrl);
      }

      let lastActivity = Date.now();

      if (!window.__KC_ACTIVITY_LISTENERS__) {
        window.__KC_ACTIVITY_LISTENERS__ = true;

        const channel =
          typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('kc-activity') : null;

        const activityEvents = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
        activityEvents.forEach((event) => {
          window.addEventListener(event, () => {
            lastActivity = Date.now();
            if (channel) {
              channel.postMessage(lastActivity);
            } else {
              localStorage.setItem('kc-last-activity', String(lastActivity));
            }
          });
        });

        if (channel) {
          channel.onmessage = (event) => {
            if (typeof event.data === 'number') {
              lastActivity = event.data;
            }
          };
        } else {
          window.addEventListener('storage', (e) => {
            if (e.key === 'kc-last-activity' && e.newValue) {
              lastActivity = Number(e.newValue);
            }
          });
        }
      }

      if (!window.__KC_TIMER_STARTED__) {
        window.__KC_TIMER_STARTED__ = true;
        const twentyFourHours = 24 * 60 * 60 * 1000;

        const refreshTimer = setInterval(() => {
          const now = Date.now();
          const inactiveFor = now - lastActivity;

          if (_kc.authenticated) {
            _kc.updateToken(60).catch(() => {});
            if (inactiveFor >= twentyFourHours) {
              clearInterval(refreshTimer);
              _kc.logout({ redirectUri: window.location.origin + '/' });
            }
          }
        }, 20000);

        _kc.onAuthLogout = () => {
          window.dispatchEvent(new CustomEvent('kc-auth-logout'));
          clearInterval(refreshTimer);
        };
      }

      onAuthenticatedCallback?.();
      return authenticated;
    })
    .catch((error) => {
      _kcInitialized = false;
      _initPromise = null;
      throw error;
    })
    .finally(() => {
      _initPromise = null;
    });

  return _initPromise;
};

const isInitialized = (): boolean => _kcInitialized;

const doRegister = (options?: { redirectUri?: string }) => {
  const redirectUri = options?.redirectUri || window.location.href;
  return _kc.register({ redirectUri, locale: 'en' });
};

const getAccountUrl = (): string => {
  return `${_kc.authServerUrl}/realms/${_kc.realm}/account`;
};

const doLogin = (options?: { redirectUri?: string; prompt?: string; maxAge?: number }) => {
  const redirectUri = options?.redirectUri || window.location.href ;
  return _kc.login({ redirectUri, maxAge: options?.maxAge });
};

const doLogout = (options?: { redirectUri?: string }) => {
  const redirectUri = options?.redirectUri || window.location.origin ;
  if (typeof window !== 'undefined') {
    try {
      sessionStorage.removeItem('currentOrganization');
      sessionStorage.removeItem('userOrganizations');
      sessionStorage.removeItem('primaryOrganization');
      window.dispatchEvent(new CustomEvent('keycloakLogout'));
    } catch {}
  }
  return _kc.logout({ redirectUri });
};

const getToken = (): string | undefined => _kc.token;
const getRefreshToken = (): string | undefined => _kc.refreshToken;
const getTokenParsed = (): KeycloakTokenParsed | undefined => _kc.tokenParsed;
const isLoggedIn = (): boolean => !!_kc.token && !!_kc.authenticated;

const updateToken = (minValidity: number = 30): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    if (!_kcInitialized || !_kc.authenticated) {
      reject(new Error('Keycloak not initialized or not authenticated'));
      return;
    }
    _kc
      .updateToken(minValidity)
      .then((refreshed) => resolve(refreshed))
      .catch((error) => reject(error));
  });
};

const verify = async (options?: { force?: boolean; minValidity?: number }): Promise<boolean> => {
  try {
    if (!isInitialized() || options?.force) {
      const authenticated = await initKeycloak();
      return authenticated;
    }
    if (!isLoggedIn()) return false;
    await updateToken(options?.minValidity || 30);
    return true;
  } catch {
    return false;
  }
};

const getUser = (): AuthUser | undefined => {
  if (!_kc.tokenParsed) return undefined;
  const token = _kc.tokenParsed;
  return {
    userId: token.sub ?? '',
    email: token.email,
    name: token.name,
    firstName: token.given_name,
    lastName: token.family_name,
    preferredUsername: token.preferred_username,
    roles: [
      ...(token.realm_access?.roles ?? []),
      ...Object.values(token.resource_access || {}).flatMap((client: any) => client.roles || []),
    ],
  };
};

const getUsername = (): string | undefined =>
  _kc.tokenParsed?.preferred_username || _kc.tokenParsed?.email;

const isTokenExpired = (minValidity: number = 0): boolean => _kc.isTokenExpired(minValidity);

const getTokenExpirationTime = (): Date | null =>
  _kc.tokenParsed?.exp ? new Date(_kc.tokenParsed.exp * 1000) : null;

const onTokenExpired = (callback: () => void): void => {
  _kc.onTokenExpired = callback;
};

const onAuthSuccess = (callback: () => void): void => {
  _kc.onAuthSuccess = callback;
};

const onAuthError = (callback: (errorData: any) => void): void => {
  _kc.onAuthError = callback;
};

const onAuthRefreshSuccess = (callback: () => void): void => {
  _kc.onAuthRefreshSuccess = callback;
};

const onAuthRefreshError = (callback: () => void): void => {
  _kc.onAuthRefreshError = callback;
};

const needsReAuthentication = (): boolean => !_kc.authenticated || isTokenExpired(30);

const AuthService = {
  initKeycloak,
  doLogin,
  doLogout,
  doRegister,
  verify,
  getToken,
  getRefreshToken,
  getTokenParsed,
  updateToken,
  isTokenExpired,
  getTokenExpirationTime,
  needsReAuthentication,
  getUser,
  getUsername,
  isLoggedIn,
  isInitialized,
  getAccountUrl,
  onTokenExpired,
  onAuthSuccess,
  onAuthError,
  onAuthRefreshSuccess,
  onAuthRefreshError,
};

export default AuthService;
export type { AuthUser };
