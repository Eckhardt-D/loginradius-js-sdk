import {Auth, AuthConfig, AuthPageOptions} from './auth.types';
import {LibError} from './error';

const _util_uuidFormat =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const getApiKey = (auth: Auth): string => auth.apiKey;
export const getAppName = (auth: Auth): string => auth.appName;
export const getCustomDomain = (auth: Auth): string | undefined =>
  auth.customDomain;

export const initializeAuth = (config: AuthConfig): Auth => {
  if (!config.apiKey) {
    throw new LibError('API_Key', 'Please Set The LoginRadius ApiKey');
  }

  if (!config.appName) {
    throw new LibError('APP_Name', 'Please Set The LoginRadius APP Name');
  }

  const hubLoginDomain = '.hub.loginradius.com';

  return {
    apiDomain: config.apiDomain || 'https://api.loginradius.com',
    appName: config.appName,
    apiKey: config.apiKey,
    token: 'LRTokenKey',
    hubLoginDomain,
    idxURL: config.customDomain || 'https://' + config.appName + hubLoginDomain,
    errorMsgs: {
      920: {
        Description:
          'The provided LoginRadius API key is invalid, please use a valid API key of your LoginRadius account.',
        ErrorCode: 920,
        Message: 'API key is invalid',
      },
      1000: {
        Description: 'Oops something went wrong, Please try again.',
        ErrorCode: 1000,
        Message: 'Oops something went wrong, Please try again.',
      },
      905: {
        Description: 'The user is not logged in, Please login again.',
        ErrorCode: 905,
        Message: 'The user is not logged in, Please login again.',
      },
      906: {
        Description: 'Access token not found. Please login again.',
        ErrorCode: 906,
        Message: 'Access token not found. Please login again.',
      },
    },
    debugMode: false,
    documentCookies: {
      getItem(key) {
        if (!key) return null;

        return (
          decodeURIComponent(
            document.cookie.replace(
              new RegExp(
                '(?:(?:^|.*;)\\s*' +
                  encodeURIComponent(key).replace(/[-.+*]/g, '\\$&') +
                  '\\s*\\=\\s*([^;]*).*$)|^.*$'
              ),
              '$1'
            )
          ) || null
        );
      },
      setItem(key, value, end, path, domain, secure) {
        if (!key || /^(?:expires|max-age|path|domain|secure)$/i.test(key)) {
          return false;
        }

        let expires = '';
        const expiryDate = {
          getInStringFormat(maxAge: number): string {
            if (maxAge === Infinity) {
              return 'Fri, 31 Dec 9999 23:59:59 GMT';
            }
            const date = new Date();
            date.setTime(date.getTime() + maxAge * 1000);
            return date.toUTCString();
          },
        };
        if (end) {
          switch (end.constructor) {
            case Number:
              expires = `;expires=${expiryDate.getInStringFormat(
                end as number
              )}`;
              '; expires=' +
                expiryDate.getInStringFormat(end as number) +
                (end === Infinity ? '' : '; max-age=' + end);
              break;
            case String:
              expires = '; expires=' + end;
              break;
            case Date:
              end = '; expires=' + (end as Date).toUTCString();
              break;
          }
        }
        document.cookie =
          encodeURIComponent(key) +
          '=' +
          encodeURIComponent(value) +
          expires +
          (domain ? '; domain=' + domain : '') +
          (path ? '; path=' + path : '') +
          (secure ? '; secure' : '');
        return true;
      },
      hasItem(key) {
        if (!key) {
          return false;
        }

        return new RegExp(
          '(?:^|;\\s*)' +
            encodeURIComponent(key).replace(/[-.+*]/g, '\\$&') +
            '\\s*\\='
        ).test(document.cookie);
      },
      removeItem(key, path, domain) {
        if (!this.hasItem(key)) {
          return false;
        }

        document.cookie =
          encodeURIComponent(key) +
          '=; expires=Thu, 01 Jan 1970 00:00:00 GMT' +
          (domain ? '; domain=' + domain : '') +
          (path ? '; path=' + path : '');

        return true;
      },
      keys() {
        const keys = document.cookie
          .replace(/((?:^|\s*;)[^=]+)(?=;|$)|^\s*|\s*(?:=[^;]*)?(?:\1|$)/g, '')
          .split(/\s*(?:=[^;]*)?;\s*/);

        for (let length = keys.length, i = 0; i < length; i++) {
          keys[i] = decodeURIComponent(keys[i]);
        }

        return keys;
      },
    },
  };
};

export const isLoggedIn = async (auth: Auth): Promise<boolean> => {
  const storedToken = await getTokenFromStorage(auth, auth.token);

  if (storedToken) {
    try {
      const isValidResponse = await authValidateAccessToken(auth, storedToken);

      return (
        isValidResponse ||
        (() => {
          localStorage.removeItem(auth.token);
          sessionStorage.removeItem(auth.token);
          auth.documentCookies.removeItem(auth.token, '', '');
          return false;
        })()
      );
    } catch ({message}) {
      throw new LibError(message as string, 'Could not validate access token.');
    }
  } else {
    return false;
  }
};

export const logout = (auth: Auth, options: AuthPageOptions): void => {
  try {
    if (_utilisNull(options) || _utilisNull(options.redirect_uri)) {
      const options = {
        redirect_uri: window.location.href,
      };

      localStorage.removeItem(auth.token);
      sessionStorage.removeItem(auth.token);
      auth.documentCookies.removeItem(auth.token, '', '');
      const url = buildLogoutURL(auth, options);
      window.location.assign(url);
    } else {
      localStorage.removeItem(auth.token);
      sessionStorage.removeItem(auth.token);
      auth.documentCookies.removeItem(auth.token, '', '');
      const url = buildLogoutURL(auth, options);
      window.location.assign(url);
    }
  } catch ({message}) {
    throw new LibError(message as string, 'Logout Error.');
  }
};

export const appCallback = async (auth: Auth): Promise<void> => {
  const query = window.location.search;

  if (query.includes('token=')) {
    const access_token = await getUrlParameter('token');
    await setBrowserStorage(auth, auth.token, access_token);
  }
};

export const authValidateAccessToken = async (
  auth: Auth,
  accessToken: string
): Promise<boolean> => {
  if (_utilisNull(accessToken)) {
    _util_message(auth, 'accessToken');
    return false;
  }

  const queryParameters = {access_token: accessToken, apiKey: auth.apiKey};
  const resourcePath = 'identity/v2/auth/access_token/validate';

  try {
    const APIresponse = await _util_xhttpCall(
      auth,
      'GET',
      resourcePath,
      queryParameters
    );

    return APIresponse;
  } catch ({message}) {
    auth.errorMsgs[1000].Description = message as string;
    auth.errorMsgs[1000];
    return false;
  }
};

export const openRegisterPage = (
  auth: Auth,
  options: AuthPageOptions
): void => {
  try {
    if (_utilisNull(options) || _utilisNull(options.redirect_uri)) {
      window.location.assign(
        buildRegisterURL(auth, {
          redirect_uri: window.location.href,
        })
      );
    } else {
      window.location.assign(buildRegisterURL(auth, options));
    }
  } catch ({message}) {
    throw new LibError(
      message as string,
      'Registration Page Redirection Failed.'
    );
  }
};

export const openLoginPage = (auth: Auth, options: AuthPageOptions): void => {
  try {
    if (_utilisNull(options) || _utilisNull(options.redirect_uri)) {
      options = {
        redirect_uri: window.location.href,
      };

      const url = buildLoginURL(auth, options);
      window.location.assign(url);
    } else {
      const url = buildLoginURL(auth, options);
      window.location.assign(url);
    }
  } catch ({message}) {
    throw new LibError(message as string, 'Login Page Redirection Failed.');
  }
};

export const forgotPassword = (auth: Auth, options: AuthPageOptions): void => {
  try {
    if (_utilisNull(options) || _utilisNull(options.redirect_uri)) {
      window.location.assign(
        buildForgotPasswordURL(auth, {
          redirect_uri: window.location.href,
        })
      );
    } else {
      window.location.assign(buildForgotPasswordURL(auth, options));
    }
  } catch ({message}) {
    throw new LibError(
      message as string,
      'Forgot Password Redirection Failed.'
    );
  }
};

export const profileUpdate = async (auth: Auth): Promise<void> => {
  try {
    const checkLoginStatus = await isLoggedIn(auth);

    if (checkLoginStatus) {
      const profileUrl = await buildProfileUpdateURL(auth);
      window.location.assign(profileUrl);
      return;
    } else {
      _util_log(auth, 'User is not logged in');
      auth.errorMsgs[905];
    }
  } catch ({message}) {
    throw new LibError(message as string, 'Profile Page Redirection Failed.');
  }
};

export const getUserProfile = async (auth: Auth) => {
  const storedToken = getTokenFromStorage(auth, auth.token);
  if (storedToken) {
    const APIresponse = await getProfileByAccessToken(auth, storedToken, '');

    if (APIresponse.ErrorCode) {
      localStorage.removeItem(auth.token);
      sessionStorage.removeItem(auth.token);
      auth.documentCookies.removeItem(auth.token, '', '');
    }
    return APIresponse;
  } else {
    return auth.errorMsgs[905];
  }
};

async function getProfileByAccessToken(
  auth: Auth,
  token: string,
  fields: string
) {
  if (_utilisNull(token)) {
    return _util_message(auth, 'accessToken');
  }

  const queryParameters = {access_token: '', fields: ''};

  queryParameters.access_token = token;

  if (!_utilisNull(fields)) {
    queryParameters.fields = fields;
  }

  const resourcePath = 'identity/v2/auth/account';

  try {
    const APIresponse = await _util_xhttpCall(
      auth,
      'GET',
      resourcePath,
      queryParameters
    );

    return APIresponse;
  } catch ({message}) {
    auth.errorMsgs[1000].Description = message as string;
    return auth.errorMsgs[1000];
  }
}

function getTokenFromStorage(auth: Auth, token: string) {
  return getBrowserStorage(auth, token);
}

function getBrowserStorage(auth: Auth, key: string) {
  if (
    isLocalStorageNameSupported('localStorage') &&
    localStorage.getItem(key) !== null &&
    localStorage.getItem(key) !== undefined &&
    localStorage.getItem(key) !== ''
  ) {
    return localStorage.getItem(key);
  }
  if (
    isLocalStorageNameSupported('sessionStorage') &&
    sessionStorage.getItem(key) !== null &&
    sessionStorage.getItem(key) !== undefined &&
    sessionStorage.getItem(key) !== ''
  ) {
    return sessionStorage.getItem(key);
  }

  return auth.documentCookies.getItem(key);
}

async function setBrowserStorage(auth: Auth, key: string, value: string) {
  let cookieFallback = true;
  if (await isLocalStorageNameSupported('localStorage')) {
    localStorage.setItem(key, value);
    cookieFallback = false;
  }

  if (await isLocalStorageNameSupported('sessionStorage')) {
    sessionStorage.setItem(key, value);
    cookieFallback = false;
  }

  if (cookieFallback) {
    auth.documentCookies.setItem(
      key,
      value,
      '',
      window.location.pathname,
      '',
      ''
    );
  }
}

async function getUrlParameter(param: string): Promise<string> {
  const pageURL = decodeURIComponent(window.location.search.substring(1));
  const urlVariables = pageURL.split('&');
  let parameterName, i;
  let response = '';

  for (i = 0; i < urlVariables.length; i++) {
    parameterName = urlVariables[i].split('=');

    if (parameterName[0] === param) {
      response = parameterName[1] === undefined ? '' : parameterName[1];
      break;
    }
  }

  return response;
}

function isLocalStorageNameSupported(
  name: 'localStorage' | 'sessionStorage'
): boolean {
  if (window[name]) {
    const testKey = 'test',
      storage = window[name];

    try {
      storage.setItem(testKey, '1');
      storage.removeItem(testKey);
      return true;
    } catch (error) {
      return false;
    }
  } else {
    return false;
  }
}

function _util_log(auth: Auth, message: string): void {
  if (auth.debugMode) {
    if (typeof console !== 'undefined') {
      console.error(message);
    }
  }
}

function _utilisNull(input: unknown) {
  return !(input === null || typeof input === 'undefined' ? '' : input);
}

function _util_message(auth: Auth, type: string) {
  auth.errorMsgs[1000].Description =
    'The API Request Paramter ' + type + ' is not Correct or WellFormated';
  return auth.errorMsgs[1000];
}

async function _util_xhttpCall(
  auth: Auth,
  method: string,
  path: string,
  queryParameters: {access_token: string; apiKey?: string; fields?: string}
) {
  if (!auth.apiKey) {
    _util_log(auth, 'Please set the LoginRadius ApiKey');
    return auth.errorMsgs[920];
  }

  if (!_util_uuidFormat.test(auth.apiKey)) {
    _util_log(auth, 'apiKey is not in valid guid format.');
    return auth.errorMsgs[920];
  } else {
    queryParameters.apiKey = auth.apiKey;

    const fecthparmaters = {
      method: '',
      headers: {},
    };

    fecthparmaters.method = method;
    fecthparmaters.headers = {
      'Content-type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    };

    const url =
      auth.apiDomain + '/' + path + '?' + _util_makeQuerySting(queryParameters);

    try {
      const response = await fetch(url, fecthparmaters);

      if (!response.ok) {
        throw new LibError('ApiError', response.statusText);
      } else {
        const data = await response.json();
        return data;
      }
    } catch ({message}) {
      _util_log(auth, ('API call error:' + message) as string);
      auth.errorMsgs[1000].Description = message as string;
      return auth.errorMsgs[1000];
    }
  }
}

function _util_makeQuerySting(queryParameters: {
  access_token: string;
  apiKey?: string;
  fields?: string;
}): string {
  const qstring: string[] = [];

  Object.entries(queryParameters).forEach(([key, value]) => {
    qstring.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });

  return qstring.join('&');
}

function buildLoginURL(auth: Auth, options: AuthPageOptions): string {
  const loginPath = '/auth';
  const redirect_uri = options.redirect_uri || window.location.href;
  const customDomain = auth.customDomain;
  auth.idxURL =
    customDomain || 'https://' + getAppName(auth) + auth.hubLoginDomain;
  const url =
    auth.idxURL + loginPath + '?action=login&return_url=' + redirect_uri;
  return url;
}

function buildLogoutURL(auth: Auth, options: AuthPageOptions) {
  const logoutPath = '/auth';
  const returnTo = options.redirect_uri || window.location.href;
  auth.idxURL =
    auth.customDomain || 'https://' + auth.appName + auth.hubLoginDomain;
  const url =
    auth.idxURL + logoutPath + '?action=logout&return_url=' + returnTo;
  return url;
}

function buildRegisterURL(auth: Auth, options: AuthPageOptions): string {
  const ReigsterPath = '/auth';
  const redirect_uri = options.redirect_uri || window.location.href;
  auth.idxURL =
    auth.customDomain || 'https://' + auth.appName + auth.hubLoginDomain;

  const url =
    auth.idxURL + ReigsterPath + '?action=register&return_url=' + redirect_uri;
  return url;
}

function buildForgotPasswordURL(auth: Auth, options: AuthPageOptions) {
  const forgotPasswordPath = '/auth';
  const redirect_uri = options.redirect_uri || window.location.href;
  auth.idxURL =
    auth.customDomain || 'https://' + auth.appName + auth.hubLoginDomain;

  const url =
    auth.idxURL +
    forgotPasswordPath +
    '?action=forgotpassword&return_url=' +
    redirect_uri;
  return url;
}

function buildProfileUpdateURL(auth: Auth) {
  const profilePath = '/profile';
  auth.idxURL =
    auth.customDomain || 'https://' + auth.appName + auth.hubLoginDomain;
  const url = auth.idxURL + profilePath;
  return url;
}
