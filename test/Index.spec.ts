import {
  initializeAuth,
  getApiKey,
  getAppName,
  getCustomDomain,
  isLoggedIn,
  authValidateAccessToken,
} from '../src';
import {Auth} from '../src/auth.types';

describe('Library initialization', () => {
  test('Correctly initializes auth session', () => {
    const auth = initializeAuth({
      appName: 'test-app-name',
      apiKey: 'xxx-xxx-xxx-xxx',
    });

    expect(auth.appName).toBe('test-app-name');
    expect(auth.apiKey).toBe('xxx-xxx-xxx-xxx');
  });

  test('Does not initialize without required apiKey', () => {
    try {
      initializeAuth({
        apiKey: '',
        appName: 'xxx',
      });
    } catch ({message}) {
      expect(message).toBe('Please Set The LoginRadius ApiKey');
    }
  });

  test('Does not initialize without required appName', () => {
    try {
      initializeAuth({
        apiKey: 'xxx',
        appName: '',
      });
    } catch ({message}) {
      expect(message).toBe('Please Set The LoginRadius APP Name');
    }
  });

  test('Correctly sets default parameters', () => {
    const auth = initializeAuth({
      apiKey: 'xxx',
      appName: 'xxx',
    });

    expect(JSON.stringify(auth)).toBe(
      JSON.stringify({
        apiDomain: 'https://api.loginradius.com',
        appName: 'xxx',
        apiKey: 'xxx',
        token: 'LRTokenKey',
        hubLoginDomain: '.hub.loginradius.com',
        idxURL: 'https://xxx.hub.loginradius.com',
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
          getItem() {
            return null;
          },
          setItem() {
            return false;
          },
          hasItem() {
            return false;
          },
          removeItem() {
            return false;
          },
          keys() {
            return [];
          },
        },
      })
    );
  });
});

describe('Auth methods', () => {
  let auth: Auth;
  beforeEach(() => {
    auth = initializeAuth({
      apiKey: 'xxx',
      appName: 'xxx',
    });
  });

  test('getApiKey returns correct key', () => {
    const key = getApiKey(auth);
    expect(key).toBe('xxx');
  });

  test('getAppName returns correct name', () => {
    const key = getAppName(auth);
    expect(key).toBe('xxx');
  });

  test('getCustomDomain undefined', () => {
    const domain = getCustomDomain(auth);
    expect(domain).toBe(undefined);
  });

  test('isLoggedIn should be false', async () => {
    const loggedIn = await isLoggedIn(auth);
    expect(loggedIn).toBe(false);
  });

  test('cannot log user in with any token', async () => {
    const valid = await authValidateAccessToken(auth, '12340');
    expect(valid.Description).toBe(
      'The provided LoginRadius API key is invalid, please use a valid API key of your LoginRadius account.'
    );
  });
});
