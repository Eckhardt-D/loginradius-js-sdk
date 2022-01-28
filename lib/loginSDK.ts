class LRError extends Error {
  constructor(errorType: string, error_description: string) {
    super(error_description);
    this.name = errorType;
    this.message = error_description;
  }
}

export default class initializeSDKClient {
  apiKey;
  appName;
  debugMode;
  /** LoginRadius default api domian */
  apiDomain = 'https://api.loginradius.com';
  /** Access token browser storage Key */
  token = 'LRTokenKey';
  /** LoginRadius default IDX hub domain */
  hubLoginDomain = '.hub.loginradius.com';
  /** LoginRadius IDX custom domain */
  customDomain;
  idxURL: string;
  errorMsgs = {
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
  };

  documentCookies = {
    getItem: function (sKey) {
      if (!sKey) {
        return null;
      }
      return (
        decodeURIComponent(
          document.cookie.replace(
            new RegExp(
              '(?:(?:^|.*;)\\s*' +
                encodeURIComponent(sKey).replace(/[-.+*]/g, '\\$&') +
                '\\s*\\=\\s*([^;]*).*$)|^.*$'
            ),
            '$1'
          )
        ) || null
      );
    },
    setItem: function (sKey, sValue, vEnd, sPath, sDomain, bSecure) {
      if (!sKey || /^(?:expires|max-age|path|domain|secure)$/i.test(sKey)) {
        return false;
      }
      let sExpires = '';
      const vExpiryDate = {
        getInStringFormat: function (nMaxAge) {
          //"max-age" in second
          if (nMaxAge === Infinity) {
            return 'Fri, 31 Dec 9999 23:59:59 GMT';
          }
          const dDate = new Date();
          dDate.setTime(dDate.getTime() + nMaxAge * 1000);
          return dDate.toUTCString();
        },
      };
      if (vEnd) {
        switch (vEnd.constructor) {
          case Number:
            sExpires =
              '; expires=' +
              vExpiryDate.getInStringFormat(vEnd) +
              (vEnd === Infinity ? '' : '; max-age=' + vEnd);
            break;
          case String:
            sExpires = '; expires=' + vEnd;
            break;
          case Date:
            sExpires = '; expires=' + vEnd.toUTCString();
            break;
        }
      }
      document.cookie =
        encodeURIComponent(sKey) +
        '=' +
        encodeURIComponent(sValue) +
        sExpires +
        (sDomain ? '; domain=' + sDomain : '') +
        (sPath ? '; path=' + sPath : '') +
        (bSecure ? '; secure' : '');
      return true;
    },
    removeItem: function (sKey, sPath, sDomain) {
      if (!this.hasItem(sKey)) {
        return false;
      }
      document.cookie =
        encodeURIComponent(sKey) +
        '=; expires=Thu, 01 Jan 1970 00:00:00 GMT' +
        (sDomain ? '; domain=' + sDomain : '') +
        (sPath ? '; path=' + sPath : '');
      return true;
    },
    hasItem: function (sKey) {
      if (!sKey) {
        return false;
      }
      return new RegExp(
        '(?:^|;\\s*)' +
          encodeURIComponent(sKey).replace(/[-.+*]/g, '\\$&') +
          '\\s*\\='
      ).test(document.cookie);
    },
    keys: function () {
      const aKeys = document.cookie
        .replace(/((?:^|\s*;)[^=]+)(?=;|$)|^\s*|\s*(?:=[^;]*)?(?:\1|$)/g, '')
        .split(/\s*(?:=[^;]*)?;\s*/);
      for (let nLen = aKeys.length, nIdx = 0; nIdx < nLen; nIdx++) {
        aKeys[nIdx] = decodeURIComponent(aKeys[nIdx]);
      }
      return aKeys;
    },
  };

  /**
  @constructor	creates an intance of class initializeSDKClient
  * @param {options} options.apiKey Required | LoginRadius API Key.
  * @param {options} options.appName Required | LoginRadius App Name.
  * @param {options} options.debugMode Optional | Type Boolean - log errors in browser log.
  * @param {options} options.apiDomain Optional | LoginRadius Api domain.
  * @param {options} options.customDomain Optional | LoginRadius IDX custom domain.
   */
  constructor(options) {
    if (!options.apiKey) {
      throw new LRError('API_Key', 'Please Set The LoginRadius ApiKey');
    }

    if (!options.appName) {
      throw new LRError('APP_Name', 'Please Set The LoginRadius APP Name');
    }

    this.apiKey = options.apiKey;
    this.appName = options.appName;

    if (options.debugMode === true) {
      this.debugMode = true;
    }

    if (options.apiDomain) {
      this.apiDomain = options.apiDomain;
    }
    if (options.customDomain) {
      this.customDomain = options.customDomain;
    }
  }

  get getApiKey() {
    if (this.apiKey) {
      return this.apiKey;
    } else {
      throw new LRError('API_Key', 'Please Set The LoginRadius ApiKey');
    }
  }
  get getAppName() {
    if (this.appName) {
      return this.appName;
    } else {
      throw new LRError('APP_Name', 'Please Set The LoginRadius APP Name');
    }
  }
  get getCustomDomain() {
    if (this.customDomain) {
      return this.customDomain;
    } else {
      return false;
    }
  }

  /**
   *@public function is used to fectch the token from query string and to store it in browser storage
   */

  async appCallback() {
    const query = window.location.search;
    if (query.includes('token=')) {
      const access_token = await this.getUrlParameter('token');
      await this.setBrowserStorage(this.token, access_token);
    }
  }

  /**
   * @private function is used to get the query parameter value
   * @param sParam The query parameter
   */

  async getUrlParameter(sParam) {
    const sPageURL = decodeURIComponent(window.location.search.substring(1));
    const sURLVariables = sPageURL.split('&');
    let sParameterName, i;

    for (i = 0; i < sURLVariables.length; i++) {
      sParameterName = sURLVariables[i].split('=');

      if (sParameterName[0] === sParam) {
        return sParameterName[1] === undefined ? true : sParameterName[1];
      }
    }
  }

  /** @private function is used to check local storage is supported or not
   *
   *
   * @param fn {lsName}
   */
  async isLocalStorageNameSupported(lsName) {
    if (window[lsName]) {
      const testKey = 'test',
        storage = window[lsName as 'localStorage' | 'sessionStorage'];
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

  /** @private function is used to set local storage
   *
   * @param fn {lsName}
   */
  async setBrowserStorage(key, value) {
    let cookieFallback = true;
    if (this.isLocalStorageNameSupported('localStorage')) {
      localStorage.setItem(key, value);
      cookieFallback = false;
    }

    if (this.isLocalStorageNameSupported('sessionStorage')) {
      sessionStorage.setItem(key, value);
      cookieFallback = false;
    }

    if (cookieFallback) {
      this.documentCookies.setItem(key, value, '', window.location, null, null);
    }
  }

  /** @public function is used to validate access token.
   * @param {options} accessToken LoginRadius access token.
   * @return LoginRadius Auth validate access token API response
   **/
  async authValidateAccessToken(accessToken) {
    if (this._utilisNull(accessToken)) {
      return this._util_message('accessToken');
    }

    const queryParameters: {access_token: string} = {access_token: ''};

    queryParameters.access_token = accessToken;

    const resourcePath = 'identity/v2/auth/access_token/validate';
    try {
      const APIresponse = await this._util_xhttpCall(
        'GET',
        resourcePath,
        queryParameters
      );

      return APIresponse;
    } catch (err) {
      this.errorMsgs[1000].Description = err;
      return this.errorMsgs[1000];
    }
  }

  /**  @public function trigger's login action
   * @param {options} options.redirect_uri URL where to redirect after login action.
   * @return redirect to LoginRadius IDX login section
   **/
  async openLoginPage(options) {
    try {
      if (this._utilisNull(options) || this._utilisNull(options.redirect_uri)) {
        const options = {
          redirect_uri: window.location.href,
        };

        const url = await this.buildLoginURL(options);

        window.location.assign(url);
      } else {
        const url = await this.buildLoginURL(options);

        window.location.assign(url);
      }
    } catch (err) {
      throw new LRError(err, 'Login Page Redirection Failed.');
    }
  }

  /** @public function is trigger registration action
   * @param {options} options.redirect_uri URL where to redirect after registration action.
   * @return redirect to LoginRadius IDX registration section
   **/
  async openRegisterPage(options) {
    try {
      if (this._utilisNull(options) || this._utilisNull(options.redirect_uri)) {
        const options = {
          redirect_uri: window.location.href,
        };

        const url = await this.buildRegisterURL(options);

        window.location.assign(url);
      } else {
        const url = await this.buildRegisterURL(options);

        window.location.assign(url);
      }
    } catch (err) {
      throw new LRError(err, 'Registration Page Redirection Failed.');
    }
  }

  /**  @public function is trigger forgot password action
   * @param {options} options.redirect_uri URL where to redirect after forgot password action.
   * @return redirect to LoginRadius IDX forgot password section
   **/

  async forgotPassword(options) {
    try {
      if (this._utilisNull(options) || this._utilisNull(options.redirect_uri)) {
        const options = {
          redirect_uri: window.location.href,
        };

        const url = await this.buildForgotPasswordURL(options);

        window.location.assign(url);
      } else {
        const url = await this.buildForgotPasswordURL(options);

        window.location.assign(url);
      }
    } catch (err) {
      throw new LRError(err, 'Forgot Password Redirection Failed.');
    }
  }

  /**  @private function is used to build login URL
   * @param {options} options.redirect_uri URL where to redirect after login action.
   * @return login URL
   **/
  async buildLoginURL(options) {
    const loginPath = '/auth.aspx';
    const redirect_uri = options.redirect_uri || window.location.href;

    if (this.getCustomDomain) {
      this.idxURL = this.getCustomDomain;
    } else {
      this.idxURL = 'https://' + this.getAppName + this.hubLoginDomain;
    }
    const url =
      this.idxURL + loginPath + '?action=login&return_url=' + redirect_uri;
    return url;
  }

  /**  @private function is used to build registration URL
   * @param {options} options.redirect_uri URL where to redirect after registration action.
   * @return registration URL
   **/
  async buildRegisterURL(options) {
    const ReigsterPath = '/auth.aspx';
    const redirect_uri = options.redirect_uri || window.location.href;

    if (this.getCustomDomain) {
      this.idxURL = this.getCustomDomain;
    } else {
      this.idxURL = 'https://' + this.getAppName + this.hubLoginDomain;
    }
    const url =
      this.idxURL +
      ReigsterPath +
      '?action=register&return_url=' +
      redirect_uri;
    return url;
  }

  /** @private function is used to build forgot password URL
   * @param {options} options.redirect_uri URL where to redirect after forgot password action.
   * @return forgot password URL
   **/
  async buildForgotPasswordURL(options) {
    const ForgotPasswordPath = '/auth.aspx';
    const redirect_uri = options.redirect_uri || window.location.href;

    if (this.getCustomDomain) {
      this.idxURL = this.getCustomDomain;
    } else {
      this.idxURL = 'https://' + this.getAppName + this.hubLoginDomain;
    }
    const url =
      this.idxURL +
      ForgotPasswordPath +
      '?action=forgotpassword&return_url=' +
      redirect_uri;
    return url;
  }

  /** @private function is used to build profile update URL
   * @return profile update URL
   **/
  async buildProfileUpdateURL() {
    const profilePath = '/profile.aspx';

    if (this.getCustomDomain) {
      this.idxURL = this.getCustomDomain;
    } else {
      this.idxURL = 'https://' + this.getAppName + this.hubLoginDomain;
    }
    const url = this.idxURL + profilePath;
    return url;
  }

  /**  @public function is trigger profile update action
   * @return redirect to LoginRadius IDX profile.aspx page
   **/
  async profileUpdate() {
    try {
      const checkLoginStatus = await this.isLoggedIn();

      if (checkLoginStatus) {
        const profileUrl = await this.buildProfileUpdateURL();
        window.location.assign(profileUrl);
      } else {
        this._util_log('User is not logged in');
        return this.errorMsgs[905];
      }
    } catch (err) {
      throw new LRError(err, 'Profile Page Redirection Failed.');
    }
  }

  /**  @public function is trigger logout action
   * @param {options} options.redirect_uri URL where to redirect after logout action.
   * @return redirects to the return url
   **/
  async logout(options) {
    try {
      if (this._utilisNull(options) || this._utilisNull(options.returnTo)) {
        const options = {
          returnTo: window.location.href,
        };

        localStorage.removeItem(this.token);
        sessionStorage.removeItem(this.token);
        this.documentCookies.removeItem(this.token, null, null);

        const url = await this.buildLogoutURL(options);

        window.location.assign(url);
      } else {
        localStorage.removeItem(this.token);
        sessionStorage.removeItem(this.token);
        this.documentCookies.removeItem(this.token, null, null);

        const url = await this.buildLogoutURL(options);

        window.location.assign(url);
      }
    } catch (err) {
      throw new LRError(err, 'Logout Error.');
    }
  }

  /** @private function is used to build Logout URL
   * @param {options} options.returnTo URL where to redirect after logout action.
   * @return Logout URL
   **/
  async buildLogoutURL(options) {
    const logoutPath = '/auth.aspx';
    const returnTo = options.returnTo || window.location.href;

    if (this.getCustomDomain) {
      this.idxURL = this.getCustomDomain;
    } else {
      this.idxURL = 'https://' + this.getAppName + this.hubLoginDomain;
    }

    const url =
      this.idxURL + logoutPath + '?action=logout&return_url=' + returnTo;
    return url;
  }

  /**  @public function is used to fetch the profile based on access token and internally calls getProfileByAccessToken method
   * @return API response
   **/
  async getUserProfile() {
    const storedToken = await this.getTokenFromStorage();
    if (storedToken) {
      const APIresponse = await this.getProfileByAccessToken(storedToken, null);

      if (APIresponse.ErrorCode) {
        localStorage.removeItem(this.token);
        sessionStorage.removeItem(this.token);
        this.documentCookies.removeItem(this.token, null, null);
      }
      return APIresponse;
    } else {
      return this.errorMsgs[905];
    }
  }

  /** @public function is used to fetch the profile based on access token
   * @param {accessToken} accessToken LoginRadius access token
   * @param {fields} fields other query parameters
   * @return API response
   **/
  async getProfileByAccessToken(accessToken, fields) {
    if (this._utilisNull(accessToken)) {
      return this._util_message('accessToken');
    }
    const queryParameters = {access_token: '', fields: []};

    queryParameters.access_token = accessToken;
    if (!this._utilisNull(fields)) {
      queryParameters.fields = fields;
    }

    const resourcePath = 'identity/v2/auth/account';

    try {
      const APIresponse = await this._util_xhttpCall(
        'GET',
        resourcePath,
        queryParameters
      );

      return APIresponse;
    } catch (err) {
      this.errorMsgs[1000].Description = err;
      return this.errorMsgs[1000];
    }
  }

  /**  @public function is checks whether user is logged in or not
   * @return bollean value
   **/
  async isLoggedIn() {
    const storedToken = await this.getTokenFromStorage();

    if (storedToken) {
      const isValidResponse = await this.authValidateAccessToken(storedToken);
      if (isValidResponse.access_token) {
        return true;
      } else {
        localStorage.removeItem(this.token);
        sessionStorage.removeItem(this.token);
        this.documentCookies.removeItem(this.token, null, null);

        return false;
      }
    } else {
      return false;
    }
  }

  /** @private function is used to get token from local storage
   **/
  async getTokenFromStorage() {
    return this.getBrowserStorage(this.token);
  }

  /** @public this function is used to get token from browser's local storage
   **/
  async getToken() {
    try {
      const accessTokenValue = await this.getTokenFromStorage();

      return accessTokenValue;
    } catch (err) {
      return this.errorMsgs[906];
    }
  }

  /**   @private function is used to get local storage
   *
   * @param fn {lsName}
   */
  async getBrowserStorage(key) {
    if (
      this.isLocalStorageNameSupported('localStorage') &&
      localStorage.getItem(key) !== null &&
      localStorage.getItem(key) !== undefined &&
      localStorage.getItem(key) !== ''
    ) {
      return localStorage.getItem(key);
    }
    if (
      this.isLocalStorageNameSupported('sessionStorage') &&
      sessionStorage.getItem(key) !== null &&
      sessionStorage.getItem(key) !== undefined &&
      sessionStorage.getItem(key) !== ''
    ) {
      return sessionStorage.getItem(key);
    }

    return this.documentCookies.getItem(key);
  }

  /**
   * @private Check null or undefined
   * @param {string} as input
   * @return input is null or not
   */
  _utilisNull(input) {
    return !(input === null || typeof input === 'undefined' ? '' : input);
  }

  /**
   * @private Check null or undefined
   * @param {string} as input
   * @return input is null or not
   */
  _util_uuidFormat =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  /**
   * @private Check json is correct or not
   * @param {string} input
   * @return input is json or not
   */
  _util_checkJson(input) {
    return (
      input === null ||
      input === undefined ||
      Array.isArray(input) ||
      typeof input !== 'object'
    );
  }

  /**
   * @private Get Validation Message
   * @param {string} type as error string
   * @return jsondata as json error object
   */
  _util_message(type) {
    this.errorMsgs[1000].Description =
      'The API Request Paramter ' + type + ' is not Correct or WellFormated';
    return this.errorMsgs[1000];
  }

  /**
   *  @private function log
   * @memberof util#
   * @param {String} message to be logged
   * @description This funtion is used to log error/warning message in browser if debug mode has been made true.
   */
  _util_log(message) {
    if (this.debugMode) {
      if (typeof console !== 'undefined') {
        console.error(message);
      }
    }
  }

  /**
   * @private The Function is used to Handle All GET, POST, PUT and DELETE API Request on Server.
   *
   * @param method
   * @param path
   * @param queryParameters
   */
  async _util_xhttpCall(method, path, queryParameters) {
    if (this.getApiKey) {
      if (!this._util_uuidFormat.test(this.getApiKey)) {
        this._util_log('apiKey is not in valid guid format.');
        return this.errorMsgs[920];
      } else {
        queryParameters.apiKey = this.getApiKey;

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
          this.apiDomain +
          '/' +
          path +
          '?' +
          this._util_makeQuerySting(queryParameters);

        try {
          const response = await fetch(url, fecthparmaters);

          if (!response.ok) {
            throw new LRError('ApiError', response.statusText);
          } else {
            const data = await response.json();
            return data;
          }
        } catch (err) {
          this._util_log('API call error:' + err);
          // return a proper error message

          this.errorMsgs[1000].Description = err;
          return this.errorMsgs[1000];
        }
      }
    } else {
      this._util_log('Please set the LoginRadius ApiKey');
      return this.errorMsgs[920];
    }
  }
  /**
   * @private The Function is used to get query string
   * @param object
   */
  _util_makeQuerySting(object) {
    const qstring = [];
    for (const row in object) {
      qstring.push(
        encodeURIComponent(row) + '=' + encodeURIComponent(object[row])
      );
    }
    return qstring.join('&');
  }
}
