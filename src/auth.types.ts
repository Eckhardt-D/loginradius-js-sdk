export type AuthError = {
  Description: string;
  ErrorCode: number;
  Message: string;
};

export type SDKError = {
  name: string;
  message: string;
};

export type AuthPageOptions = {
  redirect_uri: string;
};

export type Auth = {
  apiKey: string;
  appName: string;
  debugMode: boolean;
  apiDomain: string;
  token: string;
  hubLoginDomain: string;
  customDomain?: string;
  idxURL?: string;
  errorMsgs: {
    [code: number]: AuthError;
  };

  documentCookies: {
    getItem: (sKey: string) => string | null;
    setItem: (
      sKey: string,
      sValue: string,
      vEnd: string | number | Date,
      sPath: string,
      sDomain: string,
      bSecure: string
    ) => boolean;
    removeItem: (sKey: string, sPath: string, sDomain: string) => boolean;
    hasItem: (sKey: string) => boolean;
    keys: () => string[];
  };
};

export type AuthConfig = {
  apiKey: string;
  appName: string;
  debugMode?: boolean;
  apiDomain?: string;
  customDomain?: string;
};
