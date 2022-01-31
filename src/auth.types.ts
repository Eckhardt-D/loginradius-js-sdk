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
    getItem: (key: string) => string | null;
    setItem: (
      key: string,
      value: string,
      end: string | number | Date,
      path: string,
      domain: string,
      secure: string
    ) => boolean;
    removeItem: (key: string, path: string, domain: string) => boolean;
    hasItem: (key: string) => boolean;
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
