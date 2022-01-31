# LoginRadius JS SDK

This package is a re-write of [https://github.com/LoginRadius/javascript-sdk](https://github.com/LoginRadius/javascript-sdk). It is re-written in Typescript.

The purpose of this is to have a tested version, but also a version that allows installing the dependency and modular imports of methods by passing the auth instance to each definition.

### Initialization

```js
import {initializeAuth} from 'loginradius-js-sdk';

const auth = initializeAuth({
  appName: 'your-app-name', // required
  apiKey: 'xxx-xxx-xxx', // required
  customDomain: 'hub.loginradius.com', // Optional
  apiDomain: 'https://api.loginradius.com', // Optional
  debugMode: false, // Optional
});
```

This is the auth instance that you can pass to all the methods below.

## Usage

### openLoginPage()

```js
import {openLoginPage} from 'loginradius-js-sdk';

openLoginPage(auth, {
  redirect_uri: window.location.href, // Optional
});
```

### appCallback()

This method fetches the token from query string and store it in browser storage

```js
import {appCallback} from 'loginradius-js-sdk';
appCallback(auth);
```

### isLoggedIn()

This method checks whether the user is logged in or not, and returns a boolean value

```js
import {isLoggedIn} from 'loginradius-js-sdk';
isLoggedIn(auth); // true / false
```

### logout()

This method triggers logout action

```js
import {logout} from 'loginradius-js-sdk';

logout(auth, {
  redirect_uri: window.location.href, // Optional
});
```

Here returnTo is the return url, where the user will be redirected after successful logout.

### openRegisterPage()

This method triggers registration action and redirects to the LoginRadius IDX registration section.

```js
import {openRegisterPage} from 'loginradius-js-sdk';

openRegisterPage(auth, {
  redirect_uri: window.location.href, // Optional
});
```

Here redirect_uri is the return url, where the user will be redirected after a successful registration.

### profileUpdate()

This method redirects to LoginRadius IDX profile.aspx page.

```js
import {profileUpdate} from 'loginradius-js-sdk';

profileUpdate(auth);
```

### forgotPassword()

This method triggers forgot password action and redirects to LoginRadius IDX forgot password section

```js
import {forgotPassword} from 'loginradius-js-sdk';

forgotPassword(auth, {
  redirect_uri: window.location.href, // Optional
});
```

Here redirect_uri is the return url, where the user will be redirected after forgot password action.

### getToken()

This method gets access token from the browser's local storage

```js
import {getToken} from 'loginradius-js-sdk';
const token = getToken(auth);
```

### getUserProfile()

This method fetches the profile based on the access token.

```js
import {getUserProfile} from 'loginradius-js-sdk';
const profile = await getUserProfile(auth);
```
