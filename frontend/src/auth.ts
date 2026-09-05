/**
 * Cognito OIDC auth using oidc-client-ts.
 * Handles login redirect, callback, token storage, and logout.
 *
 * Domain-agnostic: the auth flow is independent of the app's threat-intel domain.
 */

import { UserManager, WebStorageStateStore, User } from 'oidc-client-ts';

const cognitoDomain = import.meta.env.VITE_COGNITO_DOMAIN;
const clientId = import.meta.env.VITE_COGNITO_CLIENT_ID;
const redirectUri = import.meta.env.VITE_COGNITO_REDIRECT_URI;
const userPoolId = import.meta.env.VITE_COGNITO_USER_POOL_ID;

const region = userPoolId?.split('_')[0] ?? 'us-east-1';
const authority = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;

const userManager = new UserManager({
  authority,
  client_id: clientId,
  redirect_uri: redirectUri,
  response_type: 'code',
  scope: 'openid email profile',
  post_logout_redirect_uri: window.location.origin,
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  metadataUrl: `${authority}/.well-known/openid-configuration`,
  metadata: {
    issuer: authority,
    authorization_endpoint: `https://${cognitoDomain}/oauth2/authorize`,
    token_endpoint: `https://${cognitoDomain}/oauth2/token`,
    userinfo_endpoint: `https://${cognitoDomain}/oauth2/userInfo`,
    end_session_endpoint: `https://${cognitoDomain}/logout`,
  },
});

export async function login(): Promise<void> {
  await userManager.signinRedirect();
}

export async function handleCallback(): Promise<User> {
  return await userManager.signinRedirectCallback();
}

export async function getUser(): Promise<User | null> {
  return await userManager.getUser();
}

export async function getAccessToken(): Promise<string | null> {
  const user = await userManager.getUser();
  if (!user || user.expired) return null;
  return user.access_token ?? null;
}

export async function logout(): Promise<void> {
  await userManager.signoutRedirect({
    extraQueryParams: {
      client_id: clientId,
      logout_uri: window.location.origin,
    },
  });
}
