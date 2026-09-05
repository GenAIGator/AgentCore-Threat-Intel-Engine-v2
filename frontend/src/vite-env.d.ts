/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Cognito Hosted UI domain, e.g. "my-app.auth.us-east-1.amazoncognito.com" */
  readonly VITE_COGNITO_DOMAIN: string;
  /** Cognito app client ID */
  readonly VITE_COGNITO_CLIENT_ID: string;
  /** OAuth redirect URI registered on the Cognito app client, e.g. "https://app.example.com/callback" */
  readonly VITE_COGNITO_REDIRECT_URI: string;
  /** Cognito user pool ID, e.g. "us-east-1_abc123" (region is derived from the prefix) */
  readonly VITE_COGNITO_USER_POOL_ID: string;
  /** AgentCore Runtime /invocations endpoint URL */
  readonly VITE_AGENTCORE_ENDPOINT: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
