/**
 * Root app component. Handles Cognito auth state and renders Chat or Login.
 *
 * Themed for the Threat Intelligence Engine. Auth-state logic
 * (login / callback / getUser / logout) is domain-agnostic.
 */

import { useState, useEffect } from 'react';
import { login, logout, getUser, handleCallback } from './auth';
import Chat from './Chat';

const APP_TITLE = 'Threat Intelligence Engine';
const APP_SUBTITLE = 'Research threat actors and design purple-team exercises — powered by AI';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [userName, setUserName] = useState('');

  useEffect(() => {
    async function init() {
      // Handle OAuth callback
      if (window.location.pathname === '/callback') {
        try {
          const user = await handleCallback();
          setIsAuthenticated(true);
          setUserName(user.profile.email ?? 'User');
          window.history.replaceState({}, '', '/');
        } catch (err) {
          console.error('Callback error:', err);
        }
        setIsLoading(false);
        return;
      }

      // Check existing session
      const user = await getUser();
      if (user && !user.expired) {
        setIsAuthenticated(true);
        setUserName(user.profile.email ?? 'User');
      }
      setIsLoading(false);
    }
    init();
  }, []);

  if (isLoading) {
    return <div style={styles.loading}>Loading...</div>;
  }

  if (!isAuthenticated) {
    return (
      <div style={styles.loginContainer}>
        <h1 style={styles.title}>{APP_TITLE}</h1>
        <p style={styles.subtitle}>{APP_SUBTITLE}</p>
        <button onClick={login} style={styles.loginButton}>
          Log in
        </button>
      </div>
    );
  }

  return (
    <div style={styles.appContainer}>
      <header style={styles.header}>
        <span style={styles.headerTitle}>{APP_TITLE}</span>
        <span style={styles.headerUser}>
          {userName}
          <button onClick={logout} style={styles.logoutButton}>Logout</button>
        </span>
      </header>
      <Chat />
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  loading: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh',
    fontSize: '1.2rem',
    color: '#666',
  },
  appContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    overflow: 'hidden',
  },
  loginContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  title: {
    fontSize: '2rem',
    margin: '0 0 0.5rem',
  },
  subtitle: {
    color: '#666',
    margin: '0 0 2rem',
  },
  loginButton: {
    padding: '0.75rem 2rem',
    fontSize: '1rem',
    background: '#1976d2',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.75rem 1rem',
    borderBottom: '1px solid #eee',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  headerTitle: {
    fontWeight: 600,
    fontSize: '1.1rem',
  },
  headerUser: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    fontSize: '0.9rem',
    color: '#666',
  },
  logoutButton: {
    padding: '0.4rem 0.75rem',
    fontSize: '0.85rem',
    background: '#f5f5f5',
    border: '1px solid #ddd',
    borderRadius: '4px',
    cursor: 'pointer',
  },
};
