import { getUser, handleAuthCallback, login, logout, signup } from '@netlify/identity';

window.secureNetAuth = {
  login,
  logout,
  signup,
  ready: (async function () {
    try {
      await handleAuthCallback();
      return { user: await getUser(), error: false };
    } catch (error) {
      const status = document.getElementById('message') || document.getElementById('appStatus');
      if (status) status.textContent = 'The email confirmation link could not be verified. Please request a new confirmation email or sign in.';
      return { user: null, error: true };
    }
  })(),
};
