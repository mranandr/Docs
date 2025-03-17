import { useState, useEffect } from 'react';
import { checkJWT, getCurrentUser, logout, authenticateUserWithJWT, loginWithAzure } from '../features/editor/utils/authUtils';

export const useAuth = () => {
  const [user, setUser] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);

  // Check JWT and set user if valid
  useEffect(() => {
    const token = localStorage.getItem('jwtToken');
    if (token != null && checkJWT(token)) {
      setIsAuthenticated(true);
      setUser(getCurrentUser(token)); // Set the user info from the token
    }
  }, []);

  // Sign in with JWT
  const signInWithJWT = async (email: string, password: string) => {
    try {
      const token = await authenticateUserWithJWT(email, password);
      localStorage.setItem('jwtToken', token); // Store token in localStorage
      setIsAuthenticated(true);
      setUser(getCurrentUser(token)); // Decode and set user info
    } catch (error) {
      console.error('Error during JWT sign-in:', error);
    }
  };

  const signInWithMicrosoft = async () => {
    try {
      await loginWithAzure(); // Assuming this function doesn't return a token
      const token = localStorage.getItem('jwtToken');
      if (token) {
        setIsAuthenticated(true);
        setUser(getCurrentUser(token)); // Get user info from token
      }
    } catch (error) {
      console.error('Error during Microsoft sign-in:', error);
    }
  };
  

  // Sign out user
  const signOut = () => {
    localStorage.removeItem('jwtToken');
    setUser(null);
    setIsAuthenticated(false);
    logout(); // Optionally call logout API
  };

  return {
    user,
    isAuthenticated,
    signInWithJWT,
    signInWithMicrosoft,
    signOut,
  };
};

export default useAuth;
