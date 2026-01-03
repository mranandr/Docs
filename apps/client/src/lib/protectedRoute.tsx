import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import AuthService from '@/features/auth/services/auth-service';
import { Loader } from '@mantine/core';

export default function ProtectedRoute() {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const location = useLocation();

  useEffect(() => {
    let isMounted = true;

    const checkAuth = async () => {
      try {
        if (!AuthService.isInitialized()) {
          setIsLoading(true);
          return;
        }

        if (AuthService.isLoggedIn()) {
          if (isMounted) {
            setIsAuthenticated(true);
            setIsLoading(false);
          }
          return;
        }

        const currentPath = location.pathname + location.search;
        const redirectUri = `${window.location.origin}${currentPath}`;
        AuthService.doLogin({ redirectUri });
      } catch (error) {
        console.error('Auth check error:', error);
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    checkAuth();

    return () => {
      isMounted = false;
    };
  }, [location.pathname, location.search]);

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        <Loader size="lg" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; 
  }

  return <Outlet />;
}