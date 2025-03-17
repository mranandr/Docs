import { useState, useEffect } from 'react';

export function useMicrosoftLogin() {
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [userDetails, setUserDetails] = useState({ email: '', name: '' });

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;

      const { email, name } = event.data;
      if (email && name) {
        // Set user details and open the popup
        setUserDetails({ email, name });
        setIsPopupOpen(true);
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const handleWorkspaceSubmit = async (data) => {
    try {
      // Submit workspace details to the backend
      const response = await fetch('/api/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (response.ok) {
        const { token } = await response.json();
        localStorage.setItem('token', token); // Store the token
        window.location.href = '/home'; // Redirect to the home page
      } else {
        console.error('Failed to setup workspace');
      }
    } catch (error) {
      console.error('Error during workspace setup:', error);
    }
  };

  return {
    isPopupOpen,
    userDetails,
    setIsPopupOpen,
    handleWorkspaceSubmit,
  };
}