import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getMicrosoftToken, getCurrentMicrosoftUser } from '@/features/auth/services/auth-service';
import { Loader, LoadingOverlayCssVariables } from '@mantine/core';

export function MicrosoftCallback() {
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      console.error('No authorization code found');
      return;
    }

    const fetchUserDetails = async () => {
      try {
        const tokenResponse = await getMicrosoftToken(code);
        const accessToken = tokenResponse.access_token;

        const userDetails = await getCurrentMicrosoftUser(accessToken);
        const { mail: email, displayName: name } = userDetails;

        window.opener.postMessage({ code, email, name }, window.location.origin);
        window.close(); 
      } catch (error) {
        console.error('Error during Microsoft login:', error);
        window.close();
      }
    };

    fetchUserDetails();
  }, [searchParams]);

  return Loader;
}