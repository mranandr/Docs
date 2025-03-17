import React, { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';

function SetupWorkspacePage() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryParams = new URLSearchParams(location.search);
  const email = queryParams.get('email');
  const name = queryParams.get('name');

  useEffect(() => {
    if (email && name) {
      // Submit the setup form automatically
      const setupWorkspace = async () => {
        try {
          const response = await axios.post('/api/auth/setup-workspace', {
            email,
            name,
            organizationName: 'My Organization', 
            workspaceName: 'My Workspace', 
          });

          navigate(`/dashboard?token=${response.data.token}`);
        } catch (error) {
          console.error('Error setting up workspace:', error);
        }
      };

      setupWorkspace();
    }
  }, [email, name, navigate]);

  return (
    <div>
      <h1>Setting up your workspace...</h1>
    </div>
  );
}

export default SetupWorkspacePage;