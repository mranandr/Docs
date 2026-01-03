import { useEffect } from "react";
import AuthService from "@/features/auth/services/auth-service";

export default function LoginPage() {
  useEffect(() => {
    AuthService.doLogin({
      redirectUri: window.location.href + "/setup/workspace",
    });
  }, []);

  return null; 
}
