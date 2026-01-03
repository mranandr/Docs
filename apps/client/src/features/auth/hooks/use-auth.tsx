import { useEffect, useState } from "react";
import AuthService from "../services/auth-service";
import { jwtDecode } from "jwt-decode";

interface DecodedToken {
  role: string;
  email: string;
  exp: number;
}

export function useAuth() {
  const [user, setUser] = useState<DecodedToken | null>(null);

  useEffect(() => {
    const currentUsers=AuthService.getToken()

    const token = currentUsers; 
    
    if (token) {
      try {
        const decoded: DecodedToken = jwtDecode(token);
        console.log(decoded,"userdecoded");
        
        setUser(decoded);
      } catch (e) {
        console.error("Invalid token", e);
        setUser(null);
      }
    }
  }, []);

  return { user };
}