import { useQuery } from "@tanstack/react-query";
import AuthService from "../services/auth-service";

export function useCurrentUser() {
  return useQuery({
    queryKey: ["current-user"],
    queryFn: async () => {
      // Ensure we're authenticated first
      const authenticated = await AuthService.verify();
      
      if (!authenticated) {
        throw new Error("Not authenticated");
      }

      const user = AuthService.getUser();
      
      if (!user) {
        throw new Error("User data not available");
      }

      return { user };
    },
    enabled: AuthService.isLoggedIn(), 
    staleTime: 5 * 60 * 1000, 
    retry: false, 
  });
}