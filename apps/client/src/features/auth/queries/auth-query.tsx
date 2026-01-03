import { useQuery, UseQueryResult } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import AuthService from "../services/auth-service";
import { ICollabToken, IVerifyUserToken } from "../types/auth.types";

export function useVerifyUserTokenQuery(
  verify: IVerifyUserToken
): UseQueryResult<boolean, Error> {
  return useQuery({
    queryKey: ["verify-token", verify.token],
    queryFn: async () => {
      const isAuthenticated = await AuthService.verify({ force: true });
      if (!isAuthenticated) {
        await AuthService.doLogin({ redirectUri: window.location.origin });
      }
      return isAuthenticated;
    },
    enabled: !!verify.token, 
    staleTime: 0, 
    retry: (failureCount, error) => {
      if (isAxiosError(error) && error.response?.status === 401) return false;
      if (failureCount > 3) return false;
      return true;
    },
    retryDelay: (attempt) => 5000 * Math.pow(2, attempt - 1), 
  });
}


export function useCollabToken(): UseQueryResult<ICollabToken, Error> {
  return useQuery({
    queryKey: ["collab-token"],
    queryFn: async () => {
      const token = AuthService.getToken();

      if (!token) {
        const authenticated = await AuthService.verify({ force: true });
        if (!authenticated) {
          await AuthService.doLogin({ redirectUri: window.location.origin });
          throw new Error("User not authenticated");
        }
      }

      return { token } as ICollabToken;
    },
    staleTime: 20 * 60 * 60 * 1000, 
    refetchOnMount: true,
    retry: (failureCount, error) => {
      if (isAxiosError(error) && error.response?.status === 404) return false;
      if (failureCount > 5) return false;
      return true;
    },
    retryDelay: (attempt) => 5000 * Math.pow(2, attempt - 1),
  });
}
