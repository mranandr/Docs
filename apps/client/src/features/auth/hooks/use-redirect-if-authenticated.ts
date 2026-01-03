import { useEffect } from "react";
import useCurrentUser from "@/features/user/hooks/use-current-user.ts";
import APP_ROUTE from "@/lib/app-route.ts";
import { useNavigate, useLocation } from "react-router-dom";

export function useRedirectIfAuthenticated() {
  const { data, isLoading } = useCurrentUser();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!isLoading && data?.user && location.pathname !== APP_ROUTE.HOME) {
      console.log('Redirecting authenticated user to home'); 
      navigate(APP_ROUTE.HOME, { replace: true });
    }
  }, [isLoading, data, navigate, location.pathname]);
}