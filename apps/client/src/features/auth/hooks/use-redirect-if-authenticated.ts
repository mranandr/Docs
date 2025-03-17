import { useEffect } from "react";
import APP_ROUTE from "@/lib/app-route.ts";
import { useNavigate } from "react-router-dom";

export function useRedirectIfAuthenticated() {
  const navigate = useNavigate();

  useEffect(() => {
    const user = localStorage.getItem("user");
    if (user) navigate(APP_ROUTE.HOME);
  }, [navigate]);
}
