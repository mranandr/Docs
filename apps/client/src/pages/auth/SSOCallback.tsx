import { useEffect } from "react";
import { useHistory } from "react-router-dom";
import APP_ROUTE from "@/lib/app-route.ts";

const SSOCallback = () => {
  const history = useHistory();

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get("token");

    if (token) {
      localStorage.setItem("authToken", token);
      history.push(APP_ROUTE.HOME);
    } else {
      // Handle error or redirect to login
      history.push(APP_ROUTE.AUTH.LOGIN);
    }
  }, [history]);

  return <div>Loading...</div>;
};

export default SSOCallback;