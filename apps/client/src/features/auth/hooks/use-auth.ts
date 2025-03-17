import { useState } from "react";
import {
  forgotPassword,
  login,
  logout,
  passwordReset,
  setupWorkspace,
  verifyUserToken,
} from "@/features/auth/services/auth-service";
import { useNavigate } from "react-router-dom";
import { useAtom } from "jotai";
import { currentUserAtom } from "@/features/user/atoms/current-user-atom";
import {
  IForgotPassword,
  ILogin,
  IPasswordReset,
  ISetupWorkspace,
  IVerifyUserToken,
} from "@/features/auth/types/auth.types";
import { getMicrosoftToken } from "@/features/auth/services/auth-service";
import { getCurrentMicrosoftUser } from "../services/auth-service"
import { notifications } from "@mantine/notifications";
import { IAcceptInvite } from "@/features/workspace/types/workspace.types.ts";
import { acceptInvitation } from "@/features/workspace/services/workspace-service.ts";
import APP_ROUTE from "@/lib/app-route.ts";
import { RESET } from "jotai/utils";
import { useTranslation } from "react-i18next";
import { useEffect } from "react";
import * as authService from "@/features/auth/services/auth-service";
import { authTokensAtom } from "../atoms/auth-tokens-atom";



export default function useAuth() {
  const { t } = useTranslation();
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const [, setCurrentUser] = useAtom(currentUserAtom);

  const [token] = useAtom(authTokensAtom);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    const fetchUser = async () => {
      if (!token) return;
      try {
        const userData = await authService.getUser(token, controller.signal);
        setUser(userData);
      } catch (error) {
        if (error.name !== "AbortError") {
          console.error("Error fetching user data:", error);
        }
      }
    };
    fetchUser();
    return () => controller.abort(); 
  }, [token]);
  
  
  const handleSignIn = async (data: ILogin) => {
    setIsLoading(true);

    try {
      await login(data);
      setIsLoading(false);
      navigate(APP_ROUTE.HOME);
    } catch (err) {
      setIsLoading(false);
      console.log(err);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleInvitationSignUp = async (data: IAcceptInvite) => {
    setIsLoading(true);

    try {
      await acceptInvitation(data);
      setIsLoading(false);
      navigate(APP_ROUTE.HOME);
    } catch (err) {
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleSetupWorkspace = async (data: ISetupWorkspace) => {
    setIsLoading(true);

    try {
      const res = await setupWorkspace(data);
      setIsLoading(false);
      navigate(APP_ROUTE.HOME);
    } catch (err) {
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handlePasswordReset = async (data: IPasswordReset) => {
    setIsLoading(true);

    try {
      await passwordReset(data);
      setIsLoading(false);
      navigate(APP_ROUTE.HOME);
      notifications.show({
        message: t("Password reset was successful"),
      });
    } catch (err) {
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleLogout = async () => {
    setCurrentUser(RESET);
    await logout();
    window.location.replace(APP_ROUTE.AUTH.LOGIN);
  };

  const handleForgotPassword = async (data: IForgotPassword) => {
    setIsLoading(true);

    try {
      await forgotPassword(data);
      setIsLoading(false);

      return true;
    } catch (err) {
      console.log(err);
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });

      return false;
    }
  };


  const handleVerifyUserToken = async (data: IVerifyUserToken) => {
    setIsLoading(true);

    try {
      await verifyUserToken(data);
      setIsLoading(false);
    } catch (err) {
      console.log(err);
      setIsLoading(false);
      notifications.show({
        message: err.response?.data.message,
        color: "red",
      });
    }
  };

  const handleSignInWithMicrosoft = async (code: string) => {
    setIsLoading(true);
    try {
      const data = await getMicrosoftToken(code);
      const user = await getCurrentMicrosoftUser(data.access_token);
      setCurrentUser(user);
      navigate(APP_ROUTE.HOME);
    } catch (err) {
      console.log(err);
      notifications.show({ message: "Microsoft login failed", color: "red" });
    } finally {
      setIsLoading(false);
    }
  };
  
  return {
    signIn: handleSignIn,
    invitationSignup: handleInvitationSignUp,
    setupWorkspace: handleSetupWorkspace,
    forgotPassword: handleForgotPassword,
    passwordReset: handlePasswordReset,
    verifyUserToken: handleVerifyUserToken,
    logout: handleLogout,
    signInWithMicrosoft: handleSignInWithMicrosoft,
    isLoading,
  };


 
}
