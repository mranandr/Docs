import api from "@/lib/api-client";

import {
  IChangePassword,
  ICollabToken,
  IForgotPassword,
  ILogin,
  IPasswordReset,
  ISetupWorkspace,
  IVerifyUserToken,
} from "@/features/auth/types/auth.types";

export async function login(data: ILogin): Promise<void> {
  await api.post<void>("/auth/login", data);
}

export async function logout(): Promise<void> {
  await api.post<void>("/auth/logout");
}

export async function changePassword(
  data: IChangePassword,
): Promise<IChangePassword> {
  const req = await api.post<IChangePassword>("/auth/change-password", data);
  return req.data;
}

export async function setupWorkspace(
  data: ISetupWorkspace,
): Promise<any> {
  const req = await api.post<any>("/auth/setup", data);
  return req.data;
}

export async function forgotPassword(data: IForgotPassword): Promise<void> {
  await api.post<void>("/auth/forgot-password", data);
}

export async function passwordReset(data: IPasswordReset): Promise<void> {
  await api.post<void>("/auth/password-reset", data);
}

export async function verifyUserToken(data: IVerifyUserToken): Promise<any> {
  return api.post<any>("/auth/verify-token", data);
}

export async function getCollabToken(): Promise<ICollabToken> {
  const req = await api.post<ICollabToken>("/auth/collab-token");
  return req.data;
}

export async function getUser(token: string, signal?: AbortSignal) {
  const response = await api.get("/auth/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal,
  });
  return response.data;
}

export async function getMicrosoftToken(code: string) {
  const response = await api.post("/auth/msauth/callback", { code });
  return response.data;
}

export async function getCurrentMicrosoftUser(token: string) {
  const response = await api.get("https://graph.microsoft.com/v1.0/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}