import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useState, useEffect, createContext, useContext } from "react";
import { useTranslation } from "react-i18next";
import axios from "axios";
import { ErrorBoundary } from "react-error-boundary";

import SetupWorkspace from "@/pages/auth/setup-workspace.tsx";
import LoginPage from "@/pages/auth/login";
import Home from "@/pages/dashboard/home";
import Page from "@/pages/page/page";
import AccountSettings from "@/pages/settings/account/account-settings";
import WorkspaceMembers from "@/pages/settings/workspace/workspace-members";
import WorkspaceSettings from "@/pages/settings/workspace/workspace-settings";
import Groups from "@/pages/settings/group/groups";
import GroupInfo from "@/pages/settings/group/group-info";
import Spaces from "@/pages/settings/space/spaces.tsx";
import { Error404 } from "@/components/ui/error-404.tsx";
import AccountPreferences from "@/pages/settings/account/account-preferences.tsx";
import SpaceHome from "@/pages/space/space-home.tsx";
import PageRedirect from "@/pages/page/page-redirect.tsx";
import Layout from "@/components/layouts/global/layout.tsx";
import InviteSignup from "@/pages/auth/invite-signup.tsx";
import ForgotPassword from "@/pages/auth/forgot-password.tsx";
import PasswordReset from "@/pages/auth/password-reset.tsx";
import { MicrosoftWorkspacePopup } from "@/features/auth/components/MicrosoftWorkspacePopup";
import { FaSpinner as Spinner } from "react-icons/fa";
// Create an AuthContext
const AuthContext = createContext({
  isAuthenticated: false,
  setIsAuthenticated: (value: boolean) => {},
  logout: () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

function MicrosoftWorkspaceRoute() {
  const navigate = useNavigate();

  const handleClose = () => {
    navigate("/home"); // Navigate to the home page when the modal closes
  };

  const handleSubmit = () => {
    console.log("Workspace created!");
    navigate("/home"); // Navigate to the home page after submission
  };

  return (
    <MicrosoftWorkspacePopup
      opened={true}
      onClose={handleClose}
      onSubmit={handleSubmit}
      initialEmail="user@example.com"
      initialName="John Doe"
    />
  );
}

export default function App() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Check authentication status on app load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await axios.get("/api/auth/check");
        setIsAuthenticated(response.data.isAuthenticated);
      } catch (error) {
        console.error("Error checking authentication:", error);
        setIsAuthenticated(false);
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, []);

  // Logout function
  const logout = async () => {
    try {
      await axios.post("/api/auth/logout");
      setIsAuthenticated(false);
      navigate("/login");
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  if (isLoading) {
    return <Spinner />; // Show a spinner while loading
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, setIsAuthenticated, logout }}>
      <Routes>
        <Route index element={<Navigate to="/home" />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/invites/:invitationId" element={<InviteSignup />} />
        <Route path="/setup/register" element={<SetupWorkspace />} />
        <Route path="/setup/microsoft-workspace" element={<MicrosoftWorkspaceRoute />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/password-reset" element={<PasswordReset />} />
        <Route path="/p/:pageSlug" element={<PageRedirect />} />

        <Route
          element={
            isAuthenticated ? (
              <Layout />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        >
          <Route path="/home" element={<Home />} />
          <Route path="/s/:spaceSlug" element={<SpaceHome />} />
          <Route
            path="/s/:spaceSlug/p/:pageSlug"
            element={
              <ErrorBoundary fallback={<>{t("Failed to load page. An error occurred.")}</>}>
                <Page />
              </ErrorBoundary>
            }
          />
          <Route path="/settings">
            <Route path="account/profile" element={<AccountSettings />} />
            <Route path="account/preferences" element={<AccountPreferences />} />
            <Route path="workspace" element={<WorkspaceSettings />} />
            <Route path="members" element={<WorkspaceMembers />} />
            <Route path="groups" element={<Groups />} />
            <Route path="groups/:groupId" element={<GroupInfo />} />
            <Route path="spaces" element={<Spaces />} />
          </Route>
        </Route>

        <Route path="*" element={<Error404 />} />
      </Routes>
    </AuthContext.Provider>
  );
}