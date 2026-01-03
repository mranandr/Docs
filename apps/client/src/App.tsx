import { Navigate, Route, Routes } from "react-router-dom";
import SetupWorkspace from "@/pages/auth/setup-workspace";
import Home from "@/pages/dashboard/home";
import Page from "@/pages/page/page";
import AccountSettings from "@/pages/settings/account/account-settings";
import WorkspaceMembers from "@/pages/settings/workspace/workspace-members";
import WorkspaceSettings from "@/pages/settings/workspace/workspace-settings";
import Groups from "@/pages/settings/group/groups";
import GroupInfo from "./pages/settings/group/group-info";
import Spaces from "@/pages/settings/space/spaces";
import { Error404 } from "@/components/ui/error-404";
import AccountPreferences from "@/pages/settings/account/account-preferences";
import SpaceHome from "@/pages/space/space-home";
import PageRedirect from "@/pages/page/page-redirect";
import Layout from "@/components/layouts/global/layout";
import { ErrorBoundary } from "react-error-boundary";
import Billing from "@/ee/billing/pages/billing";
import CloudLogin from "@/ee/pages/cloud-login";
import CreateWorkspace from "@/ee/pages/create-workspace";
import { isCloud } from "@/lib/config";
import { useTranslation } from "react-i18next";
import Security from "@/ee/security/pages/security";
import License from "@/ee/licence/pages/license";
import { useRedirectToCloudSelect } from "@/ee/hooks/use-redirect-to-cloud-select";
import SharedPage from "@/pages/share/shared-page";
import Shares from "@/pages/settings/shares/shares";
import ShareLayout from "@/features/share/components/share-layout";
import ShareRedirect from "@/pages/share/share-redirect";
import { useTrackOrigin } from "@/hooks/use-track-origin";
import SpacesPage from "@/pages/spaces/spaces";
import SpaceTrash from "@/pages/space/space-trash";
import UserApiKeys from "@/ee/api-key/pages/user-api-keys";
import WorkspaceApiKeys from "@/ee/api-key/pages/workspace-api-keys";
import AiSettings from "@/ee/ai/pages/ai-settings";
import { WorkspaceGuard } from "./pages/spaces/workspaceGuard";
import ProtectedRoute from "./lib/protectedRoute";

export default function App() {
  const { t } = useTranslation();
  useRedirectToCloudSelect();
  useTrackOrigin();

  return (
    <Routes>
      {/* Public routes */}
      <Route index element={<Navigate to="/home" replace />} />

      {/* Cloud-specific public routes */}
      {isCloud() && (
        <>
          <Route path="/create" element={<CreateWorkspace />} />
          <Route path="/select" element={<CloudLogin />} />
        </>
      )}

      {/* Public share routes - no authentication required */}
      <Route element={<ShareLayout />}>
        <Route path="/share/:shareId/p/:pageSlug" element={<SharedPage />} />
        <Route path="/share/p/:pageSlug" element={<SharedPage />} />
      </Route>
      <Route path="/share/:shareId" element={<ShareRedirect />} />
      <Route path="/p/:pageSlug" element={<PageRedirect />} />

      {/* Protected routes - require Keycloak authentication */}
      <Route element={<ProtectedRoute />}>
        {!isCloud() && (
          <Route path="/setup/workspace" element={<SetupWorkspace />} />
        )}

        <Route element={<WorkspaceGuard />}>
          <Route element={<Layout />}>
            <Route path="/home" element={<Home />} />
            <Route path="/spaces" element={<SpacesPage />} />
            <Route path="/s/:spaceSlug" element={<SpaceHome />} />
            <Route path="/s/:spaceSlug/trash" element={<SpaceTrash />} />

            <Route
              path="/s/:spaceSlug/p/:pageSlug"
              element={
                <ErrorBoundary fallback={<>{t("Failed to load page.")}</>}>
                  <Page />
                </ErrorBoundary>
              }
            />

            <Route path="/settings/account/profile" element={<AccountSettings />} />
            <Route path="/settings/account/preferences" element={<AccountPreferences />} />
            <Route path="/settings/account/api-keys" element={<UserApiKeys />} />
            <Route path="/settings/workspace" element={<WorkspaceSettings />} />
            <Route path="/settings/members" element={<WorkspaceMembers />} />
            <Route path="/settings/api-keys" element={<WorkspaceApiKeys />} />
            <Route path="/settings/groups" element={<Groups />} />
            <Route path="/settings/groups/:groupId" element={<GroupInfo />} />
            <Route path="/settings/spaces" element={<Spaces />} />
            <Route path="/settings/sharing" element={<Shares />} />
            <Route path="/settings/security" element={<Security />} />
            <Route path="/settings/ai" element={<AiSettings />} />

            {!isCloud() && <Route path="/settings/license" element={<License />} />}
            {isCloud() && <Route path="/settings/billing" element={<Billing />} />}
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<Error404 />} />
    </Routes>
  );
}