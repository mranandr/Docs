import React, { useEffect } from "react";
import { Helmet } from "react-helmet-async";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";

import { useWorkspacePublicDataQuery } from "@/features/workspace/queries/workspace-query";
import { SetupWorkspaceForm } from "@/features/auth/components/setup-workspace-form";
import APP_ROUTE from "@/lib/app-route";
import { getAppName } from "@/lib/config";

export default function SetupWorkspace() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  const {
    data: workspace,
    isLoading,
    isError,
    error,
  } = useWorkspacePublicDataQuery();

  useEffect(() => {
    if (!isLoading && workspace) {
      console.log("✅ SetupWorkspace: Workspace found, redirecting to home");
      navigate(APP_ROUTE.HOME, { replace: true });
    }
  }, [isLoading, workspace, navigate]);

  const workspaceNotFound = isError && (() => {
    const statusCode = (error as any)?.response?.status;
    const errorMsg = (error as any)?.response?.data?.message?.toLowerCase() || "";
    
    return (
      statusCode === 404 ||
      errorMsg.includes("workspace not found") ||
      errorMsg.includes("not found")
    );
  })();

  // Loading state
  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        color: '#666'
      }}>
        <div>
          <div style={{
            width: '48px',
            height: '48px',
            border: '4px solid #e0e0e0',
            borderTop: '4px solid #4c8bf5',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem'
          }} />
          <div>{t("Checking workspace...")}</div>
        </div>
      </div>
    );
  }

  // Show setup form only if workspace truly doesn't exist
  if (workspaceNotFound) {
    return (
      <>
        <Helmet>
          <title>
            {t("Setup Workspace")} — {getAppName()}
          </title>
        </Helmet>
        <SetupWorkspaceForm />
      </>
    );
  }

  if (isError) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        padding: '2rem',
        textAlign: 'center'
      }}>
        <h2 style={{ color: '#d32f2f', marginBottom: '1rem' }}>
          {t("Error Loading Workspace")}
        </h2>
        <p style={{ color: '#666', marginBottom: '2rem' }}>
          {(error as any)?.message || t("An unexpected error occurred")}
        </p>
        <button
          onClick={() => window.location.reload()}
          style={{
            padding: '0.75rem 1.5rem',
            background: '#4c8bf5',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '1rem'
          }}
        >
          {t("Reload")}
        </button>
      </div>
    );
  }
  return null;
}