import { useWorkspacePublicDataQuery } from "@/features/workspace/queries/workspace-query.ts";
import { MicrosoftWorkspacePopup } from "@/features/auth/components/MicrosoftWorkspacePopup";
import { Helmet } from "react-helmet-async";
import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { getAppName } from "@/lib/config.ts";
import { useTranslation } from "react-i18next";
import { AxiosError } from "axios";

export default function SetupWorkspace() {
  const { t } = useTranslation();
  const { data: workspace, isLoading, isError, error } = useWorkspacePublicDataQuery();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoading && !isError && workspace) {
      navigate("/");
    }
  }, [isLoading, isError, workspace, navigate]);

  if (isLoading) {
    return <div>Loading...</div>;
  }

  const axiosError = error as AxiosError<{ message?: string }>;

  if (isError) {
    if (
      axiosError?.response?.status === 404 &&
      axiosError?.response?.data?.message?.includes("Workspace not found")
    ) {
      return (
        <>
          <Helmet>
            <title>{t("Setup Workspace")} - {getAppName()}</title>
          </Helmet>
          <MicrosoftWorkspacePopup 
            opened={true} 
            onClose={() => navigate("/home")} 
            onSubmit={(data) => {
              console.log("Workspace created successfully", data);
              navigate("/"); // Redirect after success
            }}
            initialEmail="" 
            initialName="" 
          />
        </>
      );
    } else {
      return <div>Error loading workspace. Please try again.</div>;
    }
  }

  return null;
}
