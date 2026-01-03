import { Outlet, useNavigate } from "react-router-dom";
import { useWorkspacePublicDataQuery } from "@/features/workspace/queries/workspace-query";
import { useEffect } from "react";

export function WorkspaceGuard() {
  const { data, isLoading, isError, error } = useWorkspacePublicDataQuery();
  const navigate = useNavigate();

  useEffect(() => {
    if (isLoading) return;

    console.log("🏢 WorkspaceGuard: isLoading =", isLoading);
    console.log("🏢 WorkspaceGuard: isError =", isError);
    console.log("🏢 WorkspaceGuard: data =", data);

    if (isError && error) {
      const msg = error.message?.toLowerCase() || "";
      console.log("🏢 WorkspaceGuard: error message =", msg);

      const workspaceNotFound =
        msg.includes("404") ||
        msg.includes("not found") ||
        msg.includes("workspace not found");

      if (workspaceNotFound) {
        console.log("⚠️ WorkspaceGuard: Workspace not found, redirecting to setup");
        navigate("/setup/workspace", { replace: true });
        return;
      }
    }

    if (!isError && data) {
      console.log("✅ WorkspaceGuard: Workspace found, rendering children");
    }
  }, [isLoading, isError, error, data, navigate]);

  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        fontSize: '1.2rem',
        color: '#666'
      }}>
        Loading workspace...
      </div>
    );
  }

  if (isError && error) {
    const msg = error.message?.toLowerCase() || "";
    const workspaceNotFound =
      msg.includes("404") ||
      msg.includes("not found") ||
      msg.includes("workspace not found");
    
    if (!workspaceNotFound) {
      return (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          fontSize: '1.2rem',
          color: '#d32f2f'
        }}>
          Error loading workspace: {error.message}
        </div>
      );
    }
  }

  return <Outlet />;
}