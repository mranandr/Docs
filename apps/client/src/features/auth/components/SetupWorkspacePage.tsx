import { useState } from "react";
import { useLocation } from "react-router-dom";
import { MicrosoftWorkspacePopup } from "./MicrosoftWorkspacePopup";
import axios from "axios";

export default function SetupWorkspacePage() {
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const email = queryParams.get("email") || "";
  const name = queryParams.get("name") || "";
  
  const [modalOpen, setModalOpen] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");

  const handleWorkspaceSubmit = async (values) => {
    try {
      await axios.post("/api/workspace/setup-microsoft-workspace", {
        ...values,
        email, // Include email and name
        name,
      });
      window.location.href = "/home";
    } catch (error) {
      setErrorMessage("Failed to create workspace. Please try again.");
      console.error("Workspace setup failed:", error);
    }
  };

  return (
    <div>
      <h1>Setup Workspace</h1>
      {errorMessage && <p style={{ color: "red" }}>{errorMessage}</p>}
      <MicrosoftWorkspacePopup 
        initialEmail={email} 
        initialName={name} 
        onSubmit={handleWorkspaceSubmit}
        onClose={() => setModalOpen(false)} 
        opened={modalOpen}
      />
    </div>
  );
}

