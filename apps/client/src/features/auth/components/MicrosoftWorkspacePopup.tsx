import { useState, useEffect } from "react";
import { useForm } from "@mantine/form";
import { Modal, TextInput, Button, Alert } from "@mantine/core";

export function MicrosoftWorkspacePopup({ opened, onClose, onSubmit, initialEmail, initialName }) {
  const [isSubmitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null); // State to handle submission errors

  const form = useForm({
    initialValues: {
      organizationName: "",
      workspaceName: "",
      email: initialEmail || "user@example.com", // Default value if initialEmail is not provided
      name: initialName || "John Doe", // Default value if initialName is not provided
      auth_type: "sso", // Default value for auth_type
      sso_provider: "microsoft", // Default value for sso_provider
      sso_id: initialEmail || "user@example.com", // Use email as the SSO ID
    },
    validate: {
      organizationName: (value) => (value.trim().length > 2 ? null : "Organization name must be at least 3 characters"),
      workspaceName: (value) => (value.trim().length > 2 ? null : "Workspace name must be at least 3 characters"),
      email: (value) => (/^\S+@\S+\.\S+$/.test(value) ? null : "Invalid email"),
      name: (value) => (value.length >= 2 ? null : "Name must be at least 2 characters long"),
    },
  });

  // Update email and name when modal opens
  useEffect(() => {
    if (opened) {
      form.setValues({
        organizationName: "",
        workspaceName: "",
        email: initialEmail || "user@example.com", // Default value if initialEmail is not provided
        name: initialName || "John Doe", // Default value if initialName is not provided
        auth_type: "sso", // Reset auth_type
        sso_provider: "microsoft", // Reset sso_provider
        sso_id: initialEmail || "user@example.com", // Reset sso_id
      });
      setError(null); // Reset error state when modal opens
    }
  }, [opened, initialEmail, initialName]);

  const handleSubmit = async (values) => {
    setSubmitting(true);
    setError(null); 

    try {
      console.log("Submitting:", values);
      const response = await fetch("http://localhost:3000/api/auth/setup-register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error("Error response:", errorData);
        setError(errorData.message || "Failed to create workspace. Please try again."); 
        throw new Error(`Failed to create workspace. Status: ${response.status}`);
      }

      console.log("Workspace created successfully");
      if (onSubmit) onSubmit(); 
      onClose();
    } catch (error) {
      console.error("Error creating workspace:", error);
      setError("An unexpected error occurred. Please try again."); 
    } finally {
      setSubmitting(false);
    }
  };

  

  return (
    <Modal opened={opened} onClose={onClose} title="Setup Your Organization and Workspace">
      <form onSubmit={form.onSubmit(handleSubmit)}>
        {/* Display error message if any */}
        {error && (
          <Alert color="red" mb="md">
            {error}
          </Alert>
        )}

        <TextInput
          label="Organization"
          placeholder="Your organization name"
          {...form.getInputProps("organizationName")}
        />
        <TextInput
          label="Workspace"
          placeholder="Your workspace name"
          {...form.getInputProps("workspaceName")}
        />
        <TextInput
          label="Email"
          {...form.getInputProps("email")}
          disabled
        />
        <TextInput
          label="Name"
          {...form.getInputProps("name")}
          disabled
        />
        <Button type="submit" fullWidth mt="xl" loading={isSubmitting}>
          {isSubmitting ? "Creating..." : "Create Workspace"}
        </Button>
      </form>
    </Modal>
  );
}