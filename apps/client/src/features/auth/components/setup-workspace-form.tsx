import * as React from "react";
import * as z from "zod";
import { useForm, zodResolver } from "@mantine/form";
import {
  Container,
  Title,
  TextInput,
  Button,
  Box,
  Anchor,
  Text,
} from "@mantine/core";
import classes from "@/features/auth/components/auth.module.css";
import { useTranslation } from "react-i18next";
import SsoCloudSignup from "@/ee/components/sso-cloud-signup";
import { isCloud } from "@/lib/config";
import { Link } from "react-router-dom";
import APP_ROUTE from "@/lib/app-route";
import { notifications } from "@mantine/notifications";
import { createWorkspace } from "@/features/workspace/services/workspace-service";

const formSchema = z.object({
  workspaceName: z
    .string()
    .trim()
    .min(2, { message: "Workspace name is required" })
    .max(50, { message: "Workspace name too long" }),
});

export interface ISetupWorkspace {
  workspaceName: string;
}

export function SetupWorkspaceForm() {
  const { t } = useTranslation();
  const [isLoading, setIsLoading] = React.useState(false);

  const form = useForm<ISetupWorkspace>({
    validate: zodResolver(formSchema),
    initialValues: {
      workspaceName: "",
    },
  });

  const onSubmit = async (data: ISetupWorkspace) => {
    setIsLoading(true);
    try {
      const res = await createWorkspace(data);
      notifications.show({
        message: `Workspace "${data.workspaceName}" created successfully!`,
        color: "green",
      });
      // Redirect to login or dashboard
      window.location.href = APP_ROUTE.AUTH.LOGIN;
    } catch (err: any) {
      console.error("Workspace creation failed:", err);
      notifications.show({
        message: err?.response?.data?.message || "Failed to create workspace",
        color: "red",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <Container size={420} className={classes.container}>
        <Box p="xl" className={classes.containerBox}>
          <Title order={2} ta="center" fw={500} mb="md">
            {t("Create workspace")}
          </Title>

          {isCloud() && <SsoCloudSignup />}

          <form onSubmit={form.onSubmit(onSubmit)}>
            <TextInput
              id="workspaceName"
              type="text"
              label={t("Workspace Name")}
              placeholder={t("e.g. ACME Inc")}
              variant="filled"
              mt="md"
              {...form.getInputProps("workspaceName")}
            />

            <Button type="submit" fullWidth mt="xl" loading={isLoading}>
              {t("Create workspace")}
            </Button>
          </form>
        </Box>
      </Container>

      {isCloud() && (
        <Text ta="center" mt="md">
          {t("Already part of an existing workspace?")}{" "}
          <Anchor component={Link} to={APP_ROUTE.AUTH.SELECT_WORKSPACE} fw={500}>
            {t("Sign-in")}
          </Anchor>
        </Text>
      )}
    </div>
  );
}
