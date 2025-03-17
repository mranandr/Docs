import * as z from "zod";
import { useForm, zodResolver } from "@mantine/form";
import useAuth from "@/features/auth/hooks/use-auth";
import { ILogin } from "@/features/auth/types/auth.types";
import {
  Container,
  Title,
  TextInput,
  Button,
  PasswordInput,
  Box,
  Anchor,
} from "@mantine/core";
import { FaMicrosoft } from "react-icons/fa"; 
import classes from "./auth.module.css";
import { useRedirectIfAuthenticated } from "@/features/auth/hooks/use-redirect-if-authenticated";
import { Link } from "react-router-dom";
import APP_ROUTE from "@/lib/app-route";
import { useTranslation } from "react-i18next";
import getConfig from "@/lib/config"; 

const formSchema = z.object({
  email: z
    .string()
    .min(1, { message: "Email is required" })
    .email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
});

export function LoginForm() {
  const { t } = useTranslation();
  const { signIn, isLoading } = useAuth();
  useRedirectIfAuthenticated();

  const form = useForm<ILogin>({
    validate: zodResolver(formSchema),
    initialValues: {
      email: "",
      password: "",
    },
  });

  const onSubmit = async (data: ILogin) => {
    try {
      await signIn(data);
    } catch (error) {
      console.error("Error during sign-in:", error);
    }
  };

  const handleMicrosoftLogin = () => {
    const { azureTenantId, azureClientId, redirectUri } = getConfig();
    const scope = 'openid email profile User.Read';

    if (!azureTenantId || !azureClientId || !redirectUri) {
      console.error("Environment variables are not set correctly");
      return;
    }

    const authUrl = `https://login.microsoftonline.com/${azureTenantId}/oauth2/v2.0/authorize?client_id=${azureClientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&response_mode=query&scope=${encodeURIComponent(scope)}`;

    window.location.href = authUrl;
    console.log('Redirecting to Microsoft Auth URL:', authUrl);
  };

  return (
    <Container size={420} my={40} className={classes.container}>
      <Box p="xl" mt={200}>
        <Title order={2} ta="center" fw={500} mb="md">
          {t("Login")}
        </Title>

        <form onSubmit={form.onSubmit(onSubmit)}>
          <TextInput
            id="email"
            type="email"
            label={t("Email")}
            placeholder="email@example.com"
            variant="filled"
            {...form.getInputProps("email")}
          />

          <PasswordInput
            label={t("Password")}
            placeholder={t("Your password")}
            variant="filled"
            mt="md"
            {...form.getInputProps("password")}
          />    

          <Button type="submit" fullWidth mt="xl" loading={isLoading}>
            {t("Sign In")}
          </Button>

          <Button
            leftSection={<FaMicrosoft size={20} />}
            variant="outline"
            fullWidth
            mt="md"
            onClick={handleMicrosoftLogin}
          >
            {t("Sign in with Microsoft")}
          </Button>
        </form>

        <Anchor
          to={APP_ROUTE.AUTH.FORGOT_PASSWORD}
          component={Link}
          underline="never"
          size="sm"
        >
          {t("Forgot your password?")}
        </Anchor>
      </Box>
    </Container>
  );
}