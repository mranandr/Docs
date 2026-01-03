import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { getAppName } from "@/lib/config";
import { useTranslation } from "react-i18next";
import AuthService from "@/features/auth/services/auth-service";
import { Loader } from "@mantine/core";

export default function LoginPage() {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleKeycloakLogin = async () => {
      try {
        const isAuthenticated = await AuthService.verify({ force: true });

        if (isAuthenticated) {
          console.log("[LoginPage] ✅ User already authenticated");
          window.location.href = "/home";
        } else {
          console.log("[LoginPage] ⚙️ Redirecting to Keycloak login");
          await AuthService.doLogin({ redirectUri: window.location.origin + "/home" });
        }
      } catch (error) {
        console.error("[LoginPage] ❌ Error during login:", error);
        await AuthService.doLogin({ redirectUri: window.location.origin + "/home" });
      } finally {
        setLoading(false);
      }
    };

    handleKeycloakLogin();
  }, []);

  return (
    <>
      <Helmet>
        <title>
          {t("Sign In")} - {getAppName()}
        </title>
      </Helmet>

      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        {loading ? (
          <div className="flex flex-col items-center space-y-4">
            <Loader color="blue" size="lg" />
            <p className="text-gray-600 text-lg font-medium">
              {t("Redirecting to secure login...")}
            </p>
          </div>
        ) : (
          <p className="text-gray-600 font-medium">
            {t("If not redirected, please refresh the page.")}
          </p>
        )}
      </div>
    </>
  );
}
