// import * as z from "zod";
// import { useForm, zodResolver } from "@mantine/form";
// import {
//   Container,
//   Title,
//   TextInput,
//   Button,
//   PasswordInput,
//   Box,
// } from "@mantine/core";
// import { ISetupWorkspace } from "@/features/auth/types/auth.types";
// import useAuth from "@/features/auth/hooks/use-auth";
// import classes from "@/features/auth/components/auth.module.css";
// import { useTranslation } from "react-i18next";
// import { useNavigate } from "react-router-dom";

// // Define the form schema with custom error messages
// const formSchema = z.object({
//   workspaceName: z
//     .string()
//     .trim()
//     .min(3, { message: "Workspace name must be at least 3 characters" })
//     .max(50, { message: "Workspace name cannot exceed 50 characters" }),
//   name: z
//     .string()
//     .min(1, { message: "Name is required" })
//     .max(50, { message: "Name cannot exceed 50 characters" }),
//   email: z
//     .string()
//     .min(1, { message: "Email is required" })
//     .email({ message: "Invalid email address" }),
//   password: z
//     .string()
//     .min(8, { message: "Password must be at least 8 characters" }),
// });

// // Define props for initial values
// interface SetupWorkspaceFormProps {
//   initialEmail?: string;
//   initialName?: string;
// }

// export function SetupWorkspaceForm({
//   initialEmail = "",
//   initialName = "",
// }: SetupWorkspaceFormProps) {
//   const { t } = useTranslation();
//   const { setupWorkspace, isLoading } = useAuth();
//   const navigate = useNavigate();

//   // Initialize form with default values
//   const form = useForm<ISetupWorkspace>({
//     validate: zodResolver(formSchema),
//     initialValues: {
//       workspaceName: "",
//       name: initialName,
//       email: initialEmail,
//       password: "",
//     },
//   });

//   // Handle form submission
//   async function onSubmit(data: ISetupWorkspace) {
//     try {
//       await setupWorkspace(data);
//       navigate("/home"); // Redirect to /home after successful setup
//     } catch (error) {
//       console.error("Error setting up workspace:", error);
//       // Display error to the user (e.g., using Mantine's Notification)
//       form.setErrors({ email: "An error occurred. Please try again." });
//     }
//   }

//   return (
//     <Container size={420} my={40} className={classes.container}>
//       <Box p="xl" mt={200}>
//         <Title order={2} ta="center" fw={500} mb="md">
//           {t("Create workspace")}
//         </Title>

//         <form onSubmit={form.onSubmit(onSubmit)}>
//           <TextInput
//             id="workspaceName"
//             type="text"
//             label={t("Workspace Name")}
//             placeholder={t("e.g ACME Inc")}
//             variant="filled"
//             mt="md"
//             {...form.getInputProps("workspaceName")}
//             error={form.errors.workspaceName}
//           />

//           <TextInput
//             id="name"
//             type="text"
//             label={t("Your Name")}
//             placeholder={t("enter your full name")}
//             variant="filled"
//             mt="md"
//             {...form.getInputProps("name")}
//             error={form.errors.name}
//           />

//           <TextInput
//             id="email"
//             type="email"
//             label={t("Your Email")}
//             placeholder="email@example.com"
//             variant="filled"
//             mt="md"
//             {...form.getInputProps("email")}
//             error={form.errors.email}
//           />

//           <PasswordInput
//             label={t("Password")}
//             placeholder={t("Enter a strong password")}
//             variant="filled"
//             mt="md"
//             {...form.getInputProps("password")}
//             error={form.errors.password}
//           />

//           <Button type="submit" fullWidth mt="xl" loading={isLoading}>
//             {t("Setup workspace")}
//           </Button>
//         </form>
//       </Box>
//     </Container>
//   );
// }