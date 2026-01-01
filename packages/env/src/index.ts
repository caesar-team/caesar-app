import { z } from "zod";

/**
 * Server-side environment variables schema.
 * These are only available on the server and never exposed to the client.
 */
const serverSchema = z.object({
  // Database
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),

  // Better Auth
  BETTER_AUTH_SECRET: z
    .string()
    .min(32, "BETTER_AUTH_SECRET must be at least 32 characters"),
  BETTER_AUTH_URL: z.string().url("BETTER_AUTH_URL must be a valid URL"),

  // Passkeys
  PASSKEY_RP_ID: z.string().min(1, "PASSKEY_RP_ID is required"),

  // Node environment
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
});

/**
 * Client-side environment variables schema.
 * These are exposed to the client and must be prefixed with NEXT_PUBLIC_.
 */
const clientSchema = z.object({
  NEXT_PUBLIC_APP_URL: z.string().url("NEXT_PUBLIC_APP_URL must be a valid URL"),
});

/**
 * Validates and parses environment variables.
 * @throws {ZodError} if validation fails
 */
function validateEnv() {
  // Check if we're on the server
  const isServer = typeof window === "undefined";

  // Parse server environment variables (only on server)
  const server = isServer
    ? serverSchema.safeParse(process.env)
    : { success: true as const, data: {} as z.infer<typeof serverSchema> };

  if (!server.success) {
    console.error(
      "❌ Invalid server environment variables:",
      server.error.flatten().fieldErrors,
    );
    throw new Error("Invalid server environment variables");
  }

  // Parse client environment variables (both server and client)
  const client = clientSchema.safeParse({
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  });

  if (!client.success) {
    console.error(
      "❌ Invalid client environment variables:",
      client.error.flatten().fieldErrors,
    );
    throw new Error("Invalid client environment variables");
  }

  return {
    server: server.data,
    client: client.data,
  };
}

// Validate environment variables at module load
const env = validateEnv();

/**
 * Server-side environment variables.
 * Only accessible on the server.
 */
export const serverEnv = env.server;

/**
 * Client-side environment variables.
 * Accessible on both server and client.
 */
export const clientEnv = env.client;

/**
 * Type-safe environment variable access.
 * Automatically selects server or client env based on context.
 */
export const getEnv = () => {
  const isServer = typeof window === "undefined";
  return {
    ...env.client,
    ...(isServer ? env.server : {}),
  };
};

// Export types for use in other packages
export type ServerEnv = z.infer<typeof serverSchema>;
export type ClientEnv = z.infer<typeof clientSchema>;
