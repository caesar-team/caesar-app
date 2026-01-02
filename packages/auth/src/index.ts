import { prisma } from "@caesar/db";
import { serverEnv } from "@caesar/env";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { organization, passkey, twoFactor } from "better-auth/plugins";

/**
 * Better Auth server configuration.
 * Handles authentication and authorization for the Caesar app.
 *
 * Features:
 * - Email/password authentication
 * - Organization support with roles (owner, admin, member, guest)
 * - Two-factor authentication (TOTP) with backup codes
 * - Passkey (WebAuthn) support
 * - User encryption keys (publicKey, encryptedPrivateKey)
 */
export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // 1 day (refresh session)
    cookieCache: {
      enabled: true,
      maxAge: 5 * 60, // 5 minutes
    },
  },

  advanced: {
    cookiePrefix: "caesar",
    crossSubDomainCookies: {
      enabled: false,
    },
  },

  secret: serverEnv.BETTER_AUTH_SECRET,
  baseURL: serverEnv.BETTER_AUTH_URL,
  basePath: "/api/auth",

  trustedOrigins: [serverEnv.BETTER_AUTH_URL],

  user: {
    additionalFields: {
      publicKey: {
        type: "string",
        required: false,
        defaultValue: null,
        input: false, // Not settable via sign up
      },
      encryptedPrivateKey: {
        type: "string",
        required: false,
        defaultValue: null,
        input: false, // Not settable via sign up
      },
    },
  },

  plugins: [
    organization({
      roles: {
        owner: {
          description: "Organization owner with full permissions",
        },
        admin: {
          description: "Administrator with management permissions",
        },
        member: {
          description: "Regular member with standard access",
        },
        guest: {
          description: "Guest with limited read-only access",
        },
      },
      sendInvitationEmail: async (_data) => {},
    }),

    twoFactor({
      issuer: "Caesar App",
      backupCodes: {
        enabled: true,
        amount: 10,
        length: 10,
      },
    }),

    passkey({
      rpID: serverEnv.PASSKEY_RP_ID,
      rpName: "Caesar App",
      origin: serverEnv.BETTER_AUTH_URL,
    }),
  ],

  socialProviders: {},
});

/**
 * Better Auth API handler.
 * Mount this in your framework's API routes.
 *
 * Example (Next.js App Router):
 * ```ts
 * // app/api/auth/[...all]/route.ts
 * import { auth } from "@caesar/auth";
 * import { toNextJsHandler } from "better-auth/next-js";
 *
 * export const { POST, GET } = toNextJsHandler(auth);
 * ```
 */
export const handler = auth.handler;

/**
 * Export types for use in other packages
 */
export type Session = typeof auth.$Infer.Session;
