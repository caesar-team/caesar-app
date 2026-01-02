import { createAuthClient } from "better-auth/react";
import {
  organizationClient,
  twoFactorClient,
  passkeyClient,
} from "better-auth/client/plugins";

export function createCaesarAuthClient(baseURL: string) {
  return createAuthClient({
    baseURL,
    plugins: [organizationClient(), twoFactorClient(), passkeyClient()],
  });
}

export const authClient =
  typeof window !== "undefined"
    ? createCaesarAuthClient(window.location.origin)
    : createCaesarAuthClient("");

export const { useSession, signIn, signUp, signOut } = authClient;

export const useActiveOrganization = authClient.useActiveOrganization;
export const useOrganization = authClient.organization.useListOrganizations;

export type { Session, User } from "better-auth/types";
