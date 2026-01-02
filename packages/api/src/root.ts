import { createTRPCRouter } from "./trpc.js";

/**
 * Root tRPC router.
 * All API routes are defined here.
 *
 * Example structure:
 * ```ts
 * export const appRouter = createTRPCRouter({
 *   auth: authRouter,
 *   items: itemsRouter,
 *   organizations: organizationsRouter,
 * });
 * ```
 *
 * Currently empty - routers will be added in subsequent issues.
 */
export const appRouter = createTRPCRouter({
  // TODO: Add routers here (e.g., items, organizations, directories)
});

/**
 * Type definition for the app router.
 * This is used by the tRPC client for type inference.
 *
 * Export this type and use it in your client setup:
 * ```ts
 * import type { AppRouter } from "@caesar/api";
 * const trpc = createTRPCReact<AppRouter>();
 * ```
 */
export type AppRouter = typeof appRouter;
