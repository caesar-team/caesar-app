/**
 * @caesar/api - Type-safe tRPC API
 *
 * This package provides the tRPC API infrastructure for Caesar.
 * It includes:
 * - Context creation with ACL-enhanced database client
 * - Public and protected procedures
 * - Root router with type inference
 */

// Export root router and type
export { appRouter, type AppRouter } from "./root.js";

// Export tRPC utilities for creating routers
export {
  createTRPCRouter,
  publicProcedure,
  protectedProcedure,
  createContext,
  type Context,
} from "./trpc.js";
