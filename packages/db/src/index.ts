import { PrismaClient } from "@prisma/client";
import { serverEnv } from "@caesar/env";

/**
 * Global Prisma client instance to prevent multiple instances in development.
 * This is a workaround for hot-reloading in Next.js.
 */
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

/**
 * Prisma client instance with enhanced configuration.
 * - Uses DATABASE_URL from @caesar/env
 * - Enables query logging in development
 * - Reuses instance in development to prevent connection leaks
 */
export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      serverEnv.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
  });

if (serverEnv.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

/**
 * Export Prisma client types for use in other packages
 */
export * from "@prisma/client";
