import { initTRPC, TRPCError } from "@trpc/server";
import { type Session } from "@caesar/auth";
import { prisma, type User } from "@caesar/db";
import { enhance } from "@zenstackhq/runtime";
import SuperJSON from "superjson";

/**
 * tRPC context shape.
 * Includes:
 * - session: Better Auth session (null if not authenticated)
 * - user: User object from session (null if not authenticated)
 * - db: ACL-enhanced Prisma client from ZenStack
 */
export interface Context {
  session: Session | null;
  user: User | null;
  db: ReturnType<typeof enhance>;
}

/**
 * Factory for creating tRPC context.
 * This should be called by your framework adapter (Next.js, Express, etc.)
 *
 * @param opts - Options containing session information
 * @returns Context object with session, user, and ACL-enhanced db
 */
export const createContext = (opts: { session: Session | null }): Context => {
  const { session } = opts;

  // Extract user from session
  const user = session?.user ?? null;

  // Create ACL-enhanced Prisma client
  // ZenStack's enhance() applies access policies based on the authenticated user
  const db = enhance(prisma, { user });

  return {
    session,
    user,
    db,
  };
};

/**
 * Initialize tRPC with context and SuperJSON transformer.
 * SuperJSON handles serialization of Date, Map, Set, BigInt, etc.
 */
const t = initTRPC.context<Context>().create({
  transformer: SuperJSON,
  errorFormatter({ shape }) {
    return shape;
  },
});

/**
 * Reusable router creator.
 * Use this to define routers in your API.
 */
export const createTRPCRouter = t.router;

/**
 * Public procedure - no authentication required.
 * Anyone can call these endpoints.
 *
 * Example:
 * ```ts
 * publicProcedure
 *   .input(z.object({ name: z.string() }))
 *   .query(({ input }) => `Hello ${input.name}`);
 * ```
 */
export const publicProcedure = t.procedure;

/**
 * Protected procedure - requires authentication.
 * Throws UNAUTHORIZED if session is null.
 *
 * Example:
 * ```ts
 * protectedProcedure
 *   .input(z.object({ id: z.string() }))
 *   .query(({ ctx, input }) => {
 *     // ctx.user is guaranteed to be non-null
 *     return ctx.db.item.findUnique({ where: { id: input.id } });
 *   });
 * ```
 */
export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.session || !ctx.user) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "You must be logged in to access this resource",
    });
  }

  return next({
    ctx: {
      // Narrow context type to guarantee non-null session and user
      session: ctx.session,
      user: ctx.user,
      db: ctx.db,
    },
  });
});
