# @caesar/db

Database package for Caesar App using Prisma ORM.

## Features

- Prisma Client singleton instance
- Better Auth compatible schema (User, Session, Account, Verification)
- PostgreSQL support (SQLite for development)
- Type-safe database access
- Environment-based configuration via `@caesar/env`

## Usage

```typescript
import { prisma } from "@caesar/db";

// Query users
const users = await prisma.user.findMany();

// Create a user
const user = await prisma.user.create({
  data: {
    email: "user@example.com",
    name: "John Doe",
  },
});
```

## Scripts

```bash
# Generate Prisma client
bun run db:generate

# Push schema to database (no migrations)
bun run db:push

# Open Prisma Studio
bun run db:studio

# Create and apply migration
bun run db:migrate

# Deploy migrations (production)
bun run db:migrate:deploy
```

## Database Models

### User
Core user model with email authentication support.

### Session
User session management for Better Auth.

### Account
OAuth provider accounts linked to users.

### Verification
Email verification and password reset tokens.

## Environment Variables

Required environment variable from `@caesar/env`:
- `DATABASE_URL` - PostgreSQL connection string

## Development

The package uses a singleton pattern to prevent multiple Prisma Client instances in development mode, which can cause connection pool exhaustion.

## Type Safety

All Prisma types are re-exported from this package for use in other packages:

```typescript
import type { User, Session } from "@caesar/db";
```
