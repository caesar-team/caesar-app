# Caesar App

## Documentation

**All docs and plans go to wiki, NOT `docs/` folder:**

- Wiki repo: `/Users/akira/Jobs/Caesar/caesar-app.wiki/`
- Remote: `https://git.bshk.app/caesar-team/caesar-app.wiki.git`

### Wiki Page Naming

- Design docs: `<Feature>-Design.md`
- Implementation plans: `M<N>-<Name>-Plan.md`
- After adding: update `Home.md` with link, commit & push

## Stack
- **Frontend**: Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS
- **Backend**: tRPC, ZenStack (access policies), Prisma
- **Auth**: Better Auth
- **Database**: PostgreSQL (prod) / SQLite (dev)

## Development Team (Agents)

This project uses multi-agent development workflow. See `.claude/agents/` for configurations.

| Agent | Role | Labels |
|-------|------|--------|
| PM | Orchestrator, task decomposition | `pm`, `planning` |
| Frontend | Next.js, React, UI | `frontend`, `ui`, `react` |
| Backend | tRPC, ZenStack, Prisma | `backend`, `api`, `database` |
| DevOps | Docker, CI/CD, Deploy | `devops`, `ci`, `docker` |
| QA | Testing, Code Review | `qa`, `testing`, `review` |

## Skills

Project uses skills from:
- `skills-marketplace` (local): zenstack, better-auth, research-guide
- `wshobson/agents`: backend-architect, kubernetes-architect
- `claudekit-skills`: better-auth, docs-seeker

## Commands

```bash
# Development
bun dev              # Start dev server (DON'T RUN WITHOUT PERMISSION)
bun build            # Build for production
bun test             # Run tests

# Database
bun db:push          # Push schema changes
bun db:generate      # Generate Prisma client
bun zen:generate     # Generate ZenStack artifacts

# Agents
bun agent:pm         # Run PM agent
bun agent:frontend   # Run Frontend agent
bun agent:backend    # Run Backend agent
```

## Conventions

- Use ZenStack `@@allow`/`@@deny` for all access control
- All API routes via tRPC
- Better Auth for authentication
- Vitest for unit tests, Playwright for E2E
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`

## Gitea Integration

Repository: [Configure in .claude/settings.json]

Agents have individual Gitea accounts:
- `agent-pm`, `agent-frontend`, `agent-backend`, `agent-devops`, `agent-qa`

## File Structure

```
caesar-app/
├── src/
│   ├── app/              # Next.js App Router
│   ├── components/       # React components
│   ├── server/           # tRPC routers
│   ├── lib/              # Utilities
│   │   ├── auth.ts       # Better Auth server
│   │   ├── auth-client.ts
│   │   ├── db.ts         # Enhanced Prisma
│   │   └── trpc.ts       # tRPC setup
│   └── trpc/             # tRPC client
├── prisma/
│   └── schema.prisma     # Generated from ZenStack
├── schema.zmodel         # ZenStack schema (source of truth)
├── tests/                # Vitest tests
└── e2e/                  # Playwright tests
```
