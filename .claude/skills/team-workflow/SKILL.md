---
name: team-workflow
description: Multi-agent development workflow for Caesar App. Use when starting new features, handling issues, or coordinating team work.
version: 1.0.0
---

# Caesar Team Workflow

## Team Agents

| Agent | Gitea User | Responsibilities |
|-------|------------|------------------|
| **PM** | agent-pm | Orchestration, task decomposition, PR merging |
| **Frontend** | agent-frontend | Next.js, React, UI components |
| **Backend** | agent-backend | tRPC, ZenStack, Prisma, Better Auth |
| **DevOps** | agent-devops | Docker, CI/CD, deployment |
| **QA** | agent-qa | Testing, code review, validation |

## Workflow

### 1. New Feature Request

```
User → PM Agent → Decompose → Create Issues with Labels → Assign Agents
```

PM creates issues with:
- Clear title and description
- Acceptance criteria
- Appropriate labels (`frontend`, `backend`, etc.)
- Subtasks if needed

### 2. Implementation

```
Agent takes issue → Create branch → Implement → Open PR
```

Branch naming: `{role}/{issue-number}-{slug}`
- `frontend/42-user-profile`
- `backend/43-user-api`

### 3. Review & Merge

```
PR Created → QA Agent reviews → Tests pass → PM Agent merges
```

## Label Routing

| Labels | → Agent |
|--------|---------|
| `frontend`, `ui`, `react`, `nextjs`, `component` | frontend |
| `backend`, `api`, `database`, `auth`, `trpc`, `zenstack` | backend |
| `devops`, `ci`, `cd`, `docker`, `deploy` | devops |
| `qa`, `testing`, `test`, `review`, `bug` | qa |

## Usage Examples

### Start new feature
```
"Implement user profile page with avatar upload"

PM will:
1. Create issue #101: "User profile page UI" → frontend
2. Create issue #102: "User profile API endpoints" → backend
3. Create issue #103: "Avatar storage setup" → devops
```

### Fix bug
```
"Login fails on mobile Safari"

PM will:
1. Create issue with `bug` + `frontend` labels
2. QA Agent investigates
3. Frontend Agent fixes
4. QA Agent validates
```

### Deploy feature
```
"Deploy user profile to staging"

PM will:
1. Create issue with `devops` + `deploy` labels
2. DevOps Agent handles deployment
3. QA Agent runs E2E tests on staging
```

## Commands

```bash
# Invoke specific agent (use agent name from .claude/agents/*.md)
Task(subagent_type="backend", prompt="...")
Task(subagent_type="frontend", prompt="...")
Task(subagent_type="pm", prompt="...")
Task(subagent_type="qa", prompt="...")
Task(subagent_type="devops", prompt="...")

# Or use skills
/zenstack    # For ZenStack policies
/better-auth # For authentication
```

## Skills per Agent

### Frontend Agent
- `nextjs-expert` - Next.js patterns
- `react-expert` - React best practices
- `typescript-expert` - TypeScript

### Backend Agent
- `zenstack` - Access policies
- `better-auth` - Authentication
- `trpc-expert` - tRPC routers
- `prisma-expert` - Database

### DevOps Agent
- `docker-expert` - Containerization
- `github-actions-expert` - CI/CD

### QA Agent
- `vitest-expert` - Unit testing
- `playwright-expert` - E2E testing
