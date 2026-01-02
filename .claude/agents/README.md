# Multi-Agent Development Team

Конфигурация мультиагентной команды разработки с интеграцией Gitea.

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    PM AGENT (Orchestrator)                   │
│  Gitea: agent-pm | Role: Task decomposition, PR reviews     │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┬─────────────┐
        │             │             │             │
        ▼             ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│ FRONTEND  │  │  BACKEND  │  │  DEVOPS   │  │    QA     │
│           │  │           │  │           │  │           │
│ Next.js   │  │ tRPC      │  │ Docker    │  │ Vitest    │
│ React     │  │ ZenStack  │  │ CI/CD     │  │ Playwright│
│ Tailwind  │  │ Prisma    │  │ K8s       │  │ Review    │
└───────────┘  └───────────┘  └───────────┘  └───────────┘
```

## Быстрый старт

### 1. Создать пользователей в Gitea

```bash
# Через Admin UI или CLI
tea admin user create --username agent-pm --email agent-pm@local
tea admin user create --username agent-frontend --email agent-frontend@local
tea admin user create --username agent-backend --email agent-backend@local
tea admin user create --username agent-devops --email agent-devops@local
tea admin user create --username agent-qa --email agent-qa@local
```

### 2. Сгенерировать токены

Для каждого агента:
1. Login в Gitea под аккаунтом
2. Settings → Applications → Generate New Token
3. Permissions: `repo:read`, `repo:write`, `issue:read`, `issue:write`

### 3. Настроить окружение

```bash
cp .env.template .env
# Заполнить токены в .env
```

### 4. Добавить агентов в репозиторий

```bash
# Для работы с Gitea
tea repos add-collaborator agent-pm --permission write
tea repos add-collaborator agent-frontend --permission write
tea repos add-collaborator agent-backend --permission write
tea repos add-collaborator agent-devops --permission write
tea repos add-collaborator agent-qa --permission write
```

## Использование

### Вариант A: Claude Code Subagents

Скопировать конфиги в `~/.claude/agents/`:

```bash
cp -r agents/*/ ~/.claude/agents/
```

Запуск через Task tool:
```
Task(subagent_type="backend-agent", prompt="Implement user CRUD API")
```

### Вариант B: Claude Agent SDK

```typescript
import { Claude } from '@anthropic-ai/sdk';
import pmConfig from './agents/pm/agent.json';
import frontendConfig from './agents/frontend/agent.json';

const orchestrator = new Claude({
  systemPrompt: pmConfig.systemPrompt
});

const frontend = orchestrator.createSubagent({
  name: 'frontend',
  systemPrompt: frontendConfig.systemPrompt,
  allowedPaths: frontendConfig.allowedPaths
});

// PM делегирует задачу
await orchestrator.chat(`
  Create issue: Add user profile page
  Assign to: @frontend
`);
```

### Вариант C: Gitea Actions (автоматизация)

```yaml
# .gitea/workflows/agent-dispatch.yml
name: Agent Dispatch

on:
  issues:
    types: [labeled]

jobs:
  dispatch:
    runs-on: ubuntu-latest
    steps:
      - name: Route to agent
        run: |
          LABEL="${{ github.event.label.name }}"
          case $LABEL in
            frontend|ui|react)
              echo "Assigning to agent-frontend"
              tea issue edit ${{ github.event.issue.number }} --assignees agent-frontend
              ;;
            backend|api|database)
              echo "Assigning to agent-backend"
              tea issue edit ${{ github.event.issue.number }} --assignees agent-backend
              ;;
          esac
```

## Label Routing

| Label | Agent |
|-------|-------|
| `frontend`, `ui`, `react`, `nextjs` | frontend-agent |
| `backend`, `api`, `database`, `auth` | backend-agent |
| `devops`, `ci`, `docker`, `k8s` | devops-agent |
| `qa`, `testing`, `bug` | qa-agent |

## Workflow

1. **User** создаёт issue в Gitea
2. **PM Agent** разбивает на subtasks, ставит labels
3. **Specialized Agent** берёт issue по label
4. Agent создаёт branch, реализует, открывает PR
5. **QA Agent** ревьюит, запускает тесты
6. **PM Agent** мержит после approval

## Файлы

```
agents/
├── orchestrator.json    # Главный конфиг оркестратора
├── .env.template        # Шаблон переменных окружения
├── README.md            # Эта документация
├── pm/
│   └── agent.json       # Project Manager
├── frontend/
│   └── agent.json       # Frontend Developer
├── backend/
│   └── agent.json       # Backend Developer
├── devops/
│   └── agent.json       # DevOps Engineer
└── qa/
    └── agent.json       # QA Engineer
```

## Skills каждого агента

| Agent | Installed Skills |
|-------|-----------------|
| Frontend | nextjs-expert, react-expert, typescript-expert |
| Backend | trpc-expert, prisma-expert, zenstack, better-auth |
| DevOps | docker-expert, github-actions-expert |
| QA | vitest-expert, playwright-expert, jest-expert |
