# AI Agent Configuration Refactoring

## Summary

Refactored the AI agent configuration files to follow GitHub Copilot best practices and improve tool awareness.

## Changes Made

### 1. Enhanced `.github/copilot-instructions.md`

**Before**: Only contained Aspire wrapper documentation  
**After**: Comprehensive repository-wide context including:
- Available tools and capabilities (Shell, Development, Testing, Build, Infrastructure)
- Repository scripts with descriptions
- GitHub CLI usage patterns (addressing the "forgetting `gh`" issue)
- Clear tool categories and when to use them

### 2. Updated All Agent Files with Proper YAML Frontmatter

Added `tools` property to all `.agent.md` files following the official specification:

**Before**:
```yaml
---
description: Agent description
---
```

**After**:
```yaml
---
description: Agent description
tools:
  - read
  - edit
  - search
  - execute
  - github/*
  - playwright/*
  - aspire/*
target: vscode
---
```

**Files Updated**:
- `speckit.implement.agent.md` - Full toolset for implementation
- `speckit.tasks.agent.md` - Read, edit, search, execute
- `speckit.plan.agent.md` - Read, edit, search, execute
- `speckit.verify.agent.md` - Testing and verification tools
- `speckit.specify.agent.md` - Specification creation tools
- `speckit.checklist.agent.md` - Checklist generation tools
- `speckit.analyze.agent.md` - Read-only analysis tools
- `speckit.clarify.agent.md` - Specification clarification tools
- `speckit.constitution.agent.md` - Constitution management tools
- `speckit.taskstoissues.agent.md` - GitHub issue creation tools

### 3. Created `.github/TOOLS_REFERENCE.md`

New comprehensive reference document containing:
- **Core Tools**: read, edit, search, execute
- **MCP Servers**: GitHub, Playwright, Aspire with complete tool lists
- **CLI Tools**: git, gh, npm, pip, dotnet, docker, terraform, kubectl, helm, az
- **Repository Scripts**: Complete list with descriptions
- **GitHub Actions**: All custom actions with purposes
- **Best Practices**: When to use each tool with examples
- **Tool Selection Examples**: YAML configurations for different agent types

### 4. Simplified `AGENTS.md`

**Before**: Contained both Aspire-specific and repository-wide instructions (178 lines)  
**After**: Focused Aspire-specific guidance with clear reference to copilot-instructions.md

Added note at top:
```markdown
> **Note**: This file provides Aspire-specific guidance for AI coding agents.
> For comprehensive repository-wide instructions including available tools,
> scripts, and workflows, see [.github/copilot-instructions.md](.github/copilot-instructions.md).
```

## Benefits

### 1. **Explicit Tool Awareness**
Agents now have explicit `tools` declarations in their frontmatter, making it clear what capabilities are available.

### 2. **GitHub CLI Visibility**
Multiple mentions of `gh` CLI with specific examples throughout:
- In copilot-instructions.md "Available Tools & Capabilities" section
- In TOOLS_REFERENCE.md with detailed usage patterns
- Marked as **IMPORTANT** and **RECOMMENDED**

### 3. **Follows Official Best Practices**
- Uses YAML frontmatter properties as documented
- Uses tool aliases (read, edit, search, execute)
- Uses MCP server namespacing (github/*, playwright/*, aspire/*)
- Sets `target: vscode` for IDE-specific agents

### 4. **Better Organization**
- Repository-wide context in `.github/copilot-instructions.md`
- Aspire-specific guidance in `AGENTS.md`
- Detailed tool reference in `TOOLS_REFERENCE.md`
- Agent-specific configurations in individual `.agent.md` files

### 5. **Discoverable Tools**
Complete catalog of:
- 50+ command-line tools
- 20+ MCP server tools  
- 15+ repository scripts
- 15+ custom GitHub Actions

## Testing Recommendations

1. **Test agent tool access** - Verify agents can use declared tools
2. **Test GitHub CLI** - Confirm `gh` is available and recognized by agents
3. **Test MCP servers** - Verify Aspire, Playwright, and GitHub MCP tools work
4. **Test handoffs** - Ensure agent handoffs work with new configurations

## References

- [GitHub Copilot Custom Agents Configuration](https://docs.github.com/en/copilot/reference/custom-agents-configuration)
- [Custom Agents in VS Code](https://code.visualstudio.com/docs/copilot/customization/custom-agents)
- [Extending Copilot with MCP](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp)
