---
name: "spec"
description: "Spec-driven development workflow — constitution, PRD, feature specs, and task breakdown"
domain: "specifications"
confidence: "high"
source: "manual"
---

## Context
The Spec agent drives a structured specification workflow before any implementation begins. This skill defines the artifact hierarchy, phase flow, and quality gates that ensure every feature is fully specified before code is written.

## Patterns

### Three-Level Artifact Hierarchy
Specifications operate at three levels, each building on the previous:
1. **Constitution** (`.squad/constitution.md`) — Project-wide principles, technology standards, quality rules. Created once. All specs must comply.
2. **Project-level** (`.squad/prd.md`, `.squad/architecture.md`, `.squad/roadmap.md`) — Product requirements, system architecture, feature roadmap. Created once per project, updated as scope evolves.
3. **Feature-level** (`.squad/specs/{feature-id}/`) — Individual feature specs containing requirements.md, design.md, tasks.md, and progress.md.

### Phase Flow
Each feature spec follows five phases in strict order:
1. **Research** — Explore codebase, find existing patterns, verify feasibility
2. **Requirements** — User stories, acceptance criteria, scope boundaries
3. **Design** — Architecture decisions, component design, API contracts
4. **Tasks** — Ordered implementation steps with dependencies, parallelism markers, and verification checkpoints
5. **Review** — Validate each artifact against quality rubrics before advancing

### Task Format
Tasks in tasks.md use a structured table format:
- Each task has an ID (T01, T02...), description, agent assignment, dependency list, and parallelism marker
- `[P]` = can run in parallel with other [P] tasks at the same dependency level
- `[VERIFY]` tasks route to the Tester agent for quality gates
- Dependencies are expressed as comma-separated task IDs

### Codebase-First Principle
Always read existing code before writing specs. The spec must reflect what the codebase actually does, not assumptions about what it should do. Research phase artifacts include file paths, function signatures, and existing patterns discovered through exploration.

### Constitution Compliance
Every feature spec must be consistent with the constitution:
- Requirements validate against MUST rules
- Design follows architecture patterns
- Tasks use commit conventions and testing requirements
- Violations are flagged during review, not silently ignored

## Anti-Patterns
- **Skipping research** — Writing specs without reading the codebase leads to designs that conflict with existing patterns.
- **Monolithic tasks** — Tasks should be small enough for a single agent to complete in one session. Break large work into subtasks.
- **Missing verification** — Every 3-5 implementation tasks should have a [VERIFY] checkpoint.
- **Spec without constitution** — Always establish the constitution before writing feature specs. It prevents contradictory decisions across features.
- **Gold-plating specs** — Specs should be concise instructions, not tutorial prose. Write rules, not explanations.
