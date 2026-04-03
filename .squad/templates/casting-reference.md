# Casting Reference

On-demand reference for the Casting & Persistent Naming system. Only loaded during Init Mode or when adding new team members.

**⚠️ IMPORTANT:** This reference defines HOW to cast names. It does NOT define the team composition. The team roles and specializations MUST be derived from the USER'S project description — never from examples in the coordinator or this document.

## Universe Table

Each universe has a capacity (max agents). ONE universe per assignment. NEVER mix.

| Universe | Capacity | Shape / Tone |
|----------|----------|--------------|
| The Usual Suspects | 6 | Heist, ensemble crime, pressure-cooker |
| Reservoir Dogs | 8 | Heist, color-coded, terse |
| Alien | 8 | Sci-fi survival, crew under pressure |
| Ocean's Eleven | 14 | Heist, specialty roles, teamwork |
| Arrested Development | 15 | Ensemble comedy, dysfunctional family |
| Star Wars | 12 | Sci-fi epic, light/dark, heroes |
| The Matrix | 10 | Sci-fi cyberpunk, hacker crew |
| Firefly | 10 | Sci-fi western, scrappy crew |
| The Goonies | 8 | Adventure, underdogs, friendship |
| The Simpsons | 20 | Ensemble comedy, community |
| Breaking Bad | 12 | Drama, high-stakes chemistry |
| Lost | 18 | Mystery ensemble, survival |
| Marvel Cinematic Universe | 25 | Superhero ensemble, large teams |
| DC Universe | 18 | Superhero ensemble, diverse powers |

## Selection Algorithm

Score each universe and pick the highest score. Same inputs → same choice (unless LRU changes).

### Scoring (0–10 each)

1. **size_fit** — Does the universe capacity fit the team size?
   - `capacity >= agent_count + 2` (headroom for growth) → 10
   - `capacity >= agent_count` (exact fit) → 7
   - `capacity < agent_count` → 0 (disqualified)

2. **shape_fit** — Does the universe tone match the project shape?
   - Small focused team (3–5) → heist/crew universes score higher (Usual Suspects, Alien, Reservoir Dogs)
   - Medium team (6–10) → ensemble universes (Ocean's, Firefly, Matrix, Breaking Bad)
   - Large team (11+) → large-cast universes (Simpsons, Lost, MCU, DC, Arrested Development)

3. **resonance_fit** — Does the universe resonate with the project domain?
   - Tech/hacker project → Matrix, Firefly
   - Creative/design project → Arrested Development, Simpsons
   - Data/analytics → Breaking Bad
   - Enterprise/large-scale → Ocean's, MCU
   - This is subjective — use judgment. Any universe can work for any project.

4. **LRU** (Least Recently Used) — Has this universe been used recently in `.squad/casting/history.json`?
   - Never used → +3 bonus
   - Used but long ago → +1 bonus
   - Recently used → 0

### Final Score

`total = size_fit + shape_fit + resonance_fit + LRU`

Pick the highest-scoring universe. On ties, prefer the one with more capacity headroom.

## Casting State File Schemas

### policy.json

```json
{
  "casting_policy_version": "1.1",
  "allowlist_universes": ["Universe Name", "..."],
  "universe_capacity": {
    "Universe Name": 10
  }
}
```

- `allowlist_universes`: Array of allowed universe names
- `universe_capacity`: Map of universe → max agent count

### registry.json

```json
{
  "agents": {
    "agentname": {
      "created_at": "2026-01-01T00:00:00Z",
      "persistent_name": "AgentName",
      "universe": "Universe Name",
      "legacy_named": false,
      "status": "active"
    }
  }
}
```

- `persistent_name`: Display name (title case)
- `universe`: Which universe this name comes from
- `legacy_named`: `true` if agent existed before casting was initialized (migration)
- `status`: `"active"` or `"retired"` — retired names remain reserved, never reused

### history.json

```json
{
  "assignment_cast_snapshots": {
    "project-init-YYYY-MM-DD": {
      "created_at": "2026-01-01T00:00:00Z",
      "agents": ["Name1", "Name2"],
      "universe": "Universe Name"
    }
  },
  "universe_usage_history": [
    {
      "assignment_id": "project-init-YYYY-MM-DD",
      "assigned_at": "2026-01-01T00:00:00Z",
      "universe": "Universe Name",
      "agent_count": 5
    }
  ]
}
```

- `assignment_cast_snapshots`: Keyed by unique assignment ID. Records which agents were cast and from which universe.
- `universe_usage_history`: Append-only log of universe selections for LRU scoring.
- The `assignment_id` should reflect the PROJECT name (not "squad-sdk"), e.g., `"meal-planner-init-2026-03-07"`.
