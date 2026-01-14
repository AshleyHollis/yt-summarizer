---
description: Stage changes, create a commit, and push to the current branch.
model: zai-coding-plan/glm-4.7
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

1. **Review repo state**:
   - Run `git status` to confirm the working tree state.
   - Run `git diff` to inspect staged and unstaged changes.
   - Run `git log -5 --oneline` to follow commit style.

2. **Stage files**:
   - Add relevant files with `git add`.
   - If untracked files should not be committed, mention them explicitly.

3. **Commit changes**:
   - Craft a concise commit message (1–2 sentences) focused on the intent.
   - Create the commit.
   - If hooks update files, restage and re-run the commit.

4. **Push**:
   - Push to the current branch.
   - Report the new commit SHA and confirm the push succeeded.

## Notes

- Never skip hooks unless the user explicitly requests it.
- Do not push unless the commit succeeds.
- If there are no changes, stop and explain why.
