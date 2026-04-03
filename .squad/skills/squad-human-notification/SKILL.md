# Squad Human Notification Skill

Agents use Discord to notify the user when they need attention. Messages go to the project's Discord channel.

**Confidence:** high — verified working 2026-03-05

## When to Notify

| Situation                                 | Priority | Action                             |
| ----------------------------------------- | -------- | ---------------------------------- |
| Blocked — need decision or input          | High     | Send message with clear question   |
| Error — can't recover autonomously        | High     | Send message with error details    |
| Work complete — milestone or feature done | Normal   | Send message with summary          |
| Status update — batch/phase completed     | Normal   | Send message with progress summary |
| FYI — progress update on long task        | Low      | Send message with brief update     |

**ALWAYS notify on:**

- Task/phase completion (what was done, what's next)
- Questions that need user input
- Errors that block progress
- CI/pipeline results (pass or fail)

Do NOT notify for routine operations (individual commits, single test runs, file edits). Batch related updates into one notification per work phase.

## How to Send Notifications

### Method: Node.js script (reliable, always works)

Use this PowerShell/node one-liner to send to `#yt-summarizer` (channel ID: `1479062015220908154`):

```powershell
node -e "const{Client,GatewayIntentBits}=require(process.env.USERPROFILE+'/.copilot/tools/discordmcp/node_modules/discord.js');const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages]});c.once('ready',async()=>{const ch=await c.channels.fetch('1479062015220908154');await ch.send(process.argv[1]);c.destroy()});c.login(process.env.DISCORD_TOKEN)" "YOUR MESSAGE HERE"
```

**Channel IDs:**

- `#yt-summarizer`: `1479062015220908154` (default for this project)
- `#general`: `1479061129216135191`
- `#meal-planner`: `1479061992772997202`

### Fallback: Discord MCP tools

If the `discord` MCP tools (`send_message`, `read_messages`) are available in the session, prefer those. Fall back to the node script method when MCP tools are unavailable.

### Check for user replies

Use `read_messages` MCP tool or the node script with `channel.messages.fetch({limit:5})` to poll for responses after posting a question.

## Message Format

Keep messages scannable. Use this structure:

```
**{AgentName}: {Brief subject}**

**Status**: Blocked / Complete / Error / FYI
**Context**: [1-2 sentences of what's happening]

[Details, options, or summary as needed]

**Next**: [What happens next, or what you need from the user]
```

## Message Naming Convention

Always prefix with the agent name so the user can scan messages quickly:

- `**Ripley: DB migration needs review**`
- `**Kane: Frontend build failing — missing env var**`
- `**Parker: Preview deployment complete**`
- `**Lambert: E2E tests passing — 14/14 green**`
- `**Dallas: Architecture decision needed — caching strategy**`

## Rules

1. **One message per topic.** Don't mix unrelated issues in a single message.
2. **Don't spam.** Batch related updates into a single message rather than sending many small ones.
3. **Include actionable info.** Don't just say "something failed" — include the error, what you tried, and what you need.
4. **Respect the channel.** This channel is shared across all feature branches for the project. Include the branch/feature name when relevant.
5. **Two-way comms.** After posting a question, check for replies before proceeding with a default action. Give the user reasonable time to respond.

## Discord Watcher (Two-Way Communication)

A background watcher daemon monitors `#yt-summarizer` for human messages and writes them to an inbox file.

### Architecture

```
Discord #yt-summarizer ←→ discord-watcher.cjs (detached daemon)
                              ↓ writes new human messages
                         ~/.copilot/tools/discordmcp/inbox.json
                              ↑ Coordinator checks periodically
                         Copilot CLI session
```

### Starting the watcher

The coordinator MUST start the Discord watcher at the beginning of every session:

```powershell
node "$env:USERPROFILE\.copilot\tools\discordmcp\discord-watcher.cjs" --interval 10 --channel 1479062015220908154
```

Run as a **detached** background process so it survives session end.

### Checking for messages

The coordinator MUST check the inbox file periodically (at minimum: after every agent batch, and before calling task_complete):

```powershell
if (Test-Path "$env:USERPROFILE\.copilot\tools\discordmcp\inbox.json") {
    Get-Content "$env:USERPROFILE\.copilot\tools\discordmcp\inbox.json" | ConvertFrom-Json | Format-Table
}
```

When messages are found:
1. Read and process them as if the user typed them in the CLI
2. Clear the inbox file after processing
3. Respond on Discord acknowledging the message

### Files

| File | Purpose |
|------|---------|
| `~/.copilot/tools/discordmcp/discord-watcher.cjs` | Watcher daemon script |
| `~/.copilot/tools/discordmcp/inbox.json` | New human messages (coordinator reads) |
| `~/.copilot/tools/discordmcp/.last-read-id` | Last processed Discord message ID |
