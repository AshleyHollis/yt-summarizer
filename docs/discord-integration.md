# Discord Integration for Copilot CLI + Squad

> **Portable reference** — copy this file into any repo's `.squad/` or `.copilot/` directory to enable Discord two-way communication with Copilot CLI sessions.

## Overview

This integration enables:
- **Outbound**: Copilot agents send status updates, questions, and error reports to a Discord channel
- **Inbound**: A background watcher daemon monitors Discord for human messages and queues them for the Copilot session to process
- **Two-way**: Agents post questions → user replies on Discord → agent reads reply and acts on it

## Prerequisites

### 1. Discord Bot

Create a Discord bot at https://discord.com/developers/applications:

1. Click **New Application** → name it (e.g., "Squad Bot")
2. Go to **Bot** tab → click **Reset Token** → **copy the token** (you'll need it below)
3. Under **Privileged Gateway Intents**, enable:
   - ✅ Message Content Intent
   - ✅ Server Members Intent  
   - ✅ Presence Intent (optional)
4. Go to **OAuth2** → **URL Generator**:
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Read Message History`, `View Channels`
5. Copy the generated URL → open in browser → add bot to your Discord server

### 2. Store the Bot Token

Set `DISCORD_TOKEN` as a **persistent User environment variable** (not a system/machine variable — user-level survives reboots and is accessible to detached processes):

**PowerShell:**
```powershell
[Environment]::SetEnvironmentVariable("DISCORD_TOKEN", "your-bot-token-here", "User")
```

**Verify:**
```powershell
[Environment]::GetEnvironmentVariable("DISCORD_TOKEN", "User")
# Should print your token
```

> ⚠️ **Do NOT commit the token to source control.** It's stored in the Windows registry under HKCU, not in any file.

### 3. Find Your Channel IDs

After the bot joins your server, find channel IDs by:
- Enabling Developer Mode in Discord (Settings → Advanced → Developer Mode)
- Right-clicking a channel → Copy Channel ID

Or run this after setup:
```powershell
node -e "
const{Client,GatewayIntentBits}=require(process.env.USERPROFILE+'/.copilot/tools/discordmcp/node_modules/discord.js');
const c=new Client({intents:[GatewayIntentBits.Guilds]});
c.once('ready',()=>{
  c.guilds.cache.forEach(g=>{
    console.log('Guild: '+g.name+' ('+g.id+')');
    g.channels.cache.filter(ch=>ch.type===0).forEach(ch=>console.log('  #'+ch.name+' ('+ch.id+')'));
  });
  c.destroy()
});
c.login(process.env.DISCORD_TOKEN);
"
```

---

## Installation

### Step 1: Install the Discord MCP Server

```powershell
# Create tools directory
New-Item -ItemType Directory -Path "$env:USERPROFILE\.copilot\tools" -Force

# Clone and build the Discord MCP server
cd "$env:USERPROFILE\.copilot\tools"
git clone https://github.com/v-3/discordmcp.git
cd discordmcp
npm install
npm run build

# Verify
Test-Path "$env:USERPROFILE\.copilot\tools\discordmcp\build\index.js"
# Should return True
```

### Step 2: Configure Copilot CLI MCP

Add the Discord MCP server to your Copilot CLI config. Choose one or both locations:

**User-level** (`~/.copilot/mcp-config.json`) — applies to all repos:
```json
{
  "mcpServers": {
    "discord": {
      "type": "local",
      "command": "node",
      "args": [
        "C:\\Users\\YOUR_USERNAME\\.copilot\\tools\\discordmcp\\build\\index.js"
      ],
      "env": {
        "DISCORD_TOKEN": "${DISCORD_TOKEN}"
      },
      "tools": ["*"]
    }
  }
}
```

**Repo-level** (`.copilot/mcp-config.json`) — applies to this repo only:
```json
{
  "mcpServers": {
    "discord": {
      "type": "local",
      "command": "node",
      "args": [
        "C:\\Users\\YOUR_USERNAME\\.copilot\\tools\\discordmcp\\build\\index.js"
      ],
      "env": {
        "DISCORD_TOKEN": "${DISCORD_TOKEN}"
      },
      "tools": ["*"]
    }
  }
}
```

> ⚠️ **Use absolute paths** — `${USERPROFILE}` variable expansion does not work in the `args` array. Replace `YOUR_USERNAME` with your actual Windows username.

> ⚠️ **Restart Copilot CLI** after editing MCP config files. MCP servers are loaded at session start.

### Step 3: Install the Discord Watcher (Two-Way Communication)

The watcher is a Node.js script that runs as a background daemon, polling Discord for human messages and writing them to an inbox file.

**Create the file** at `~/.copilot/tools/discordmcp/discord-watcher.cjs`:

```javascript
#!/usr/bin/env node
/**
 * Discord watcher for Squad — polls a channel for new human messages
 * and writes them to a file that the Copilot CLI session can monitor.
 *
 * Usage: node discord-watcher.cjs [--interval 10] [--channel CHANNEL_ID]
 * Env: DISCORD_TOKEN (reads from User env vars if not in process.env)
 */
const { Client, GatewayIntentBits } = require('discord.js');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function getToken() {
  if (process.env.DISCORD_TOKEN) return process.env.DISCORD_TOKEN;
  try {
    const result = execSync(
      'powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable(\'DISCORD_TOKEN\', \'User\')"',
      { encoding: 'utf8' }
    ).trim();
    if (result) return result;
  } catch {}
  throw new Error('DISCORD_TOKEN not found');
}

const DISCORD_TOKEN = getToken();
const args = process.argv.slice(2);
const intervalIdx = args.indexOf('--interval');
const channelIdx = args.indexOf('--channel');
const POLL_INTERVAL = intervalIdx !== -1 ? parseInt(args[intervalIdx + 1]) * 1000 : 10000;
const CHANNEL_ID = channelIdx !== -1 ? args[channelIdx + 1] : 'YOUR_DEFAULT_CHANNEL_ID';
const INBOX_FILE = path.join(__dirname, 'inbox.json');
const LAST_READ_FILE = path.join(__dirname, '.last-read-id');

let lastReadId = null;
try { lastReadId = fs.readFileSync(LAST_READ_FILE, 'utf8').trim(); } catch {}

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

client.once('ready', () => {
  console.log(`[Discord Watcher] Online as ${client.user.tag}`);
  console.log(`[Discord Watcher] Monitoring channel ${CHANNEL_ID} every ${POLL_INTERVAL/1000}s`);
  poll();
  setInterval(poll, POLL_INTERVAL);
});

async function poll() {
  try {
    const channel = await client.channels.fetch(CHANNEL_ID);
    const opts = { limit: 10 };
    if (lastReadId) opts.after = lastReadId;
    const messages = await channel.messages.fetch(opts);
    const humanMsgs = messages.filter(m => !m.author.bot).sort((a, b) => a.createdTimestamp - b.createdTimestamp);
    if (humanMsgs.size > 0) {
      const inbox = humanMsgs.map(m => ({
        id: m.id, author: m.author.username,
        content: m.content, timestamp: m.createdAt.toISOString()
      }));
      let existing = [];
      try { existing = JSON.parse(fs.readFileSync(INBOX_FILE, 'utf8')); } catch {}
      const allIds = new Set(existing.map(e => e.id));
      const newMsgs = inbox.filter(m => !allIds.has(m.id));
      if (newMsgs.length > 0) {
        existing.push(...newMsgs);
        fs.writeFileSync(INBOX_FILE, JSON.stringify(existing, null, 2));
        console.log(`[Discord Watcher] ${newMsgs.length} new message(s) from: ${newMsgs.map(m => m.author).join(', ')}`);
      }
      const lastMsg = humanMsgs.last();
      lastReadId = lastMsg.id;
      fs.writeFileSync(LAST_READ_FILE, lastReadId);
    }
  } catch (err) {
    console.error(`[Discord Watcher] Error: ${err.message}`);
  }
}

client.login(DISCORD_TOKEN);
```

> ⚠️ **File must be `.cjs`** (CommonJS), not `.js`. The discordmcp package uses `"type": "module"` in its `package.json`, so `.js` files are treated as ESM and `require()` won't work.

> ⚠️ **Replace `YOUR_DEFAULT_CHANNEL_ID`** with your project's default Discord channel ID.

### Step 4: Verify Everything Works

```powershell
# 1. Test the MCP server starts
$env:DISCORD_TOKEN = [Environment]::GetEnvironmentVariable("DISCORD_TOKEN", "User")
node -e "
  try { require('$($env:USERPROFILE -replace '\\','/')/.copilot/tools/discordmcp/build/index.js');
  setTimeout(()=>process.exit(0), 2000) } catch(e) { console.error(e.message); process.exit(1) }
"
# Should print: "Discord MCP Server running on stdio" and "Discord bot is ready!"

# 2. Test sending a message
node -e "
const{Client,GatewayIntentBits}=require('$($env:USERPROFILE -replace '\\','/')/.copilot/tools/discordmcp/node_modules/discord.js');
const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages]});
c.once('ready',async()=>{
  const ch=await c.channels.fetch('YOUR_CHANNEL_ID');
  await ch.send('🤖 Test message from Copilot CLI');
  console.log('Message sent!');
  c.destroy()
});
c.login(process.env.DISCORD_TOKEN);
"

# 3. Test reading messages
node -e "
const{Client,GatewayIntentBits}=require('$($env:USERPROFILE -replace '\\','/')/.copilot/tools/discordmcp/node_modules/discord.js');
const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages,GatewayIntentBits.MessageContent]});
c.once('ready',async()=>{
  const ch=await c.channels.fetch('YOUR_CHANNEL_ID');
  const msgs=await ch.messages.fetch({limit:3});
  msgs.forEach(m=>console.log('['+m.createdAt.toISOString()+'] '+m.author.username+': '+m.content.substring(0,100)));
  c.destroy()
});
c.login(process.env.DISCORD_TOKEN);
"
```

---

## Usage in Copilot CLI Sessions

### Sending Messages (Outbound)

Any Copilot agent can send a message using this one-liner:

```powershell
$token = [Environment]::GetEnvironmentVariable("DISCORD_TOKEN", "User")
$channelId = "YOUR_CHANNEL_ID"
$message = "Your message here"

node -e "const{Client,GatewayIntentBits}=require('$($env:USERPROFILE -replace '\\','/')/.copilot/tools/discordmcp/node_modules/discord.js');const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages]});c.once('ready',async()=>{const ch=await c.channels.fetch('$channelId');await ch.send(process.argv[1]);c.destroy()});c.login('$token')" $message
```

### Reading Messages (Inbound)

**One-shot read** (get recent messages):
```powershell
$token = [Environment]::GetEnvironmentVariable("DISCORD_TOKEN", "User")

node -e "
const{Client,GatewayIntentBits}=require('$($env:USERPROFILE -replace '\\','/')/.copilot/tools/discordmcp/node_modules/discord.js');
const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages,GatewayIntentBits.MessageContent]});
c.once('ready',async()=>{
  const ch=await c.channels.fetch('YOUR_CHANNEL_ID');
  const msgs=await ch.messages.fetch({limit:10});
  msgs.filter(m=>!m.author.bot).forEach(m=>console.log('['+m.createdAt.toISOString()+'] '+m.author.username+': '+m.content));
  c.destroy()
});
c.login('$token');
"
```

**Continuous monitoring** (watcher daemon):
```powershell
# Start as detached background process (survives session end)
node "$env:USERPROFILE\.copilot\tools\discordmcp\discord-watcher.cjs" --interval 10 --channel YOUR_CHANNEL_ID
# Run with: mode="async", detach=true

# Check for new messages
if (Test-Path "$env:USERPROFILE\.copilot\tools\discordmcp\inbox.json") {
    Get-Content "$env:USERPROFILE\.copilot\tools\discordmcp\inbox.json" | ConvertFrom-Json | Format-Table
    # Process messages, then clear inbox:
    Remove-Item "$env:USERPROFILE\.copilot\tools\discordmcp\inbox.json"
}
```

---

## Squad Integration

### Add to Squad Routing Rules

Add these rules to `.squad/routing.md` under `## Rules`:

```markdown
### Discord Notifications (Mandatory)

N. **Every agent MUST send Discord notifications** — Read the `squad-human-notification` skill before starting work. Agents must notify on: phase/task completion, errors blocking progress, questions needing input, and CI/pipeline results.
N+1. **Coordinator sends summary notifications** — After collecting results from agent batches, the coordinator sends a Discord summary with what completed and what's next.
N+2. **Start Discord watcher on every session** — The coordinator MUST start the Discord watcher daemon as a detached background process at the beginning of every session. Check inbox.json after every agent batch and before calling task_complete.
N+3. **Process Discord inbox like user input** — When the inbox contains messages, treat them as if the user typed them in the CLI. Acknowledge on Discord, then route the work.
```

### Add the Notification Skill

Create `.squad/skills/squad-human-notification/SKILL.md` — see the full skill file in this repo for the template. Key sections:

- **When to Notify**: Always on phase completion, errors, questions, CI results
- **How to Send**: Node.js one-liner (always works) or Discord MCP tools (when available)
- **Message Format**: `**{AgentName}: {Subject}**` + Status/Context/Next
- **Watcher Architecture**: How the two-way inbox system works

### Session Startup Checklist

At the start of every Copilot CLI session with Discord enabled:

1. **Start the Discord watcher**:
   ```powershell
   node "$env:USERPROFILE\.copilot\tools\discordmcp\discord-watcher.cjs" --interval 10
   ```
   Run as `mode: "async"`, `detach: true`.

2. **Initialize last-read marker** (first time only, or to skip old messages):
   ```powershell
   $token = [Environment]::GetEnvironmentVariable("DISCORD_TOKEN", "User")
   node -e "
   const{Client,GatewayIntentBits}=require(process.env.USERPROFILE+'/.copilot/tools/discordmcp/node_modules/discord.js');
   const fs=require('fs');
   const c=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages,GatewayIntentBits.MessageContent]});
   c.once('ready',async()=>{
     const ch=await c.channels.fetch('YOUR_CHANNEL_ID');
     const msgs=await ch.messages.fetch({limit:1});
     const latest=msgs.first();
     if(latest){fs.writeFileSync(process.env.USERPROFILE+'/.copilot/tools/discordmcp/.last-read-id',latest.id);
     console.log('Marked last read: '+latest.id)}
     c.destroy()
   });
   c.login('$token');
   "
   ```

3. **Send a "session started" notification** to Discord so the user knows the bot is listening.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Discord Server                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │ #project-channel                                │    │
│  │   Human: "Please fix the login bug"             │    │
│  │   Bot: "🔧 Ripley: Working on login fix..."     │    │
│  │   Human: "Also check the API timeout"           │    │
│  │   Bot: "✅ Login fix complete, checking API..."  │    │
│  └──────────────┬───────────────────▲──────────────┘    │
└─────────────────┼───────────────────┼───────────────────┘
                  │ polls every 10s   │ sends messages
                  ▼                   │
┌─────────────────────────────────────────────────────────┐
│  discord-watcher.cjs (detached background process)      │
│  - Polls channel for human (non-bot) messages           │
│  - Writes new messages to inbox.json                    │
│  - Tracks last-read-id to avoid duplicates              │
└──────────────┬──────────────────────────────────────────┘
               │ writes
               ▼
┌──────────────────────────┐
│  ~/.copilot/tools/       │
│    discordmcp/           │
│      inbox.json          │◄── Coordinator reads after each agent batch
│      .last-read-id       │
│      build/index.js      │◄── MCP server (loaded by Copilot at session start)
│      node_modules/       │◄── discord.js (used by watcher + send scripts)
└──────────────────────────┘
               ▲
               │ reads inbox, sends via node one-liner
┌──────────────────────────────────────────────────────────┐
│  Copilot CLI Session                                     │
│  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ Squad Coordinator │──│ Spawned Agents               │  │
│  │ - Checks inbox   │  │ - Send Discord notifications │  │
│  │ - Routes work    │  │ - Report status/errors       │  │
│  │ - Acknowledges   │  │ - Ask questions on Discord   │  │
│  └──────────────────┘  └──────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## File Reference

| File | Location | Purpose |
|------|----------|---------|
| `discordmcp/` | `~/.copilot/tools/` | Discord MCP server (cloned from v-3/discordmcp) |
| `discordmcp/build/index.js` | `~/.copilot/tools/` | MCP server entry point (stdio protocol) |
| `discordmcp/discord-watcher.cjs` | `~/.copilot/tools/` | Background watcher daemon |
| `discordmcp/inbox.json` | `~/.copilot/tools/` | Queued human messages (created by watcher) |
| `discordmcp/.last-read-id` | `~/.copilot/tools/` | Last processed Discord message ID |
| `mcp-config.json` | `~/.copilot/` | User-level MCP config (all repos) |
| `mcp-config.json` | `.copilot/` (repo) | Repo-level MCP config (this repo only) |
| `SKILL.md` | `.squad/skills/squad-human-notification/` | Agent notification skill |

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Discord MCP tools not appearing | MCP config uses `${USERPROFILE}` in args | Use absolute path instead |
| Discord MCP tools not appearing | Session started before config was saved | Restart Copilot CLI session |
| `TokenInvalid` error | `DISCORD_TOKEN` not in environment | Set as User env var (see Prerequisites) |
| Watcher crashes with `require is not defined` | File has `.js` extension | Rename to `.cjs` (CommonJS) |
| Watcher doesn't pick up messages | `Message Content Intent` not enabled | Enable in Discord Developer Portal → Bot |
| Watcher picks up old messages | `.last-read-id` not initialized | Run the initialization script (see Session Startup) |
| Bot can't see channels | Bot not added to server | Re-generate OAuth2 URL and add bot |
| `${DISCORD_TOKEN}` is empty in detached process | Detached processes don't inherit env vars | Watcher uses `getToken()` fallback to read from User env |

## Limitations

1. **Session-scoped watcher**: The watcher daemon runs per-session. Between Copilot CLI sessions, messages queue in Discord and are picked up when the next session starts the watcher.
2. **Polling, not real-time**: The watcher polls every N seconds (default: 10). There's a slight delay between a Discord message and the agent seeing it.
3. **Single channel**: The watcher monitors one channel at a time. Use `--channel` to change the target.
4. **Windows-only token fallback**: The `getToken()` function uses PowerShell to read User env vars, which is Windows-specific. On macOS/Linux, ensure `DISCORD_TOKEN` is exported in the shell environment.
