# Copilot Agent Instructions

## Aspire Background Wrapper

This repository includes a wrapper script at `tools\aspire.cmd` that detaches the Aspire process into a separate window. This prevents the VS Code agent from killing long-running Aspire processes when it executes subsequent terminal commands.

### Usage Guidelines

- **Do not run long-lived servers in foreground** - they will be killed when the next terminal command runs.
- **Running `aspire run` is safe** - the repo wrapper automatically detaches the process.
- **Verify Aspire is running** by checking the log file:
  ```powershell
  Get-Content aspire.log -Tail 50
  ```
- The wrapper logs all Aspire output to `aspire.log` in the repository root.
- If you need to stop Aspire, close the detached "Aspire" command window or use Task Manager.

### How It Works

The `tools\aspire.cmd` wrapper:
1. Locates the real `aspire` executable on PATH (skipping itself)
2. Launches Aspire in a detached window using `start`
3. Redirects output to `aspire.log` for debugging
4. Returns control immediately so the agent can continue

The VS Code terminal PATH is configured to resolve `tools\` first, so `aspire` commands use the wrapper automatically.
