  #!/usr/bin/env pwsh
  # fetch-yt-summarizer-secrets.ps1
  # Run on your local machine to collect the secrets needed for VPS dev setup.
  # Requires: az CLI logged in, gh CLI logged in (optional)

  $KV = "kv-ytsumm-prd-ci"

  Write-Host "`n=== Fetching from Azure Key Vault: $KV ===`n"

  $secrets = @{
      "azure-openai-embedding-deployment" = "azure-openai-embedding-deployment"
      "openai-api-key"                    = "openai-api-key"
      "auth0-domain"                      = "auth0-domain"
      "auth0-client-id"                   = "auth0-client-id"
      "auth0-client-secret"               = "auth0-client-secret"
      "auth0-session-secret"              = "auth0-session-secret"
  }

  $results = @{}

  foreach ($param in $secrets.Keys) {
      $kvKey = $secrets[$param]
      try {
          $value = az keyvault secret show --vault-name $KV --name $kvKey --query "value" -o tsv 2>$null
          if ($value) {
              $results[$param] = $value
              Write-Host "  [OK] $param"
          } else {
              Write-Host "  [MISSING] $param - not in Key Vault, checking env vars..."
          }
      } catch {
          Write-Host "  [ERROR] $param - $_"
      }
  }

  # Fallback: check environment variables
  $envMappings = @{
      "openai-api-key"                    = @("OPENAI_API_KEY")
      "azure-openai-embedding-deployment" = @("AZURE_OPENAI_EMBEDDING_DEPLOYMENT")
      "auth0-domain"                      = @("AUTH0_ISSUER_BASE_URL", "AUTH0_DOMAIN")
      "auth0-client-id"                   = @("AUTH0_CLIENT_ID")
      "auth0-client-secret"               = @("AUTH0_CLIENT_SECRET")
      "auth0-session-secret"              = @("AUTH0_SECRET", "AUTH0_SESSION_SECRET")
  }

  foreach ($param in $envMappings.Keys) {
      if (-not $results.ContainsKey($param)) {
          foreach ($envVar in $envMappings[$param]) {
              $value = [System.Environment]::GetEnvironmentVariable($envVar)
              if ($value) {
                  $results[$param] = $value
                  Write-Host "  [ENV] $param (from `$$envVar)"
                  break
              }
          }
      }
  }

  # Output the dotnet user-secrets commands
  Write-Host "`n=== dotnet user-secrets commands (run these on the VPS) ===`n"
  Write-Host "cd /home/openclaw/dev/yt-summarizer/services/aspire/AppHost"
  Write-Host "export DOTNET_ROOT=`$HOME/.dotnet PATH=`$PATH:`$HOME/.dotnet:`$HOME/.dotnet/tools`n"

  foreach ($param in $results.Keys) {
      $value = $results[$param]
      Write-Host "dotnet user-secrets set `"Parameters:$param`" `"$value`""
  }

  $missing = $secrets.Keys | Where-Object { -not $results.ContainsKey($_) }
  if ($missing) {
      Write-Host "`n=== Still missing (find manually) ==="
      $missing | ForEach-Object { Write-Host "  $_" }
  }