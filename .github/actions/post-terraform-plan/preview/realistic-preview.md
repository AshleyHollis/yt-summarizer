<!-- terraform-plan-comment -->

# ✅ Terraform Plan

> 📋 **Run [#42](https://github.com/AshleyHollis/yt-summarizer/actions/runs/12345)** · 2026-01-13 08:48:50 UTC · @developer

![add](https://img.shields.io/badge/add-7-2eb039?style=flat-square) ![change](https://img.shields.io/badge/change-12-d4a017?style=flat-square) ![destroy](https://img.shields.io/badge/destroy-1-c62b2b?style=flat-square)

```diff
+ 7 to add
! 12 to change
- 1 to destroy
```


### ➕ Resources to Create · 7


<details>
<summary>🟢 <code>module.github_oidc.azuread_application.github_actions</code></summary>

```diff
+ resource "azuread_application" "github_actions" {
      description = "Service principal for GitHub Actions OIDC authentication"
      display_name = "GitHub Actions OIDC"
      sign_in_audience = "AzureADMyOrg"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azuread_application_federated_identity_credential.main</code></summary>

```diff
+ resource "azuread_application_federated_identity_credential" "main" {
       audiences = ["api://AzureADTokenExchange"]
      description = "Federated credential for main branch"
      display_name = "github-oidc-main"
      issuer = "https://token.actions.githubusercontent.com"
      subject = "repo:AshleyHollis/yt-summarizer:ref:refs/heads/main"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azuread_application_federated_identity_credential.production</code></summary>

```diff
+ resource "azuread_application_federated_identity_credential" "production" {
       audiences = ["api://AzureADTokenExchange"]
      description = "Federated credential for production environment"
      display_name = "github-oidc-production"
      issuer = "https://token.actions.githubusercontent.com"
      subject = "repo:AshleyHollis/yt-summarizer:environment:production"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azuread_application_federated_identity_credential.pull_request</code></summary>

```diff
+ resource "azuread_application_federated_identity_credential" "pull_request" {
       audiences = ["api://AzureADTokenExchange"]
      description = "Federated credential for pull requests"
      display_name = "github-oidc-pull-request"
      issuer = "https://token.actions.githubusercontent.com"
      subject = "repo:AshleyHollis/yt-summarizer:pull_request"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azuread_service_principal.github_actions</code></summary>

```diff
+ resource "azuread_service_principal" "github_actions" {
      description = "Service principal for GitHub Actions"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azurerm_role_assignment.acr_push[0]</code></summary>

```diff
+ resource "azurerm_role_assignment" "acr_push" {
      role_definition_name = "AcrPush"
      scope = "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/yt-summarizer-rg/providers/Microsoft.ContainerRegistry/registries/ytsummarizerregistry"
}
```

</details>

<details>
<summary>🟢 <code>module.github_oidc.azurerm_role_assignment.contributor[0]</code></summary>

```diff
+ resource "azurerm_role_assignment" "contributor" {
      role_definition_name = "Contributor"
      scope = "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/yt-summarizer-rg"
}
```

</details>


### 🔄 Resources to Replace · 1


<details>
<summary>🟣 <code>module.cdn.azurerm_cdn_profile.profile</code></summary>

```diff
-/+ resource "azurerm_cdn_profile" "profile" {
    # forces replacement
!!     sku = "Standard_Verizon" -> "Standard_Microsoft"
}
```

</details>


### ✏️ Resources to Update · 11


<details>
<summary>🟡 <code>module.acr.azurerm_container_registry.acr</code></summary>

```diff
~ resource "azurerm_container_registry" "acr" {
!     sku = "Basic" -> "Standard"
!     tags {
+         managed-by = "terraform"
!     }
}
```

</details>

<details>
<summary>🟡 <code>module.aks.azurerm_kubernetes_cluster.aks</code></summary>

```diff
~ resource "azurerm_kubernetes_cluster" "aks" {
!     default_node_pool {
!         node_count = 2 -> 3
!     }
!     kubernetes_version = "1.28.5" -> "1.29.0"
}
```

</details>

<details>
<summary>🟡 <code>module.key_vault.azurerm_key_vault_secret.secrets["sql-connection-string"]</code></summary>

```diff
~ resource "azurerm_key_vault_secret" "secrets" {
!     content_type = "text/plain" -> "application/x-connection-string"
!     expiration_date = null -> "2025-12-31T23:59:59Z"
}
```

</details>

<details>
<summary>🟡 <code>module.sql.azurerm_mssql_database.database</code></summary>

```diff
~ resource "azurerm_mssql_database" "database" {
!     max_size_gb = 2 -> 10
!     sku_name = "Basic" -> "S0"
!     storage_account_type = "Local" -> "Geo"
}
```

</details>

<details>
<summary>🟡 <code>module.sql.azurerm_mssql_server.server</code></summary>

```diff
~ resource "azurerm_mssql_server" "server" {
!     minimum_tls_version = "1.0" -> "1.2"
!     public_network_access_enabled = true -> false
}
```

</details>

<details>
<summary>🟡 <code>module.storage.azurerm_storage_account.storage</code></summary>

```diff
~ resource "azurerm_storage_account" "storage" {
!     account_replication_type = "LRS" -> "GRS"
}
```

</details>

<details>
<summary>🟡 <code>module.storage.azurerm_storage_container.containers["embeddings"]</code></summary>

```diff
~ resource "azurerm_storage_container" "containers" {
!     container_access_type = "private" -> "blob"
}
```

</details>

<details>
<summary>🟡 <code>module.storage.azurerm_storage_container.containers["summaries"]</code></summary>

```diff
~ resource "azurerm_storage_container" "containers" {
!     container_access_type = "private" -> "blob"
}
```

</details>

<details>
<summary>🟡 <code>module.storage.azurerm_storage_container.containers["transcripts"]</code></summary>

```diff
~ resource "azurerm_storage_container" "containers" {
!     container_access_type = "private" -> "blob"
}
```

</details>

<details>
<summary>🟡 <code>module.storage.azurerm_storage_queue.queues["embed-queue"]</code></summary>

```diff
~ resource "azurerm_storage_queue" "queues" {
+     metadata {
+         purpose = "embedding-jobs"
+     }
}
```

</details>

<details>
<summary>🟡 <code>module.swa.azurerm_static_web_app.swa</code></summary>

```diff
~ resource "azurerm_static_web_app" "swa" {
!     sku_size = "Free" -> "Standard"
!     sku_tier = "Free" -> "Standard"
}
```

</details>


### 🗑️ Resources to Destroy · 1


<details>
<summary>🔴 <code>module.key_vault.azurerm_role_assignment.secrets_officer[0]</code></summary>

```diff
- resource "azurerm_role_assignment" "secrets_officer" {
      scope = "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/yt-summarizer-rg/providers/Microsoft.KeyVault/vaults/ytsummarizerkv"
}
```

</details>

---
<sub>🔗 [View full workflow run](https://github.com/AshleyHollis/yt-summarizer/actions/runs/12345)</sub>
