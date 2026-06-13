# =============================================================================
# Channel Backup Storage
# =============================================================================

locals {
  backup_storage_account_name = (
    var.backup_storage_account_name != ""
    ? var.backup_storage_account_name
    : replace("st${local.name_prefix}bak", "-", "")
  )
}

module "backup_storage" {
  source = "../../modules/storage"

  name                = local.backup_storage_account_name
  resource_group_name = module.shared.resource_group_name
  location            = module.shared.resource_group_location

  # LRS keeps this cheap; the primary production storage account remains GRS.
  account_replication_type = var.backup_storage_replication_type

  containers = [
    { name = var.backup_container_name }
  ]

  tags = merge(local.common_tags, {
    DataRole = "channel-backups"
  })
}

resource "azurerm_log_analytics_workspace" "backup_jobs" {
  name                = "law-${local.name_prefix}-backup"
  resource_group_name = module.shared.resource_group_name
  location            = module.shared.resource_group_location
  sku                 = "PerGB2018"
  retention_in_days   = var.backup_job_log_retention_days

  tags = merge(local.common_tags, {
    DataRole = "channel-backups"
  })
}

resource "azurerm_container_app_environment" "backup_jobs" {
  name                       = "cae-${local.name_prefix}-backup"
  resource_group_name        = module.shared.resource_group_name
  location                   = module.shared.resource_group_location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.backup_jobs.id

  tags = merge(local.common_tags, {
    DataRole = "channel-backups"
  })
}

resource "azurerm_user_assigned_identity" "backup_job" {
  name                = "id-${local.name_prefix}-backup-job"
  resource_group_name = module.shared.resource_group_name
  location            = module.shared.resource_group_location

  tags = merge(local.common_tags, {
    DataRole = "channel-backups"
  })
}

resource "azurerm_role_assignment" "backup_job_live_storage_reader" {
  scope                = module.storage.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.backup_job.principal_id
}

resource "azurerm_role_assignment" "backup_job_backup_storage_contributor" {
  scope                = module.backup_storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.backup_job.principal_id
}

resource "azurerm_role_assignment" "backup_job_acr_pull" {
  scope                = data.azurerm_container_registry.shared.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.backup_job.principal_id
}

resource "azurerm_role_assignment" "backup_job_key_vault_reader" {
  scope                = module.shared.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.backup_job.principal_id
}

resource "azurerm_container_app_job" "nightly_backup" {
  name                         = "caj-${local.name_prefix}-backup"
  resource_group_name          = module.shared.resource_group_name
  location                     = module.shared.resource_group_location
  container_app_environment_id = azurerm_container_app_environment.backup_jobs.id
  replica_retry_limit          = 1
  replica_timeout_in_seconds   = var.backup_job_timeout_seconds

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.backup_job.id]
  }

  registry {
    server   = data.azurerm_container_registry.shared.login_server
    identity = azurerm_user_assigned_identity.backup_job.id
  }

  secret {
    name                = "database-url"
    key_vault_secret_id = azurerm_key_vault_secret.secrets["sql-connection-string"].versionless_id
    identity            = azurerm_user_assigned_identity.backup_job.id
  }

  schedule_trigger_config {
    cron_expression          = var.backup_schedule_cron_expression
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "backup"
      image   = "${data.azurerm_container_registry.shared.login_server}/yt-summarizer-workers:${var.backup_worker_image_tag}"
      command = ["python", "-m", "backup.nightly"]
      cpu     = 0.5
      memory  = "1Gi"

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }

      env {
        name  = "ENVIRONMENT"
        value = "production"
      }

      env {
        name  = "AZURE_STORAGE_USE_MANAGED_IDENTITY"
        value = "true"
      }

      env {
        name  = "AZURE_STORAGE_ACCOUNT_URL"
        value = module.storage.primary_blob_endpoint
      }

      env {
        name  = "BACKUP_STORAGE_USE_MANAGED_IDENTITY"
        value = "true"
      }

      env {
        name  = "AZURE_BACKUP_STORAGE_ACCOUNT_URL"
        value = module.backup_storage.primary_blob_endpoint
      }

      env {
        name  = "BACKUP_CHANNELS"
        value = join(",", var.backup_channels)
      }

      env {
        name  = "BACKUP_CONTAINER_NAME"
        value = var.backup_container_name
      }

      env {
        name  = "PYTHONUNBUFFERED"
        value = "1"
      }
    }
  }

  tags = merge(local.common_tags, {
    DataRole = "channel-backups"
  })

  depends_on = [
    azurerm_role_assignment.backup_job_acr_pull,
    azurerm_role_assignment.backup_job_backup_storage_contributor,
    azurerm_role_assignment.backup_job_key_vault_reader,
    azurerm_role_assignment.backup_job_live_storage_reader,
  ]
}

resource "azurerm_storage_management_policy" "backup_storage" {
  storage_account_id = module.backup_storage.id

  rule {
    name    = "delete-old-snapshot-metadata"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
      prefix_match = [
        "${var.backup_container_name}/reports/",
        "${var.backup_container_name}/snapshots/",
      ]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.backup_snapshot_retention_days
      }

      version {
        delete_after_days_since_creation = var.backup_blob_version_retention_days
      }
    }
  }

  rule {
    name    = "delete-old-mirror-versions"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["${var.backup_container_name}/mirror/"]
    }

    actions {
      version {
        delete_after_days_since_creation = var.backup_blob_version_retention_days
      }
    }
  }
}
