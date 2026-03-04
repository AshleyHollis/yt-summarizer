# =============================================================================
# Azure Storage (Blob + Queue)
# =============================================================================

module "storage" {
  source = "../../modules/storage"

  name                = replace("st${local.name_prefix}", "-", "")
  resource_group_name = module.shared.resource_group_name
  location            = module.shared.resource_group_location

  # Use GRS for production data protection
  account_replication_type = "GRS"

  containers = [
    { name = "transcripts" },
    { name = "summaries" },
    { name = "embeddings" }
  ]

  queues = [
    "transcribe-queue",
    "summarize-queue",
    "embed-queue",
    "relationships-queue"
  ]

  tags = local.common_tags
}
