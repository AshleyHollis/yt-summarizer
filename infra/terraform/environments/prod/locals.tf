# =============================================================================
# Local Variables
# =============================================================================

locals {
  environment = "prod"
  name_prefix = "ytsumm-prd"

  common_tags = {
    Environment = local.environment
    Project     = "yt-summarizer"
    ManagedBy   = "terraform"
  }
}
