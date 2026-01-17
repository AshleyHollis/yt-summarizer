# =============================================================================
# GitHub Actions OIDC
# =============================================================================
# Creates Azure AD app registration and federated credentials for CI/CD

module "github_oidc" {
  source = "../../modules/github-oidc"

  github_organization     = "AshleyHollis"
  github_repository       = "yt-summarizer"
  assign_contributor_role = false
  acr_id                  = ""

  tags = local.common_tags
}
