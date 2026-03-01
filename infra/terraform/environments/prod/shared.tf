# In environments/prod/shared.tf (new file)
module "shared" {
  source = "git::https://github.com/AshleyHollis/shared-infra.git//terraform/modules/shared-infra-data?ref=v1"
}
