module "shared" {
  source = "git::https://github.com/AshleyHollis/shared-infra.git//terraform/modules/shared-infra-data?ref=v2"

  resource_group_name = "rg-ytsumm-prd"
  key_vault_name      = "kv-ytsumm-prd"
}
