# =============================================================================
# AKS Single-Node Cluster Module
# =============================================================================
# Creates an Azure Kubernetes Service cluster optimized for cost
# with ACR pull integration for container deployments

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "name" {
  description = "Name of the AKS cluster"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "dns_prefix" {
  description = "DNS prefix for the cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "node_pool_name" {
  description = "Name of the default node pool"
  type        = string
  default     = "system2"
}

variable "node_count" {
  description = "Number of nodes in the default pool"
  type        = number
  default     = 1
}

variable "node_vm_size" {
  description = "VM size for nodes"
  type        = string
  default     = "Standard_B4als_v2"  # 4 vCPUs, 8GB RAM, ~$97/month
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB"
  type        = number
  default     = 30
}

variable "max_pods" {
  description = "Maximum number of pods per node"
  type        = number
  default     = 100
}

variable "acr_id" {
  description = "ID of the Azure Container Registry to attach"
  type        = string
  default     = null
}

variable "attach_acr" {
  description = "Whether to attach ACR to the cluster"
  type        = bool
  default     = false
}

variable "enable_workload_identity" {
  description = "Enable Workload Identity for pod-managed Azure access"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Resources
# -----------------------------------------------------------------------------

resource "azurerm_kubernetes_cluster" "aks" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.dns_prefix
  kubernetes_version  = var.kubernetes_version

  # Enable OIDC issuer for Workload Identity
  oidc_issuer_enabled       = var.enable_workload_identity
  workload_identity_enabled = var.enable_workload_identity

  # Single-node pool for cost optimization
  default_node_pool {
    name                 = var.node_pool_name
    node_count           = var.node_count
    vm_size              = var.node_vm_size
    os_disk_size_gb      = var.os_disk_size_gb
    max_pods             = var.max_pods
    auto_scaling_enabled = false  # Renamed from enable_auto_scaling in azurerm 4.x
  }

  # Managed identity for AAD integration
  identity {
    type = "SystemAssigned"
  }

  # Network configuration
  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
    outbound_type     = "loadBalancer"
  }

  tags = var.tags

  # Ignore Azure-managed attributes that would cause cluster replacement
  lifecycle {
    ignore_changes = [
      # Azure-managed add-ons and features
      azure_policy_enabled,
      http_application_routing_enabled,
      local_account_disabled,
      open_service_mesh_enabled,
      custom_ca_trust_certificates_base64,
      cost_analysis_enabled,

      # Azure-managed networking
      kubelet_identity,
      network_profile[0].load_balancer_profile[0].effective_outbound_ips,
      network_profile[0].load_balancer_profile[0].managed_outbound_ip_count,
      network_profile[0].load_balancer_profile[0].idle_timeout_in_minutes,
      network_profile[0].load_balancer_profile[0].managed_outbound_ipv6_count,
      network_profile[0].load_balancer_profile[0].outbound_ip_address_ids,
      network_profile[0].load_balancer_profile[0].outbound_ip_prefix_ids,
      network_profile[0].load_balancer_profile[0].outbound_ports_allocated,
      network_profile[0].load_balancer_profile[0].backend_pool_type,

      # Azure-managed node provisioning
      node_provisioning_profile,

      # Azure-managed node pool defaults
      default_node_pool[0].tags,
      default_node_pool[0].zones,
      default_node_pool[0].node_public_ip_enabled,
      default_node_pool[0].fips_enabled,
      default_node_pool[0].host_encryption_enabled,
      default_node_pool[0].only_critical_addons_enabled,
      default_node_pool[0].max_count,
      default_node_pool[0].min_count,
      default_node_pool[0].upgrade_settings,

      # Azure-managed identity defaults
      identity[0].identity_ids,
    ]
  }
}

# Grant AKS access to pull images from ACR
resource "azurerm_role_assignment" "acr_pull" {
  count                = var.attach_acr ? 1 : 0
  principal_id         = try(azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id, null)
  role_definition_name = "AcrPull"
  scope                = var.acr_id
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "id" {
  description = "The ID of the AKS cluster"
  value       = azurerm_kubernetes_cluster.aks.id
}

output "name" {
  description = "The name of the AKS cluster"
  value       = azurerm_kubernetes_cluster.aks.name
}

output "fqdn" {
  description = "The FQDN of the AKS cluster"
  value       = azurerm_kubernetes_cluster.aks.fqdn
}

output "kube_config_raw" {
  description = "Raw kubeconfig for the cluster"
  value       = azurerm_kubernetes_cluster.aks.kube_config_raw
  sensitive   = true
}

output "host" {
  description = "The Kubernetes API server endpoint"
  value       = azurerm_kubernetes_cluster.aks.kube_config[0].host
}

output "client_certificate" {
  description = "Base64 encoded client certificate"
  value       = azurerm_kubernetes_cluster.aks.kube_config[0].client_certificate
  sensitive   = true
}

output "client_key" {
  description = "Base64 encoded client key"
  value       = azurerm_kubernetes_cluster.aks.kube_config[0].client_key
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "Base64 encoded cluster CA certificate"
  value       = azurerm_kubernetes_cluster.aks.kube_config[0].cluster_ca_certificate
  sensitive   = true
}

output "kubelet_identity_object_id" {
  description = "Object ID of the kubelet managed identity"
  value       = try(azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id, null)
}

output "identity_principal_id" {
  description = "Principal ID of the cluster managed identity"
  value       = azurerm_kubernetes_cluster.aks.identity[0].principal_id
}

output "oidc_issuer_url" {
  description = "OIDC issuer URL for Workload Identity federation"
  value       = azurerm_kubernetes_cluster.aks.oidc_issuer_url
}
