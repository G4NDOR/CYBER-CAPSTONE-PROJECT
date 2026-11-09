variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Project name prefix for tags and resources"
  type        = string
  default     = "ortsoc-alert-enrichment"
}

variable "bastion_instance_type" {
  description = "Low-cost compute for bastion host"
  type        = string
  default     = "t3.micro" # Free-tier eligible
}

variable "app_node_instance_type" {
  description = "Compute instance for k3s cluster and microservices"
  type        = string
  default     = "t3.small" # 2 vCPU, 2GB RAM (enough for k3s + containers)
}

variable "admin_ssh_key_path" {
  description = "Path to the local public key"
  type        = string
  default     = "~/.ssh/capstone_aws_key.pub"
}

variable "allowed_admin_ipv4" {
  description = "List of public IPv4 CIDRs allowed to SSH into Bastion"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Optional change to ["MY_IP/32"] for strict security
}