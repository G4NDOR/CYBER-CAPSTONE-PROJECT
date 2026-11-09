output "bastion_public_ipv4" {
  description = "Public IPv4 address of the Bastion jump host"
  value       = aws_instance.bastion.public_ip
}

output "app_node_private_ipv4" {
  description = "Internal IPv4 of the app node (reachable only via Bastion)"
  value       = aws_instance.app_node.private_ip
}

output "app_node_ipv6" {
  description = "Direct routable IPv6 address of the app node"
  value       = aws_instance.app_node.ipv6_addresses[0]
}

output "ssh_jump_command" {
  description = "One-liner command to SSH into the private node through the bastion"
  value       = "ssh -J ubuntu@${aws_instance.bastion.public_ip} ubuntu@${aws_instance.app_node.private_ip} -i ~/.ssh/capstone_aws_key"
}