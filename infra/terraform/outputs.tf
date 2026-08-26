output "vpc_id" {
  value = aws_vpc.trial.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}

output "trial_ec2_instance_id" {
  value = aws_instance.trial.id
}

output "trial_ec2_private_ip" {
  description = "Public IP는 없으며 접속은 SSM만 사용한다."
  value       = aws_instance.trial.private_ip
}

output "ssm_connect_command" {
  value = join(" ", compact([
    "aws ssm start-session --target ${aws_instance.trial.id}",
    "--region ${var.aws_region}",
    var.aws_profile == "" ? "" : "--profile ${var.aws_profile}",
  ]))
}

output "ecr_repository_urls" {
  value = {
    for name, repository in aws_ecr_repository.images : name => repository.repository_url
  }
}

output "topology_revision" {
  value = local.topology_revision
}

output "topology_action_path_ids" {
  value = sort(keys(local.topology.action_paths))
}

output "expected_linux_users" {
  value = [local.u1.name, local.u2.name]
}

output "expected_containers" {
  value = [
    local.topology.containers.C1.container_name,
    local.topology.containers.C2.container_name,
    local.topology.containers.C3.container_name,
  ]
}

output "remote_evidence_sink_enabled" {
  value = var.enable_remote_evidence_sink
}
