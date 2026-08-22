output "vpc_id" {
  value = aws_vpc.trial.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}

output "trial_ec2_instance_ids" {
  value = aws_instance.trial[*].id
}

output "trial_ec2_private_ips" {
  description = "Private IP만 존재 (public IP 없음). 접속은 SSM Session Manager로."
  value       = aws_instance.trial[*].private_ip
}

output "ssm_connect_command" {
  description = "인스턴스별 SSM 접속 명령어 예시"
  value       = [for id in aws_instance.trial[*].id : "aws ssm start-session --target ${id}"]
}

output "canary_file_path" {
  description = "Host Canary 파일 경로 (auditd -w 규칙 대상). SSM 접속 후 /opt/trial/scripts/check_canary.sh 실행해서 확인"
  value       = var.canary_file_path
}

output "golden_ami_id" {
  description = "create_golden_ami = true로 apply한 경우에만 값이 생김"
  value       = try(aws_ami_from_instance.golden[0].id, null)
}

output "backend_ecr_repository_url" {
  description = "대시보드 배포 컨트롤러가 백엔드 이미지를 push할 ECR URL"
  value       = aws_ecr_repository.agent_backend.repository_url
}

output "environment_id" {
  value = var.environment_id
}

output "created_by" {
  value = var.created_by
}

output "backend_local_port" {
  description = "SSM Port Forwarding의 원격 대상 포트"
  value       = 8000
}

output "backend_ssm_port_forward_commands" {
  description = "로컬 제어 백엔드를 유지한 채 원격 백엔드를 localhost:8001로 연결하는 명령"
  value = [
    for id in aws_instance.trial[*].id :
    "aws ssm start-session --target ${id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8000,localPortNumber=8001 --region ${var.aws_region} --profile whs-team"
  ]
}
