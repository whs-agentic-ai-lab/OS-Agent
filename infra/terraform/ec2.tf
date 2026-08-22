# 실험용 EC2 인스턴스. 지금은 기본 우분투 이미지 + Docker만 올린다.
# Agent/Gateway 같은 애플리케이션은 여기서 만들지 않고, 나중에 별도로 배포한다.

# AWS가 공식으로 관리하는 SSM Public Parameter에서 최신 Ubuntu 24.04 AMI ID를 가져온다.
# (AWS 계정별 owners ID로 aws_ami를 필터링하는 대신, AWS가 직접 갱신하는 값을 그대로 사용)
data "aws_ssm_parameter" "ubuntu_2404_amd64" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

resource "aws_instance" "trial" {
  count = var.trial_ec2_count # 한 번에 EC2 한 대만 사용

  lifecycle {
    precondition {
      condition     = var.backend_image_uri != ""
      error_message = "전체 환경 배포 전에 backend_image_uri가 필요합니다. 배포 컨트롤러를 사용하세요."
    }
  }

  ami                    = var.golden_ami_id != "" ? var.golden_ami_id : data.aws_ssm_parameter.ubuntu_2404_amd64.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.trial_ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.trial_ec2.name

  # public IP 없음
  associate_public_ip_address = false

  # EBS 암호화 + 인스턴스 삭제 시 볼륨도 같이 삭제
  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_size           = 20
    volume_type           = "gp3"
  }

  metadata_options {
    http_tokens                 = "required" # IMDSv2 강제 (메타데이터 탈취 방지)
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1 # 컨테이너 등 한 홉 너머로 메타데이터 응답이 전달되지 않도록 제한
    instance_metadata_tags      = "disabled"
  }

  # EC2가 처음 부팅될 때 자동 실행되는 스크립트.
  # Docker/auditd 설치 + 권한 감시 규칙 등록 + Canary 파일 생성까지 여기서 끝낸다.
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    canary_file_path  = var.canary_file_path
    aws_region        = var.aws_region
    backend_image_uri = var.backend_image_uri
    ecr_registry      = split("/", aws_ecr_repository.agent_backend.repository_url)[0]
    runtime_compose_b64 = base64encode(templatefile("${path.module}/runtime-compose.yml.tpl", {
      backend_image_uri = var.backend_image_uri
    }))
    baseline_compose_b64 = base64encode(file("${path.module}/compose/docker-compose.yml"))
    mount_rw_compose_b64 = base64encode(file("${path.module}/compose/docker-compose.override.mount-rw.yml"))
  })

  # user_data 내용이 바뀌면 (예: auditd 규칙 추가) 수동으로 -replace를 안 해도
  # terraform apply가 알아서 인스턴스를 재생성한다.
  user_data_replace_on_change = true

  # EC2가 부팅하자마자 user_data가 돌아가는데, 그 안에서 인터넷 접속(apt/docker pull)과
  # SSM 등록이 필요하다. NAT 경로와 SSM 관리 권한이 EC2보다 먼저 준비되어 있어야
  # 부트스트랩이 안전하게 성공한다 — 암묵적 참조만으로는 이 순서가 보장 안 돼서 명시한다.
  depends_on = [
    aws_route.private_via_nat,
    aws_iam_role_policy_attachment.ssm_core,
    aws_iam_role_policy.backend_ecr_pull,
  ]

  tags = {
    Name          = "${var.project_name}-ec2-${count.index}"
    EnvironmentId = var.environment_id
    CreatedBy     = var.created_by
    OwnerArn      = var.owner_arn
  }
}
