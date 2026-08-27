aws_region           = "us-east-1"
availability_zone    = "us-east-1a"
instance_type        = "t3.small"
root_volume_size_gib = 30

# AMI ID와 이미지 digest, Vector SHA-256은 환경 생성 시 비추적 terraform.tfvars
# 또는 안전한 배포 입력으로 반드시 고정한다.
