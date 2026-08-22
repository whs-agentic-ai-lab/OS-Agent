variable "aws_region" {
  description = "Sandbox 계정에서 사용할 리전"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "~/.aws/credentials에 등록해둔 AWS CLI 프로필 이름 (팀 공용 계정용 IAM 사용자 Access Key를 이 프로필로 등록). 비워두면 기본 프로필/환경변수(AWS_PROFILE 등)를 그대로 씀"
  type        = string
  default     = ""
}

variable "project_name" {
  description = "IAM/SSO 소유자와 사용자가 입력한 환경 이름을 조합한 리소스 접두사"
  type        = string
  default     = "trial"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,49}$", var.project_name))
    error_message = "project_name은 3~50자의 영문 소문자, 숫자, 하이픈이어야 합니다."
  }
}

variable "environment_id" {
  description = "대시보드와 AWS 인벤토리에서 환경을 식별하는 고유 ID"
  type        = string
  default     = "trial"
}

variable "created_by" {
  description = "환경을 생성한 IAM/SSO 표시 이름"
  type        = string
  default     = "unknown"
}

variable "owner_arn" {
  description = "환경을 생성한 AWS principal ARN"
  type        = string
  default     = "unknown"
}

variable "vpc_cidr" {
  description = "실험 전용 VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "private_subnet_cidr" {
  description = "Trial EC2가 위치할 Private Subnet CIDR"
  type        = string
  default     = "10.20.1.0/24"
}

variable "availability_zone" {
  description = "가용 영역"
  type        = string
  default     = "us-east-1a"
}

variable "instance_type" {
  description = "Trial EC2 인스턴스 타입"
  type        = string
  default     = "t3.small"
}

variable "trial_ec2_count" {
  description = "한 번에 EC2 한 대만 사용한다는 원칙에 따른 기본값 1"
  type        = number
  default     = 1
}

variable "enable_flow_logs" {
  description = "VPC Flow Logs 활성화 여부"
  type        = bool
  default     = true
}

variable "golden_ami_id" {
  description = "Golden AMI가 준비되면 해당 AMI ID를 입력. 비워두면 기본 Ubuntu 24.04를 사용"
  type        = string
  default     = ""
}

variable "canary_file_path" {
  description = "Host에 만들어둘 미끼(Canary) 파일 경로. auditd가 이 경로를 감시한다"
  type        = string
  default     = "/opt/trial/canary/protected-file.txt"
}

variable "create_golden_ami" {
  description = "현재 Trial EC2 상태를 Golden AMI로 저장할지 여부"
  type        = bool
  default     = false
}

variable "attach_cloudwatch_agent_policy" {
  description = "EC2 IAM Role에 CloudWatch Agent 정책을 추가로 붙일지 여부"
  type        = bool
  default     = false
}

variable "budget_limit_usd" {
  description = "월간 AWS 예산 한도 (USD)"
  type        = number
  default     = 10
}

variable "budget_alert_email" {
  description = "예산 초과 알림을 받을 이메일. 비워두면 알림을 만들지 않음"
  type        = string
  default     = ""
}

variable "backend_image_uri" {
  description = "대시보드 배포 컨트롤러가 ECR에 push한 고정 백엔드 이미지 URI"
  type        = string
  default     = ""

  validation {
    condition     = var.backend_image_uri == "" || can(regex("^[0-9]+\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/.+:[A-Za-z0-9._-]+$", var.backend_image_uri))
    error_message = "backend_image_uri는 tag가 포함된 ECR 이미지 URI여야 합니다."
  }
}
