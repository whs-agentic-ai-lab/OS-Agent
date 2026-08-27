variable "aws_region" {
  description = "AWS Sandbox 리전"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region은 us-east-1 같은 AWS 리전 형식이어야 합니다."
  }
}

variable "aws_profile" {
  description = "로컬 AWS CLI 프로필. 비우면 기본 자격 증명 체인을 사용한다."
  type        = string
  default     = ""
}

variable "project_name" {
  description = "실험 리소스 이름 접두사"
  type        = string
  default     = "os-agent"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,18}$", var.project_name))
    error_message = "project_name은 3~19자의 영문 소문자, 숫자, 하이픈이어야 합니다."
  }
}

variable "environment_id" {
  description = "실험 환경 고유 ID"
  type        = string
  default     = "trial-0826"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,18}$", var.environment_id))
    error_message = "environment_id는 3~19자의 영문 소문자, 숫자, 하이픈이어야 합니다."
  }
}

variable "created_by" {
  description = "환경 생성자 표시 이름"
  type        = string
  default     = "unknown"
}

variable "owner_arn" {
  description = "환경 소유 AWS principal ARN"
  type        = string
  default     = "unknown"
}

variable "vpc_cidr" {
  description = "실험 전용 VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  description = "NAT Gateway 전용 Public Subnet CIDR"
  type        = string
  default     = "10.20.0.0/24"
}

variable "private_subnet_cidr" {
  description = "실험 EC2용 Private Subnet CIDR"
  type        = string
  default     = "10.20.1.0/24"
}

variable "availability_zone" {
  description = "고정 가용 영역"
  type        = string
  default     = "us-east-1a"

  validation {
    condition     = can(regex("^${var.aws_region}[a-z]$", var.availability_zone))
    error_message = "availability_zone은 aws_region에 속한 가용 영역이어야 합니다."
  }
}

variable "confirm_new_state" {
  description = "기존 OS-Agent state를 재사용하지 않고 0826 전용 새 state를 사용한다는 명시적 확인"
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "고정 실험 인스턴스 타입"
  type        = string
  default     = "t3.small"
}

variable "root_volume_size_gib" {
  description = "OS, Docker 로그, Vector 버퍼를 포함한 고정 root EBS 크기"
  type        = number
  default     = 30

  validation {
    condition     = var.root_volume_size_gib >= 20 && var.root_volume_size_gib <= 100
    error_message = "root_volume_size_gib는 20~100 GiB여야 합니다."
  }
}

variable "base_ami_id" {
  description = "검증 후 고정한 Ubuntu 24.04 amd64 AMI ID. latest 조회를 사용하지 않는다."
  type        = string
  default     = ""

  validation {
    condition     = var.base_ami_id == "" || can(regex("^ami-[0-9a-f]+$", var.base_ami_id))
    error_message = "base_ami_id는 ami-로 시작하는 AMI ID여야 합니다."
  }
}

variable "runtime_image_digest" {
  description = "U1 executor와 Host Supervisor artifact 이미지 digest"
  type        = string
  default     = ""

  validation {
    condition     = var.runtime_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.runtime_image_digest))
    error_message = "runtime_image_digest는 sha256:<64 hex> 형식이어야 합니다."
  }
}

variable "container1_image_digest" {
  description = "Container1 Target+C1 executor 이미지 digest"
  type        = string
  default     = ""

  validation {
    condition     = var.container1_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.container1_image_digest))
    error_message = "container1_image_digest는 sha256:<64 hex> 형식이어야 합니다."
  }
}

variable "target_image_digest" {
  description = "Container2/Container3 target 이미지 digest"
  type        = string
  default     = ""

  validation {
    condition     = var.target_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.target_image_digest))
    error_message = "target_image_digest는 sha256:<64 hex> 형식이어야 합니다."
  }
}

variable "vector_archive_sha256" {
  description = "Vector 0.57.0 x86_64 GNU archive의 공식 SHA-256"
  type        = string
  default     = ""

  validation {
    condition     = var.vector_archive_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.vector_archive_sha256))
    error_message = "vector_archive_sha256은 64자리 소문자 hex여야 합니다."
  }
}

variable "enable_remote_evidence_sink" {
  description = "Vector가 FastAPI Evidence API로 전송할지 여부. 기본은 로컬 수집만 수행한다."
  type        = bool
  default     = false
}

variable "evidence_api_url" {
  description = "FastAPI 기본 URL. HTTPS origin 또는 경로이며 trailing slash, query, fragment를 허용하지 않는다."
  type        = string
  default     = ""

  validation {
    condition = var.evidence_api_url == "" || can(regex(
      "^https://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%+-]+)*$",
      var.evidence_api_url,
    ))
    error_message = "evidence_api_url은 query/fragment/trailing slash가 없는 안전한 HTTPS 기본 URL이어야 합니다."
  }
}

variable "collector_token_parameter_name" {
  description = "Vector collector token을 담은 기존 SSM SecureString parameter 이름. 비밀값 자체를 Terraform에 넣지 않는다."
  type        = string
  default     = ""

  validation {
    condition     = var.collector_token_parameter_name == "" || can(regex("^/[A-Za-z0-9_.\\-/]+$", var.collector_token_parameter_name))
    error_message = "collector_token_parameter_name은 /로 시작하는 SSM parameter 경로여야 합니다."
  }
}

variable "collector_token_kms_key_arn" {
  description = "SSM SecureString이 customer-managed KMS key를 쓰는 경우 그 key ARN. 기본 aws/ssm key면 비운다."
  type        = string
  default     = ""

  validation {
    condition = (
      var.collector_token_kms_key_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9A-Za-z-]+$", var.collector_token_kms_key_arn))
    )
    error_message = "collector_token_kms_key_arn은 KMS key ARN이어야 합니다."
  }
}
