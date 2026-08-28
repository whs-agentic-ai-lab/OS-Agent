terraform {
  required_version = ">= 1.9.0"

  # The dashboard passes an explicit per-environment -state path to every
  # stateful command. Keep the backend at Terraform's default local path so
  # init never attempts to migrate unrelated legacy state automatically.
  backend "local" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = {
      Project       = "agentic-ai-trust-boundary"
      Layer         = "os-ubuntu"
      Managed       = "terraform"
      ManagedBy     = "Terraform"
      EnvironmentId = var.environment_id
      CreatedBy     = var.created_by
      OwnerArn      = var.owner_arn
    }
  }
}
