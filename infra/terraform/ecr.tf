resource "aws_ecr_repository" "agent_backend" {
  name                 = "${var.project_name}-backend"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "agent_backend" {
  repository = aws_ecr_repository.agent_backend.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최근 이미지 5개만 유지"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}
