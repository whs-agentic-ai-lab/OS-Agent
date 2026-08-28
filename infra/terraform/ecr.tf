locals {
  image_repository_names = toset(["runtime", "container1", "target"])
  image_digests = {
    runtime    = var.runtime_image_digest
    container1 = var.container1_image_digest
    target     = var.target_image_digest
  }
}

data "aws_ecr_image" "pinned" {
  for_each = {
    for name, digest in local.image_digests : name => digest if digest != ""
  }

  repository_name = aws_ecr_repository.images[each.key].name
  image_digest    = each.value
}

resource "aws_ecr_repository" "images" {
  for_each = local.image_repository_names

  name                 = "${local.resource_prefix}-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Component = each.key
  }
}
