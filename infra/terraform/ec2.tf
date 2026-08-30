locals {
  experiment_compose = templatefile("${path.module}/experiment-compose.yml.tpl", {
    runtime_image_uri    = local.runtime_image_uri
    container1_image_uri = local.container1_image_uri
    target_image_uri     = local.target_image_uri
    topology_revision    = local.topology_revision
    c1_uid               = local.topology.containers.C1.runtime_uid
    c1_gid               = local.topology.containers.C1.runtime_gid
    c2_uid               = local.topology.containers.C2.runtime_uid
    c2_gid               = local.topology.containers.C2.runtime_gid
    c3_uid               = local.topology.containers.C3.runtime_uid
    c3_gid               = local.topology.containers.C3.runtime_gid
    supervisor_gid       = local.supervisor_group.gid
  })

  bootstrap_assets = {
    topology_json = jsonencode(local.topology)
    compose       = local.experiment_compose
    docker_daemon = file("${path.module}/config/docker/daemon.json")
    audit_rules = templatefile("${path.module}/config/audit/os-agent.rules.tpl", {
      u1_uid = local.u1.uid
      u2_uid = local.u2.uid
      c1_uid = local.topology.containers.C1.runtime_uid
      c2_uid = local.topology.containers.C2.runtime_uid
      c3_uid = local.topology.containers.C3.runtime_uid
    })
    journald = file("${path.module}/config/journald/99-os-agent.conf")
    nftables = templatefile("${path.module}/config/nftables/os-agent.nft.tpl", {
      u1_uid = local.u1.uid
      u2_uid = local.u2.uid
    })
    vector_config = templatefile("${path.module}/config/vector/vector.yaml.tpl", {
      environment_id      = var.environment_id
      topology_revision   = local.topology_revision
      remote_sink_enabled = var.enable_remote_evidence_sink
      evidence_api_uri    = jsonencode("${var.evidence_api_url}/internal/evidence/events")
    })
    evidence_upload_config = jsonencode({
      enabled        = var.enable_remote_evidence_sink
      api_url        = var.evidence_api_url
      environment_id = var.environment_id
      token_file     = "/etc/vector/secrets/collector_token"
    })
    logrotate           = file("${path.module}/config/logrotate/os-agent")
    supervisor_unit     = file("${path.module}/systemd/os-agent-host-supervisor.service")
    experiment_unit     = file("${path.module}/systemd/os-agent-experiment.service")
    docker_events_unit  = file("${path.module}/systemd/os-agent-docker-events.service")
    docker_logs_unit    = file("${path.module}/systemd/os-agent-docker-logs.service")
    vector_unit         = file("${path.module}/systemd/vector.service")
    relay_docker_events = file("${path.module}/scripts/relay_docker_events.sh")
    relay_docker_logs   = file("${path.module}/scripts/relay_docker_logs.sh")
    capture_state       = file("${path.module}/scripts/capture_state.sh")
    verify_environment  = file("${path.module}/scripts/verify_environment.sh")
  }

  minified_bootstrap_assets = {
    for name, content in local.bootstrap_assets : name => join("\n", [
      for line in split("\n", replace(content, "\r\n", "\n")) : line
      if trimspace(line) != "" && (
        !startswith(trimspace(line), "#") || startswith(trimspace(line), "#!")
      )
    ])
  }

  # Quoted heredocs keep asset bytes literal; one outer gzip avoids nested
  # base64/JSON escaping overhead while retaining the existing size limit.
  bootstrap_asset_cases = join("\n", [
    for name, content in local.minified_bootstrap_assets : join("\n", [
      "${name}) cat <<'OS_AGENT_ASSET'",
      content,
      "OS_AGENT_ASSET",
      ";;",
    ])
  ])

  rendered_user_data_source = templatefile("${path.module}/user_data.sh.tpl", {
    aws_region                  = var.aws_region
    environment_id              = var.environment_id
    topology_revision           = local.topology_revision
    ecr_registry                = local.ecr_registry
    runtime_image_uri           = local.runtime_image_uri
    container1_image_uri        = local.container1_image_uri
    target_image_uri            = local.target_image_uri
    vector_version              = local.vector_version
    vector_archive_url          = local.vector_archive_url
    vector_archive_sha256       = var.vector_archive_sha256
    enable_remote_evidence_sink = var.enable_remote_evidence_sink
    collector_parameter_name    = var.collector_token_parameter_name
    openrouter_parameter_name   = var.openrouter_api_key_parameter_name
    bootstrap_asset_cases       = local.bootstrap_asset_cases
  })

  rendered_user_data = join("\n", [
    for line in split("\n", replace(local.rendered_user_data_source, "\r\n", "\n")) : line
    if trimspace(line) != "" && (
      !startswith(trimspace(line), "#") || startswith(trimspace(line), "#!")
    )
  ])

  compressed_user_data = base64gzip(local.rendered_user_data)
}

resource "aws_instance" "trial" {
  ami                    = try(data.aws_ami.selected[0].id, var.base_ami_id)
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.trial_ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.trial_ec2.name

  associate_public_ip_address = false

  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_size           = var.root_volume_size_gib
    volume_type           = "gp3"
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  user_data_base64 = local.compressed_user_data

  user_data_replace_on_change = true

  lifecycle {
    precondition {
      condition     = var.confirm_new_state
      error_message = "confirm_new_state=true로 설정하고 0826 전용 빈 state를 사용하는지 명시적으로 확인해야 합니다."
    }

    precondition {
      condition     = local.action_path_contract_valid
      error_message = "topology.yaml의 8개 action path 또는 source/target mapping이 변경되었습니다."
    }

    precondition {
      condition     = local.host_identity_contract_valid
      error_message = "Linux Host User1/User2 identity 계약이 변경되었습니다."
    }

    precondition {
      condition     = local.container_contract_valid
      error_message = "C1/C2/C3 identity, runtime UID/GID, ownership 또는 role 계약이 변경되었습니다."
    }

    precondition {
      condition     = var.base_ami_id != ""
      error_message = "실험 전에 검증한 base_ami_id를 고정해야 합니다."
    }

    precondition {
      condition = alltrue([
        var.runtime_image_digest != "",
        var.container1_image_digest != "",
        var.target_image_digest != "",
        var.vector_archive_sha256 != "",
      ])
      error_message = "세 이미지 digest와 Vector 공식 SHA-256을 모두 고정해야 합니다."
    }

    precondition {
      condition     = var.openrouter_api_key_parameter_name != ""
      error_message = "AI 공격 Agent 실행을 위해 OpenRouter SSM SecureString parameter 이름이 필요합니다."
    }

    precondition {
      condition = (
        !var.enable_remote_evidence_sink ||
        (var.evidence_api_url != "" && var.collector_token_parameter_name != "")
      )
      error_message = "원격 Evidence sink를 켜려면 HTTPS API URL과 SSM collector token parameter가 필요합니다."
    }

    precondition {
      condition     = length(local.compressed_user_data) <= 20480
      error_message = "gzip user-data가 내부 15 KiB 상한을 넘습니다. EC2 16 KiB 한도를 위한 여유를 복구해야 합니다."
    }
  }

  depends_on = [
    aws_route.private_via_nat,
    aws_iam_role_policy_attachment.ssm_core,
    aws_iam_role_policy.ecr_pull,
    aws_iam_role_policy.collector_token,
    aws_iam_role_policy.openrouter_api_key,
    data.aws_ecr_image.pinned,
    data.aws_ami.selected,
  ]

  tags = {
    Name             = "${local.resource_prefix}-ec2"
    EnvironmentId    = var.environment_id
    TopologyRevision = local.topology_revision
    CreatedBy        = var.created_by
    OwnerArn         = var.owner_arn
  }
}
