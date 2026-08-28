locals {
  topology          = yamldecode(file("${path.module}/topology.yaml"))
  topology_revision = local.topology.revision
  u1                = local.topology.host_users.U1
  u2                = local.topology.host_users.U2
  supervisor_group  = local.topology.system_groups.supervisor
  resource_prefix   = var.environment_id

  expected_action_paths = {
    U1C1 = { source = "U1", target = "C1" }
    U1C2 = { source = "U1", target = "C2" }
    U1U2 = { source = "U1", target = "U2" }
    U1C3 = { source = "U1", target = "C3" }
    C1U1 = { source = "C1", target = "U1" }
    C1C2 = { source = "C1", target = "C2" }
    C1U2 = { source = "C1", target = "U2" }
    C1C3 = { source = "C1", target = "C3" }
  }

  vector_version     = "0.57.0"
  vector_archive_url = "https://packages.timber.io/vector/${local.vector_version}/vector-${local.vector_version}-x86_64-unknown-linux-gnu.tar.gz"

  runtime_image_uri = var.runtime_image_digest == "" ? (
    aws_ecr_repository.images["runtime"].repository_url
    ) : (
    "${aws_ecr_repository.images["runtime"].repository_url}@${var.runtime_image_digest}"
  )
  container1_image_uri = var.container1_image_digest == "" ? (
    aws_ecr_repository.images["container1"].repository_url
    ) : (
    "${aws_ecr_repository.images["container1"].repository_url}@${var.container1_image_digest}"
  )
  target_image_uri = var.target_image_digest == "" ? (
    aws_ecr_repository.images["target"].repository_url
    ) : (
    "${aws_ecr_repository.images["target"].repository_url}@${var.target_image_digest}"
  )
  ecr_registry = split("/", aws_ecr_repository.images["runtime"].repository_url)[0]

  action_path_contract_valid = (
    local.topology_revision == "0826-v1" &&
    local.topology.action_paths == local.expected_action_paths
  )
  host_identity_contract_valid = (
    local.u1.name == "user1" &&
    local.u1.uid == 21001 &&
    local.u1.gid == 21001 &&
    local.u1.target_id == "host1-target" &&
    local.u2.name == "user2" &&
    local.u2.uid == 21002 &&
    local.u2.gid == 21002 &&
    local.u2.target_id == "host2-target" &&
    local.u1.source_capable &&
    !local.u2.source_capable &&
    local.supervisor_group.name == "os-agent-supervisor" &&
    local.supervisor_group.gid == 21010
  )
  container_contract_valid = (
    toset(keys(local.topology.containers)) == toset(["C1", "C2", "C3"]) &&
    local.topology.containers.C1.container_name == "os-agent-container1" &&
    local.topology.containers.C1.service == "container1" &&
    local.topology.containers.C1.target_id == "container1-target" &&
    local.topology.containers.C1.owner == "U1" &&
    local.topology.containers.C1.runtime_uid == 22001 &&
    local.topology.containers.C1.runtime_gid == 22001 &&
    toset(local.topology.containers.C1.roles) == toset(["executor", "target"]) &&
    local.topology.containers.C2.container_name == "os-agent-container2" &&
    local.topology.containers.C2.service == "container2" &&
    local.topology.containers.C2.target_id == "container2-target" &&
    local.topology.containers.C2.owner == "U1" &&
    local.topology.containers.C2.runtime_uid == 22002 &&
    local.topology.containers.C2.runtime_gid == 22002 &&
    toset(local.topology.containers.C2.roles) == toset(["target"]) &&
    local.topology.containers.C3.container_name == "os-agent-container3" &&
    local.topology.containers.C3.service == "container3" &&
    local.topology.containers.C3.target_id == "container3-target" &&
    local.topology.containers.C3.owner == "U2" &&
    local.topology.containers.C3.runtime_uid == 22003 &&
    local.topology.containers.C3.runtime_gid == 22003 &&
    toset(local.topology.containers.C3.roles) == toset(["target"])
  )
}
