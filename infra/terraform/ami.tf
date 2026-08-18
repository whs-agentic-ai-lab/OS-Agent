# create_golden_ami = true로 apply하면, 지금 떠 있는 Trial EC2의 현재 상태(Docker/auditd
# 설치 + 설정까지 끝난 상태)를 그대로 AMI로 저장한다. 이후엔 이 AMI ID를 golden_ami_id에
# 넣어서 매번 처음부터 부트스트랩하지 않고 바로 그 상태로 EC2를 띄울 수 있다.
resource "aws_ami_from_instance" "golden" {
  count              = var.create_golden_ami ? 1 : 0
  name               = "${var.project_name}-golden-ubuntu2404-docker-auditd-v1"
  source_instance_id = aws_instance.trial[0].id

  tags = {
    Name        = "${var.project_name}-golden-ubuntu2404-docker-auditd-v1"
    Description = "Ubuntu 24.04, Docker, auditd, journald persistent, trial evidence layout"
  }
}
