# 대시보드에서 변경할 수 없는 최소 테스트 고정 환경
aws_region         = "us-east-1"
availability_zone  = "us-east-1a"
project_name       = "os-agent-test"
instance_type      = "t3.small"
trial_ec2_count    = 1

enable_flow_logs = true

budget_alert_email             = ""
attach_cloudwatch_agent_policy = false
create_golden_ami              = false
