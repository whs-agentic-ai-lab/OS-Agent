# 월간 AWS 비용이 한도를 넘으면 알림을 받기 위한 예산. 실습 중 비용이 새는 걸 조기에 잡기 위함.
resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # budget_alert_email이 비어있으면 알림 없이 예산 한도만 만들어둔다.
  dynamic "notification" {
    for_each = var.budget_alert_email == "" ? [] : [1]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.budget_alert_email]
    }
  }
}
