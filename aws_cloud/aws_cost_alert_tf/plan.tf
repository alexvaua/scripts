provider "aws" {
  region = "eu-central-1"
}

resource "aws_budgets_budget" "budget_and_notification" {
  name              = "budget-monthly"
  budget_type       = "COST"
  limit_amount      = "10"
  limit_unit        = "USD"
  time_period_end   = "2087-06-15_00:00"
  time_period_start = "2023-03-09_00:00"
  time_unit         = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 5
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["mailfwd3+aws_cost@gmail.com"]
  }
}
