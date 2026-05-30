output "vpc_id" {
  value       = aws_vpc.main.id
  description = "ID of the secure VPC"
}

output "ec2_public_ip" {
  value       = aws_instance.web_app.public_ip
  description = "Public IP of the web application server"
}

output "web_security_group_id" {
  value       = aws_security_group.web_sg.id
  description = "ID of the web traffic Security Group"
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions_role.arn
  description = "ARN of the IAM Role for GitHub Actions OIDC deployment"
}
