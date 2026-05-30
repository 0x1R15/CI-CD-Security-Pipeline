# IAM Instance Profile for EC2 Instance (Least-Privilege System Management)
resource "aws_iam_role" "ec2_ssm_role" {
  name = "devsecops-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach AmazonSSMManagedInstanceCore policy to allow Session Manager & Run Command
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "devsecops-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# --- OIDC Configuration for GitHub Actions (Passwordless & Keys-Free Authentication) ---

# GitHub OIDC Identity Provider (Create if not already exists in account)
# Normally configured once per AWS account. If it exists, it can be imported or referenced via data source.
# For self-contained code, we define it here, but add a variable to toggle creation if needed.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  # Official GitHub thumbprint for SSL verification
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]
}

# IAM Role for GitHub Actions (Deployment Role)
resource "aws_iam_role" "github_actions_role" {
  name = "devsecops-github-actions-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # Scope assumptions strictly to the specific GitHub repository and main branch
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org_or_user}/${var.github_repo_name}:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

# Custom Least-Privilege deployment policy for GitHub Actions
# Allows only uploading artifacts and triggering Systems Manager (SSM) Run Command on the specific EC2 instance
resource "aws_iam_policy" "deploy_policy" {
  name        = "devsecops-github-deploy-policy"
  description = "Allows deployment actions via SSM on the web app instance"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = [
          "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"
        ]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Name" = "devsecops-secure-app"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_deploy" {
  role       = aws_iam_role.github_actions_role.name
  policy_arn = aws_iam_policy.deploy_policy.arn
}
