variable "aws_region" {
  type        = string
  description = "AWS Region to deploy resources into"
  default     = "us-east-1"
}

variable "aws_account_id" {
  type        = string
  description = "The 12-digit AWS Account ID"
  default     = "123456789012"
}

variable "ami_id" {
  type        = string
  description = "AMI ID for Ubuntu 22.04 LTS"
  default     = "ami-0c7217cdde317cfec" # Ubuntu 22.04 LTS AMI in us-east-1 (may vary)
}

variable "instance_type" {
  type        = string
  description = "EC2 instance size"
  default     = "t3.micro"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository path (org/repo)"
  default     = "example-org/cloud-security-cicd"
}

variable "github_org_or_user" {
  type        = string
  description = "GitHub Organization or Username"
  default     = "example-org"
}

variable "github_repo_name" {
  type        = string
  description = "GitHub repository name"
  default     = "cloud-security-cicd"
}

variable "create_oidc_provider" {
  type        = bool
  description = "Set to true to provision a new GitHub OIDC provider"
  default     = false
}
