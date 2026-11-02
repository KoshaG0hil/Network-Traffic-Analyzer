variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Deployment Region"
}

variable "environment" {
  type        = string
  default     = "prod"
  description = "Deployment Environment"
}

variable "aws_account_id" {
  type        = string
  default     = "123456789012"
  description = "Target AWS Account ID"
}
