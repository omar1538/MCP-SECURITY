variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "mcp-sec-gw"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-3"
}

variable "image" {
  description = "Container image URI (ECR) built from docker/Dockerfile."
  type        = string
}
