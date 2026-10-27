# AWS Fargate deployment sketch for the MCP Security Gateway testbed.
#
# This provisions a private VPC and an ECS Fargate service per MCP server behind
# the gateway. It is a reference topology, not an auto-applied pipeline: review
# `terraform plan` before any apply, and supply your own image registry.
#
#   terraform init
#   terraform plan  -var="image=<ecr-repo-uri>:latest"
#   terraform apply -var="image=<ecr-repo-uri>:latest"

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ---- network -----------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-vpc" }
}

resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-private-${count.index}" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# The tool servers never need the public internet; traffic stays inside the VPC.
resource "aws_security_group" "tasks" {
  name        = "${var.name}-tasks"
  description = "intra-VPC MCP traffic only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "MCP ports from within the VPC"
    from_port   = 8101
    to_port     = 8104
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---- cluster + logging -------------------------------------------------------
resource "aws_ecs_cluster" "this" {
  name = "${var.name}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = 14
}

# ---- one Fargate service per MCP server --------------------------------------
locals {
  servers = {
    docstore     = 8101
    transactions = 8102
    payments     = 8103
    notify       = 8104
  }
}

resource "aws_ecs_task_definition" "server" {
  for_each                 = local.servers
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = each.key
      image     = var.image
      essential = true
      command   = ["python", "-m", "mcp_servers.${each.key}", "--host", "0.0.0.0", "--port", tostring(each.value)]
      portMappings = [{ containerPort = each.value }]
      environment  = [{ name = "MSG_DATA_DIR", value = "/data" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = each.key
        }
      }
    }
  ])
}

resource "aws_ecs_service" "server" {
  for_each        = local.servers
  name            = "${var.name}-${each.key}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.server[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }
}
