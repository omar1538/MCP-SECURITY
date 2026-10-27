output "vpc_id" {
  value = aws_vpc.this.id
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "services" {
  value = { for k, s in aws_ecs_service.server : k => s.name }
}

output "log_group" {
  value = aws_cloudwatch_log_group.this.name
}
