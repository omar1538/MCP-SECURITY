# Least-privilege roles: an execution role to pull the image and write logs, and
# a task role the containers assume at runtime (kept empty here - the servers
# need no AWS APIs; a real payments integration would attach scoped policies).

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Secrets (e.g. an LLM API key for the live agent) belong in Secrets Manager and
# are injected via the task definition's `secrets` block, never baked into images.
resource "aws_secretsmanager_secret" "llm_api_key" {
  name        = "${var.name}/llm-api-key"
  description = "OpenAI-compatible API key for the live agent (optional)"
}
