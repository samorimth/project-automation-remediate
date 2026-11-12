output "aws_region" {
  description = "Região em que esta pilha seria criada."
  value       = var.aws_region
}

output "vpc_id" {
  description = "VPC exclusiva do laboratório."
  value       = aws_vpc.lab.id
}

output "public_subnet_id" {
  description = "Subnet pública reservada ao NAT Gateway."
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Subnet privada das instâncias Ubuntu."
  value       = aws_subnet.private.id
}

output "lab_security_group_id" {
  description = "Security group das instâncias, sem regras de entrada."
  value       = aws_security_group.lab.id
}

output "iam_role_arn" {
  description = "Role de instância com AmazonSSMManagedInstanceCore."
  value       = aws_iam_role.lab.arn
}

output "instance_profile_name" {
  description = "Instance profile anexado às instâncias quando a execução estiver ligada."
  value       = aws_iam_instance_profile.lab.name
}

output "instance_ids" {
  description = "IDs das instâncias criadas. Lista vazia enquanto enable_execution for falso."
  value       = aws_instance.lab[*].id
}

output "paid_resources_enabled" {
  description = "Interruptores de custo e a quantidade efetiva de instâncias."
  value = {
    nat_gateway       = var.enable_nat_gateway
    ssm_vpc_endpoints = var.enable_ssm_vpc_endpoints
    execution         = var.enable_execution
    instance_count    = local.lab_instance_count
  }
}
