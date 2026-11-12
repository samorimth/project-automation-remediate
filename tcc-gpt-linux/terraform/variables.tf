variable "aws_region" {
  description = "Região da pilha do laboratório. Padrão experimental atual: us-east-2 (tentativa após SCP em us-east-1/sa-east-1). A instância Windows já existente na conta não é consultada." # pragma: allowlist secret
  type        = string
  default     = "us-east-2"

  validation {
    condition     = contains(["us-east-1", "us-east-2", "sa-east-1"], var.aws_region) # pragma: allowlist secret
    error_message = "aws_region deve ser us-east-1, us-east-2 ou sa-east-1." # pragma: allowlist secret
  }
}

variable "instance_type" {
  description = "Tipo da instância Ubuntu descartável."
  type        = string
  default     = "t3.small"

  validation {
    condition     = contains(["t3.micro", "t3.small", "t3.medium"], var.instance_type)
    error_message = "instance_type deve ser t3.micro, t3.small ou t3.medium."
  }
}

variable "instance_count" {
  description = "Quantidade desejada de instâncias quando enable_execution for verdadeiro."
  type        = number
  default     = 1

  validation {
    condition     = var.instance_count >= 0
    error_message = "instance_count não pode ser negativo."
  }
}

variable "max_instances" {
  description = "Limite superior de instâncias desta pilha."
  type        = number
  default     = 3

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 3
    error_message = "max_instances deve estar entre 1 e 3."
  }
}

variable "max_simultaneous_instances" {
  description = "Quantas EC2 de experimento podem existir ao mesmo tempo. Cada repetição usa uma instância nova e a destrói antes da seguinte. O padrão é uma."
  type        = number
  default     = 1

  validation {
    condition     = var.max_simultaneous_instances >= 1 && var.max_simultaneous_instances <= 3
    error_message = "max_simultaneous_instances deve ficar entre 1 e 3."
  }
}

variable "ubuntu_ami_id" {
  description = "AMI Ubuntu explícita. Vazio seleciona a AMI oficial mais recente da Canonical."
  type        = string
  default     = ""
}

variable "ubuntu_ami_name_filter" {
  description = "Filtro do nome da AMI Ubuntu 24.04 LTS publicada pela Canonical."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
}

variable "experiment_id" {
  description = "Identificador do experimento, usado apenas em tags e nomes."
  type        = string
  default     = "fase-1"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,40}$", var.experiment_id))
    error_message = "experiment_id deve usar letras minúsculas, dígitos e hífen."
  }
}

variable "environment" {
  description = "Ambiente lógico da pilha. Produção não é um valor aceito."
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["lab", "dev"], var.environment)
    error_message = "environment deve ser lab ou dev."
  }
}

variable "enable_execution" {
  description = "Liga a criação das instâncias EC2. O padrão é falso para impedir custo acidental."
  type        = bool
  default     = false
}

variable "enable_nat_gateway" {
  description = "Liga o NAT Gateway, necessário para o Systems Manager e para os repositórios de pacotes. Recurso pago."
  type        = bool
  default     = false
}

variable "enable_ssm_vpc_endpoints" {
  description = "Liga os VPC endpoints de interface do Systems Manager. Recurso pago e insuficiente, sozinho, para atualizar pacotes Ubuntu."
  type        = bool
  default     = false
}
