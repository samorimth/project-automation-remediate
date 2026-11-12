terraform {
  required_version = ">= 1.6.0"

  # Estado local de propósito. Um backend remoto em S3 criaria custo e
  # ampliaria o alcance desta pilha para fora do laboratório.
  backend "local" {
    path = "terraform.tfstate"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
