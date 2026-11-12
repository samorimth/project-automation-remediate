provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project      = "tcc-gpt-linux"
      ExperimentId = var.experiment_id
      Environment  = var.environment
      ManagedBy    = "terraform"
      Purpose      = "tcc-lab"
    }
  }
}
