# Pilha exclusiva do laboratório.
# Não consulta a VPC default e não referencia instâncias já existentes na conta.

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_ami" "ubuntu" {
  count = var.enable_execution && var.ubuntu_ami_id == "" ? 1 : 0

  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = [var.ubuntu_ami_name_filter]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  lab_instance_count = var.enable_execution ? var.instance_count : 0
  discovered_ami_id  = one(data.aws_ami.ubuntu[*].id)
  ubuntu_ami_id = coalesce(
    var.ubuntu_ami_id != "" ? var.ubuntu_ami_id : null,
    local.discovered_ami_id,
    "ami-unused",
  )
}

resource "terraform_data" "guards" {
  input = {
    instance_count   = var.instance_count
    max_instances    = var.max_instances
    enable_execution = var.enable_execution
    enable_nat       = var.enable_nat_gateway
  }

  lifecycle {
    precondition {
      condition     = var.instance_count <= var.max_instances
      error_message = "instance_count não pode ser maior que max_instances."
    }

    precondition {
      condition     = !var.enable_execution || var.enable_nat_gateway
      error_message = "enable_execution exige enable_nat_gateway. Os VPC endpoints do Systems Manager não alcançam os repositórios Ubuntu."
    }
  }
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "tcc-lab-${var.experiment_id}"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "tcc-lab-${var.experiment_id}-nat"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "tcc-lab-${var.experiment_id}-private"
  }
}

resource "aws_internet_gateway" "lab" {
  count  = var.enable_nat_gateway ? 1 : 0
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "tcc-lab-${var.experiment_id}"
  }
}

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "tcc-lab-${var.experiment_id}-nat"
  }

  depends_on = [aws_internet_gateway.lab]
}

resource "aws_nat_gateway" "lab" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name = "tcc-lab-${var.experiment_id}"
  }

  depends_on = [aws_internet_gateway.lab]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "tcc-lab-${var.experiment_id}-nat"
  }
}

resource "aws_route" "public_internet" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab[count.index].id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "tcc-lab-${var.experiment_id}-private"
  }
}

resource "aws_route" "private_nat" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.lab[count.index].id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "lab" {
  name_prefix = "tcc-lab-"
  description = "Laboratorio TCC: sem entrada; saida para DNS, HTTP e HTTPS."
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "DNS UDP para o resolvedor da VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }

  egress {
    description = "DNS TCP para o resolvedor da VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }

  egress {
    description = "HTTP para repositorios de pacotes"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS para Systems Manager e repositorios de pacotes"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "tcc-lab-${var.experiment_id}"
  }
}

resource "aws_security_group" "endpoints" {
  count       = var.enable_ssm_vpc_endpoints ? 1 : 0
  name_prefix = "tcc-lab-endpoints-"
  description = "HTTPS dos VPC endpoints do Systems Manager a partir da VPC do laboratorio."
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "HTTPS a partir da VPC do laboratorio"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }

  egress {
    description = "Resposta HTTPS dentro da VPC do laboratorio"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }

  tags = {
    Name = "tcc-lab-${var.experiment_id}-endpoints"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = var.enable_ssm_vpc_endpoints ? toset(["ssm", "ssmmessages", "ec2messages"]) : toset([])

  vpc_id              = aws_vpc.lab.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = aws_security_group.endpoints[*].id
  private_dns_enabled = true

  tags = {
    Name = "tcc-lab-${var.experiment_id}-${each.value}"
  }
}

resource "aws_iam_role" "lab" {
  name_prefix        = "tcc-lab-ssm-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json

  tags = {
    Name = "tcc-lab-${var.experiment_id}-ssm"
  }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.lab.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "lab" {
  name_prefix = "tcc-lab-ssm-"
  role        = aws_iam_role.lab.name
}

resource "aws_instance" "lab" {
  count = local.lab_instance_count

  ami                         = local.ubuntu_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.lab.id]
  iam_instance_profile        = aws_iam_instance_profile.lab.name
  associate_public_ip_address = false
  user_data                   = file("${path.module}/user_data.sh")
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "tcc-lab-${var.experiment_id}-${count.index + 1}"
  }

  lifecycle {
    precondition {
      condition     = local.ubuntu_ami_id != "ami-unused"
      error_message = "Não foi possível resolver a AMI Ubuntu."
    }

    precondition {
      condition     = var.enable_nat_gateway
      error_message = "A instância de laboratório exige enable_nat_gateway para o Systems Manager e para a atualização de pacotes."
    }
  }

  depends_on = [terraform_data.guards, aws_route.private_nat]
}
