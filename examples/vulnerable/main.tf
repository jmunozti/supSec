# Intentionally vulnerable Terraform for supSec demo
resource "aws_s3_bucket" "data" {
  bucket = "my-unsecured-bucket"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "public_db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  password            = "SuperSecret123!"
  skip_final_snapshot = true
  deletion_protection = false
  encrypted           = false
}

resource "aws_kms_key" "no_rotation" {
  description = "key without rotation"
}
