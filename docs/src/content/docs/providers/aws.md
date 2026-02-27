---
title: AWS Secrets Manager
description: Store and retrieve secrets from AWS Secrets Manager
---

AWS Secrets Manager is a fully managed service that helps you protect access to your applications, services, and IT resources. This provider enables SecretSpec to store and retrieve secrets from AWS Secrets Manager.

## Features

- **Fully managed**: No infrastructure to manage
- **Automatic encryption**: Secrets are encrypted at rest using AWS KMS
- **IAM integration**: Uses AWS credential chain for authentication
- **Region-aware**: Supports all AWS regions
- **Profile isolation**: Different secrets for different environments
- **Custom naming**: Optional prefix for secret namespacing

## Authentication

The AWS Secrets Manager provider uses the default AWS credential chain, which automatically searches for credentials in the following order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **IAM roles**: For EC2, ECS, Lambda, and other AWS services
3. **AWS credentials file**: `~/.aws/credentials`
4. **IAM Identity Center**: AWS SSO configuration in `~/.aws/config`

### Environment Variables

```bash
export AWS_ACCESS_KEY_ID=your-access-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export AWS_REGION=us-east-1
```

### IAM Roles (Recommended for Production)

When running on AWS services (EC2, ECS, Lambda, EKS), the provider automatically uses the instance's IAM role without any additional configuration.

### AWS Credentials File

Configure credentials in `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = your-access-key-id
aws_secret_access_key = your-secret-access-key
region = us-east-1

[production]
aws_access_key_id = prod-access-key-id
aws_secret_access_key = prod-secret-access-key
region = us-west-2
```

Then use the appropriate profile:

```bash
export AWS_PROFILE=production
```

## URI Format

```
aws://[region][/prefix]
aws-secretsmanager://[region][/prefix]
```

### Parameters

- **region** (optional): AWS region (e.g., `us-east-1`, `eu-west-2`). If not specified, uses the default region from AWS credential chain.
- **prefix** (optional): Prefix for secret names to enable namespacing.

### Examples

```bash
# Use default region from AWS credential chain
aws://

# Specify a region
aws://us-east-1

# Use with prefix for namespacing
aws://us-west-2/myapp

# Alternative scheme name
aws-secretsmanager://eu-west-1
```

## Configuration

### Basic Usage

```bash
# Set a secret
secretspec set DATABASE_URL --provider aws://us-east-1

# Get a secret
secretspec get DATABASE_URL --provider aws://us-east-1

# Check all secrets
secretspec check --provider aws://us-east-1

# Run with secrets
secretspec run --provider aws://us-east-1 -- npm start
```

### With Prefix

Use a prefix to namespace your secrets:

```bash
# Set secrets with prefix
secretspec set API_KEY --provider aws://us-east-1/myapp
secretspec set DATABASE_URL --provider aws://us-east-1/myapp

# Secrets will be stored as:
# myapp/{project}/{profile}/API_KEY
# myapp/{project}/{profile}/DATABASE_URL
```

### Default Provider

Set AWS Secrets Manager as your default provider:

```bash
# Interactive configuration
secretspec config init

# Or manually in ~/.config/secretspec/config.toml
[defaults]
provider = "aws://us-east-1"
```

### Per-Secret Provider Configuration

Configure different providers for different secrets in `secretspec.toml`:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["aws-prod"] }
API_KEY = { description = "API Key", providers = ["aws-shared"] }
```

Define provider aliases in `~/.config/secretspec/config.toml`:

```toml
[providers]
aws-prod = "aws://us-east-1/production"
aws-shared = "aws://us-west-2/shared"
```

## IAM Permissions

The AWS credentials used by SecretSpec need the following IAM permissions:

### Minimum Permissions (Read-Only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:secretspec/*"
    }
  ]
}
```

### Full Permissions (Read/Write)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:CreateSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:DeleteSecret",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:secretspec/*"
    }
  ]
}
```

### With Prefix

If using a prefix, adjust the resource ARN:

```json
{
  "Resource": "arn:aws:secretsmanager:*:*:secret:myapp/*"
}
```

## Secret Naming

Secrets are stored with the following naming pattern:

```
secretspec/{project}/{profile}/{key}
```

Or with a prefix:

```
{prefix}/{project}/{profile}/{key}
```

### Examples

| Project | Profile | Key | Secret Name |
|---------|---------|-----|-------------|
| myapp | default | DATABASE_URL | `secretspec/myapp/default/DATABASE_URL` |
| myapp | production | API_KEY | `secretspec/myapp/production/API_KEY` |
| myapp | production | API_KEY | `myapp/myapp/production/API_KEY` (with prefix "myapp") |

## Local Development with LocalStack

For local development and testing, you can use [LocalStack](https://localstack.cloud/) to simulate AWS Secrets Manager.

### Using Docker

```bash
# Start LocalStack
docker run -d -p 4566:4566 localstack/localstack

# Set the endpoint URL
export AWS_ENDPOINT_URL=http://localhost:4566

# Use SecretSpec with LocalStack
secretspec set DATABASE_URL --provider aws://
```

### Using the Endpoint Parameter

You can also specify the endpoint directly in the URI:

```bash
secretspec set DATABASE_URL --provider "aws://?endpoint=http://localhost:4566"
```

### Test Credentials

LocalStack doesn't require real AWS credentials, but you need to provide dummy values:

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_REGION=us-east-1
```

## Best Practices

### 1. Use IAM Roles in Production

When running on AWS infrastructure, use IAM roles instead of access keys:

```bash
# No credentials needed - uses instance IAM role
secretspec run --provider aws://us-east-1 -- npm start
```

### 2. Use Profiles for Environment Isolation

```toml
[profiles.development]
DATABASE_URL = { description = "Dev DB", providers = ["aws-dev"] }

[profiles.production]
DATABASE_URL = { description = "Prod DB", providers = ["aws-prod"] }
```

### 3. Restrict IAM Permissions

Follow the principle of least privilege:

- Use read-only permissions for applications that only retrieve secrets
- Scope permissions to specific secret name patterns
- Use different IAM roles for different environments

### 4. Use Prefixes for Multi-Tenant Applications

```bash
# Team A secrets
secretspec set API_KEY --provider aws://us-east-1/team-a

# Team B secrets
secretspec set API_KEY --provider aws://us-east-1/team-b
```

### 5. Enable AWS CloudTrail

CloudTrail logs all API calls to AWS Secrets Manager, providing an audit trail for secret access.

## Troubleshooting

### "Unable to locate credentials"

**Problem**: The AWS SDK cannot find credentials.

**Solution**: Ensure credentials are configured:

```bash
# Check if credentials are set
aws sts get-caller-identity

# Or configure credentials
aws configure
```

### "AccessDeniedException"

**Problem**: The IAM user or role doesn't have permissions.

**Solution**: Add the required IAM permissions (see [IAM Permissions](#iam-permissions)).

### "InvalidClientTokenId"

**Problem**: The AWS access key is invalid or has been deactivated.

**Solution**: Verify your access key is active in the AWS IAM console.

### "Secret not found"

**Problem**: The secret doesn't exist in AWS Secrets Manager.

**Solution**: 
1. Check the secret name format: `secretspec/{project}/{profile}/{key}`
2. Verify you're using the correct region
3. Check if a prefix is configured

### "Region is missing"

**Problem**: No region specified and AWS SDK cannot determine the default region.

**Solution**: Set the region explicitly:

```bash
# Option 1: Environment variable
export AWS_REGION=us-east-1

# Option 2: In URI
secretspec set DATABASE_URL --provider aws://us-east-1

# Option 3: AWS config file
aws configure set region us-east-1
```

### LocalStack Connection Issues

**Problem**: Cannot connect to LocalStack.

**Solution**:
1. Verify LocalStack is running: `docker ps`
2. Check the endpoint URL: `http://localhost:4566`
3. Ensure the port is not blocked by firewall

## Cost Considerations

AWS Secrets Manager pricing includes:

- **Per secret per month**: $0.40 per secret
- **API calls**: $0.05 per 10,000 API calls

For development environments, consider:
- Using the free tier (30 days free for secrets)
- Using LocalStack for local development
- Cleaning up unused secrets

## Comparison with Other Providers

| Feature | AWS Secrets Manager | GCSM | OnePassword |
|---------|-------------------|------|-------------|
| Cloud-based | ✅ | ✅ | ✅ |
| Encryption | ✅ AWS KMS | ✅ Google-managed | ✅ End-to-end |
| IAM Integration | ✅ Native | ✅ GCP IAM | ❌ |
| Secret Rotation | ✅ Built-in | ❌ | ❌ |
| Cross-region Replication | ✅ | ❌ | ❌ |
| Cost | $0.40/secret/month | $0.06/secret/month | Subscription |

## Related Resources

- [AWS Secrets Manager Documentation](https://docs.aws.amazon.com/secretsmanager/)
- [AWS SDK for Rust](https://aws.amazon.com/sdk-for-rust/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [LocalStack Documentation](https://docs.localstack.cloud/)