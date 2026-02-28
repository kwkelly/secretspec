//! AWS Secrets Manager provider
//!
//! This provider integrates with AWS Secrets Manager to store and retrieve secrets.
//!
//! # Authentication
//!
//! Uses the default AWS credential chain:
//! - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
//! - IAM roles for EC2/ECS/Lambda
//! - AWS credentials file (`~/.aws/credentials`)
//! - IAM Identity Center (SSO)
//!
//! # Configuration
//!
//! The provider supports configuration via:
//! - `AWS_REGION` or `AWS_DEFAULT_REGION` - Default region
//! - `AWS_ENDPOINT_URL` - Custom endpoint URL (for LocalStack testing)
//! - URI parameters - Override defaults (e.g., `aws://us-east-1?endpoint=http://localhost:4566`)
//!
//! # URI Format
//!
//! `aws://[region][/prefix]` or `aws-secretsmanager://[region][/prefix]`
//!
//! Both region and prefix are optional. If not specified, defaults from the
//! AWS credential chain are used.
//!
//! # Secret Naming
//!
//! Secrets are stored with the naming pattern: `secretspec/{project}/{profile}/{key}`
//! If a prefix is configured: `{prefix}/{project}/{profile}/{key}`
//!
//! # Example
//!
//! ```bash
//! # Set up authentication (optional if using IAM roles)
//! export AWS_ACCESS_KEY_ID=your-access-key
//! export AWS_SECRET_ACCESS_KEY=your-secret-key
//! export AWS_REGION=us-east-1
//!
//! # Use with defaults from environment
//! secretspec set DATABASE_URL --provider aws://
//!
//! # Override region
//! secretspec set DATABASE_URL --provider aws://us-west-2
//!
//! # Use with prefix for namespacing
//! secretspec set API_KEY --provider aws://us-east-1/myapp
//!
//! # Test with LocalStack
//! export AWS_ENDPOINT_URL=http://localhost:4566
//! secretspec set DATABASE_URL --provider aws://
//! ```

use super::Provider;
use crate::{Result, SecretSpecError};
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::future::Future;
use url::Url;

/// Configuration for the AWS Secrets Manager provider.
///
/// Contains the AWS region and optional prefix for secret namespacing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSecretsManagerConfig {
    /// The AWS region (e.g., "us-east-1", "eu-west-1")
    /// If not specified, uses the default region from AWS credential chain
    /// (AWS_REGION or AWS_DEFAULT_REGION env vars, ~/.aws/config, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional prefix for secret names (e.g., "myapp" results in "myapp/secretspec/...")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Optional custom endpoint URL for testing with LocalStack
    /// If not specified, uses the default endpoint from AWS credential chain
    /// (AWS_ENDPOINT_URL env var, etc.)
    #[serde(skip)]
    pub endpoint_url: Option<String>,
}

/// Validates an AWS region format.
///
/// AWS regions typically follow the pattern: {geo}-{direction}-{number}
/// Examples: us-east-1, eu-west-2, ap-southeast-1
fn validate_aws_region(region: &str) -> std::result::Result<(), SecretSpecError> {
    if region.is_empty() {
        return Err(SecretSpecError::ProviderOperationFailed(
            "AWS region cannot be empty".to_string(),
        ));
    }

    // Check for valid characters (alphanumeric and hyphens)
    for c in region.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "AWS region contains invalid character '{}'. \
                Only alphanumeric characters and hyphens are allowed",
                c
            )));
        }
    }

    // Basic pattern check - should have at least one hyphen for standard regions
    // but allow custom regions for LocalStack testing
    if !region.contains('-') && region != "localhost" {
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "AWS region '{}' does not appear to be a valid region. \
            Expected format like 'us-east-1' or 'eu-west-2'",
            region
        )));
    }

    Ok(())
}

impl TryFrom<&Url> for AwsSecretsManagerConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();
        if scheme != "aws" && scheme != "aws-secretsmanager" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for AWS Secrets Manager provider. Expected 'aws' or 'aws-secretsmanager'.",
                scheme
            )));
        }

        // Extract region from host portion: aws://us-east-1 or aws://us-east-1/prefix
        // Region is optional - if not specified, will use default from AWS credential chain
        let region = url
            .host_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        // Validate region format if provided
        if let Some(ref region_str) = region {
            validate_aws_region(region_str)?;
        }

        // Extract optional prefix from path
        let prefix = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        // Extract endpoint URL from query parameters (for testing)
        let endpoint_url = url
            .query_pairs()
            .find(|(key, _)| key == "endpoint")
            .map(|(_, value)| value.to_string());

        Ok(Self {
            region,
            prefix,
            endpoint_url,
        })
    }
}

impl TryFrom<Url> for AwsSecretsManagerConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
    }
}

/// AWS Secrets Manager provider.
///
/// This provider stores and retrieves secrets from AWS Secrets Manager using
/// the AWS SDK for Rust with the default credential chain for authentication.
pub struct AwsSecretsManagerProvider {
    config: AwsSecretsManagerConfig,
}

crate::register_provider! {
    struct: AwsSecretsManagerProvider,
    config: AwsSecretsManagerConfig,
    name: "aws",
    description: "AWS Secrets Manager",
    schemes: ["aws", "aws-secretsmanager"],
    examples: ["aws://us-east-1", "aws://eu-west-2/myapp", "aws-secretsmanager://us-east-1"],
}

impl AwsSecretsManagerProvider {
    /// Creates a new AwsSecretsManagerProvider with the given configuration.
    pub fn new(config: AwsSecretsManagerConfig) -> Self {
        Self { config }
    }

    /// Validates a secret name component for AWS Secrets Manager.
    ///
    /// Components must contain only alphanumeric characters, underscores, hyphens, and slashes.
    fn validate_name_component(name: &str, component: &str) -> Result<()> {
        if component.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} cannot be empty",
                name
            )));
        }

        for c in component.chars() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} contains invalid character '{}'. \
                    Only alphanumeric characters, underscores, and hyphens are allowed",
                    name, c
                )));
            }
        }

        Ok(())
    }

    /// Formats and validates the secret name for AWS Secrets Manager.
    ///
    /// Converts the SecretSpec path format to AWS-compatible name:
    /// `secretspec/{project}/{profile}/{key}`
    ///
    /// If a prefix is configured: `{prefix}/{project}/{profile}/{key}`
    ///
    /// AWS Secrets Manager secret names must:
    /// - Be 1-512 characters long
    /// - Contain only alphanumeric characters, hyphens, underscores, and slashes
    fn format_secret_name(&self, project: &str, profile: &str, key: &str) -> Result<String> {
        // Validate each component
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;

        let secret_name = if let Some(prefix) = &self.config.prefix {
            format!("{}/{}/{}/{}", prefix, project, profile, key)
        } else {
            format!("secretspec/{}/{}/{}", project, profile, key)
        };

        // AWS secret names must be 1-512 characters
        if secret_name.len() > 512 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 512)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// Checks if an error indicates the resource was not found.
    fn is_not_found_error<E: std::error::Error + 'static>(e: &E) -> bool {
        let error_str = e.to_string();
        error_str.contains("ResourceNotFoundException") || error_str.contains("not found")
    }

    /// Checks if an error indicates the resource already exists.
    fn is_already_exists_error<E: std::error::Error + 'static>(e: &E) -> bool {
        let error_str = e.to_string();
        error_str.contains("ResourceExistsException") || error_str.contains("already exists")
    }

    /// Executes an async future in a blocking context.
    ///
    /// Creates a new tokio runtime for each operation. While this has some
    /// overhead, it ensures compatibility with SecretSpec's synchronous
    /// Provider trait.
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
            .block_on(future)
    }

    /// Creates a SecretsManagerService client.
    async fn create_client(&self) -> Result<SecretsManagerClient> {
        let mut config_builder = aws_config::defaults(BehaviorVersion::latest());

        // Use specified region or fall back to default from credential chain
        // (AWS_REGION, AWS_DEFAULT_REGION, ~/.aws/config, instance metadata)
        if let Some(region) = &self.config.region {
            config_builder = config_builder.region(Region::new(region.clone()));
        }

        // Use custom endpoint URL or fall back to default from credential chain
        // (AWS_ENDPOINT_URL env var)
        if let Some(endpoint) = &self.config.endpoint_url {
            config_builder = config_builder.endpoint_url(endpoint);
        }

        let sdk_config: SdkConfig = config_builder.load().await;
        Ok(SecretsManagerClient::new(&sdk_config))
    }

    /// Retrieves a secret value from AWS Secrets Manager.
    async fn get_secret_async(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<SecretString>> {
        let secret_name = self.format_secret_name(project, profile, key)?;
        let client = self.create_client().await?;

        match client
            .get_secret_value()
            .secret_id(&secret_name)
            .send()
            .await
        {
            Ok(response) => {
                // AWS Secrets Manager can return either SecretString or SecretBinary
                if let Some(secret_string) = response.secret_string {
                    Ok(Some(SecretString::new(secret_string.into())))
                } else if let Some(secret_binary) = response.secret_binary {
                    // Handle binary secrets by converting to UTF-8
                    let data =
                        String::from_utf8(secret_binary.into_inner().to_vec()).map_err(|e| {
                            SecretSpecError::ProviderOperationFailed(format!(
                                "Secret data is not valid UTF-8: {}",
                                e
                            ))
                        })?;
                    Ok(Some(SecretString::new(data.into())))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                // Check if the error is "not found" (secret doesn't exist)
                if Self::is_not_found_error(&e) {
                    return Ok(None);
                }
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to retrieve secret '{}': {}",
                    secret_name, e
                )))
            }
        }
    }

    /// Creates or updates a secret in AWS Secrets Manager.
    ///
    /// Always attempts to create the secret first (idempotent operation), then updates if it exists.
    /// This avoids TOCTOU race conditions by not checking existence before creation.
    async fn set_secret_async(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> Result<()> {
        let secret_name = self.format_secret_name(project, profile, key)?;
        let client = self.create_client().await?;

        // Try to create the secret first
        let create_result = client
            .create_secret()
            .name(&secret_name)
            .secret_string(value.expose_secret())
            .send()
            .await;

        match create_result {
            Ok(_) => Ok(()),
            Err(e) => {
                // If secret already exists, update it instead
                if Self::is_already_exists_error(&e) {
                    // Update existing secret
                    client
                        .put_secret_value()
                        .secret_id(&secret_name)
                        .secret_string(value.expose_secret())
                        .send()
                        .await
                        .map_err(|e| {
                            SecretSpecError::ProviderOperationFailed(format!(
                                "Failed to update secret '{}': {}",
                                secret_name, e
                            ))
                        })?;
                    return Ok(());
                }
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to create secret '{}': {}",
                    secret_name, e
                )))
            }
        }
    }
}

impl Provider for AwsSecretsManagerProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match (&self.config.region, &self.config.prefix) {
            (Some(region), Some(prefix)) => format!("aws://{}/{}", region, prefix),
            (Some(region), None) => format!("aws://{}", region),
            (None, Some(prefix)) => format!("aws:///{}", prefix),
            (None, None) => "aws://".to_string(),
        }
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        self.block_on(self.get_secret_async(project, key, profile))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        self.block_on(self.set_secret_async(project, key, value, profile))
    }

    fn allows_set(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_config_from_url() {
        let url = Url::parse("aws://us-east-1").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, Some("us-east-1".to_string()));
        assert_eq!(config.prefix, None);
    }

    #[test]
    fn test_aws_config_without_region() {
        let url = Url::parse("aws://").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, None);
        assert_eq!(config.prefix, None);
    }

    #[test]
    fn test_aws_config_with_prefix() {
        let url = Url::parse("aws://eu-west-2/myapp").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, Some("eu-west-2".to_string()));
        assert_eq!(config.prefix, Some("myapp".to_string()));
    }

    #[test]
    fn test_aws_config_with_endpoint() {
        let url = Url::parse("aws://us-east-1?endpoint=http://localhost:4566").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, Some("us-east-1".to_string()));
        assert_eq!(
            config.endpoint_url,
            Some("http://localhost:4566".to_string())
        );
    }

    #[test]
    fn test_aws_config_alternative_scheme() {
        let url = Url::parse("aws-secretsmanager://ap-southeast-1").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, Some("ap-southeast-1".to_string()));
    }

    #[test]
    fn test_aws_config_invalid_scheme() {
        let url = Url::parse("invalid://us-east-1").unwrap();
        let result = AwsSecretsManagerConfig::try_from(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_config_validates_invalid_region() {
        let url = Url::parse("aws://invalid_region").unwrap();
        let result = AwsSecretsManagerConfig::try_from(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_aws_region() {
        assert!(validate_aws_region("us-east-1").is_ok());
        assert!(validate_aws_region("eu-west-2").is_ok());
        assert!(validate_aws_region("ap-southeast-1").is_ok());
        assert!(validate_aws_region("localhost").is_ok()); // For LocalStack
        assert!(validate_aws_region("").is_err());
        assert!(validate_aws_region("invalid_region").is_err());
        assert!(validate_aws_region("us$east$1").is_err());
    }

    #[test]
    fn test_format_secret_name() {
        let config = AwsSecretsManagerConfig {
            region: Some("us-east-1".to_string()),
            prefix: None,
            endpoint_url: None,
        };
        let provider = AwsSecretsManagerProvider::new(config);

        let name = provider
            .format_secret_name("myproject", "production", "API_KEY")
            .unwrap();
        assert_eq!(name, "secretspec/myproject/production/API_KEY");
    }

    #[test]
    fn test_format_secret_name_with_prefix() {
        let config = AwsSecretsManagerConfig {
            region: Some("us-east-1".to_string()),
            prefix: Some("myapp".to_string()),
            endpoint_url: None,
        };
        let provider = AwsSecretsManagerProvider::new(config);

        let name = provider
            .format_secret_name("myproject", "production", "API_KEY")
            .unwrap();
        assert_eq!(name, "myapp/myproject/production/API_KEY");
    }

    #[test]
    fn test_format_secret_name_validates_components() {
        let config = AwsSecretsManagerConfig {
            region: Some("us-east-1".to_string()),
            prefix: None,
            endpoint_url: None,
        };
        let provider = AwsSecretsManagerProvider::new(config);

        // Empty component should fail
        assert!(
            provider
                .format_secret_name("", "production", "API_KEY")
                .is_err()
        );
        assert!(
            provider
                .format_secret_name("myproject", "", "API_KEY")
                .is_err()
        );
        assert!(
            provider
                .format_secret_name("myproject", "production", "")
                .is_err()
        );

        // Invalid characters should fail
        assert!(
            provider
                .format_secret_name("my/project", "production", "API_KEY")
                .is_err()
        );
        assert!(
            provider
                .format_secret_name("myproject", "produc tion", "API_KEY")
                .is_err()
        );
    }

    #[test]
    fn test_provider_uri() {
        let config = AwsSecretsManagerConfig {
            region: Some("us-east-1".to_string()),
            prefix: None,
            endpoint_url: None,
        };
        let provider = AwsSecretsManagerProvider::new(config);
        assert_eq!(provider.uri(), "aws://us-east-1");

        let config_with_prefix = AwsSecretsManagerConfig {
            region: Some("eu-west-2".to_string()),
            prefix: Some("myapp".to_string()),
            endpoint_url: None,
        };
        let provider_with_prefix = AwsSecretsManagerProvider::new(config_with_prefix);
        assert_eq!(provider_with_prefix.uri(), "aws://eu-west-2/myapp");

        let config_no_region = AwsSecretsManagerConfig {
            region: None,
            prefix: None,
            endpoint_url: None,
        };
        let provider_no_region = AwsSecretsManagerProvider::new(config_no_region);
        assert_eq!(provider_no_region.uri(), "aws://");

        // Test prefix without region (triple slash format)
        let config_prefix_no_region = AwsSecretsManagerConfig {
            region: None,
            prefix: Some("myapp".to_string()),
            endpoint_url: None,
        };
        let provider_prefix_no_region = AwsSecretsManagerProvider::new(config_prefix_no_region);
        assert_eq!(provider_prefix_no_region.uri(), "aws:///myapp");
    }

    #[test]
    fn test_aws_config_with_prefix_no_region() {
        // Test parsing triple slash URI
        let url = Url::parse("aws:///myapp").unwrap();
        let config = AwsSecretsManagerConfig::try_from(&url).unwrap();
        assert_eq!(config.region, None);
        assert_eq!(config.prefix, Some("myapp".to_string()));
    }

    #[test]
    fn test_round_trip_uri_with_prefix_no_region() {
        // Test that URI generation and parsing are symmetric for prefix without region
        let original_uri = "aws:///myapp";
        let config = AwsSecretsManagerConfig::try_from(&Url::parse(original_uri).unwrap()).unwrap();

        // Create provider and get URI
        let provider = AwsSecretsManagerProvider::new(config.clone());
        let regenerated_uri = provider.uri();

        // Parse the regenerated URI
        let reparsed_config =
            AwsSecretsManagerConfig::try_from(&Url::parse(&regenerated_uri).unwrap()).unwrap();

        // Verify round-trip
        assert_eq!(config.region, reparsed_config.region);
        assert_eq!(config.prefix, reparsed_config.prefix);
        assert_eq!(regenerated_uri, original_uri);
    }
}
