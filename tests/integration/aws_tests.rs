use secrecy::{ExposeSecret, SecretString};
use secretspec::Provider;
use std::convert::TryFrom;
use testcontainers::{ImageExt, core::IntoContainerPort, runners::AsyncRunner};
use testcontainers_modules::localstack::LocalStack;

fn get_test_providers() -> Vec<String> {
    std::env::var("SECRETSPEC_TEST_PROVIDERS")
        .unwrap_or_else(|_| String::new())
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

fn generate_test_project_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let suffix = timestamp % 100000;
    format!("secretspec_test_{}", suffix)
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn test_aws_provider_with_localstack() {
    let providers = get_test_providers();
    if !providers.contains(&"aws".to_string()) {
        println!(
            "Skipping AWS integration test (SECRETSPEC_TEST_PROVIDERS does not include 'aws')"
        );
        return;
    }

    let localstack = LocalStack::default()
        .with_env_var("SERVICES", "secretsmanager")
        .start()
        .await
        .expect("Should start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("Should get LocalStack port");
    let endpoint = format!("http://localhost:{}", host_port);

    let provider_uri = format!("aws://us-east-1?endpoint={}", endpoint);
    let provider = Box::<dyn Provider>::try_from(provider_uri.as_str())
        .expect("Should create AWS provider with LocalStack endpoint");

    let project_name = generate_test_project_name();

    // Test 1: Get non-existent secret
    let result = provider.get(&project_name, "TEST_PASSWORD", "default");
    match result {
        Ok(None) => {
            // Expected: key doesn't exist
        }
        Ok(Some(_)) => {
            panic!("Should not find non-existent secret");
        }
        Err(_) => {
            // Some providers may return error instead of None
        }
    }

    // Test 2: Set a secret
    let test_value = SecretString::new("test_password_aws".into());
    provider
        .set(&project_name, "TEST_PASSWORD", &test_value, "default")
        .expect("Should set secret");

    // Test 3: Retrieve the secret
    let retrieved = provider
        .get(&project_name, "TEST_PASSWORD", "default")
        .expect("Should get secret")
        .expect("Should find secret");

    assert_eq!(
        retrieved.expose_secret(),
        "test_password_aws",
        "Retrieved value should match set value"
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn test_aws_provider_without_region_with_localstack() {
    let providers = get_test_providers();
    if !providers.contains(&"aws".to_string()) {
        println!(
            "Skipping AWS integration test (SECRETSPEC_TEST_PROVIDERS does not include 'aws')"
        );
        return;
    }

    let localstack = LocalStack::default()
        .with_env_var("SERVICES", "secretsmanager")
        .start()
        .await
        .expect("Should start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("Should get LocalStack port");
    let endpoint = format!("http://localhost:{}", host_port);

    let provider_uri = format!("aws://?endpoint={}", endpoint);
    let provider = Box::<dyn Provider>::try_from(provider_uri.as_str())
        .expect("Should create AWS provider without region");

    let project_name = generate_test_project_name();
    let test_value = SecretString::new("test_value_no_region".into());

    provider
        .set(&project_name, "TEST_KEY", &test_value, "default")
        .expect("Should set secret");

    let retrieved = provider
        .get(&project_name, "TEST_KEY", "default")
        .expect("Should get secret")
        .expect("Should find secret");

    assert_eq!(retrieved.expose_secret(), "test_value_no_region");
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn test_aws_provider_with_prefix_and_localstack() {
    let providers = get_test_providers();
    if !providers.contains(&"aws".to_string()) {
        println!(
            "Skipping AWS integration test (SECRETSPEC_TEST_PROVIDERS does not include 'aws')"
        );
        return;
    }

    let localstack = LocalStack::default()
        .with_env_var("SERVICES", "secretsmanager")
        .start()
        .await
        .expect("Should start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("Should get LocalStack port");
    let endpoint = format!("http://localhost:{}", host_port);

    let provider_uri = format!("aws://us-east-1/myapp?endpoint={}", endpoint);
    let provider = Box::<dyn Provider>::try_from(provider_uri.as_str())
        .expect("Should create AWS provider with prefix");

    let project_name = generate_test_project_name();
    let test_value = SecretString::new("test_value_with_prefix".into());

    provider
        .set(&project_name, "TEST_KEY", &test_value, "default")
        .expect("Should set secret with prefix");

    let retrieved = provider
        .get(&project_name, "TEST_KEY", "default")
        .expect("Should get secret with prefix")
        .expect("Should find secret");

    assert_eq!(retrieved.expose_secret(), "test_value_with_prefix");
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn test_aws_provider_profile_isolation_with_localstack() {
    let providers = get_test_providers();
    if !providers.contains(&"aws".to_string()) {
        println!(
            "Skipping AWS integration test (SECRETSPEC_TEST_PROVIDERS does not include 'aws')"
        );
        return;
    }

    let localstack = LocalStack::default()
        .with_env_var("SERVICES", "secretsmanager")
        .start()
        .await
        .expect("Should start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("Should get LocalStack port");
    let endpoint = format!("http://localhost:{}", host_port);

    let provider_uri = format!("aws://us-east-1?endpoint={}", endpoint);
    let provider =
        Box::<dyn Provider>::try_from(provider_uri.as_str()).expect("Should create AWS provider");

    let project_name = generate_test_project_name();
    let dev_value = SecretString::new("dev_secret".into());
    let prod_value = SecretString::new("prod_secret".into());

    provider
        .set(&project_name, "API_KEY", &dev_value, "development")
        .expect("Should set dev secret");
    provider
        .set(&project_name, "API_KEY", &prod_value, "production")
        .expect("Should set prod secret");

    let dev_retrieved = provider
        .get(&project_name, "API_KEY", "development")
        .expect("Should get dev secret")
        .expect("Should find dev secret");
    assert_eq!(dev_retrieved.expose_secret(), "dev_secret");

    let prod_retrieved = provider
        .get(&project_name, "API_KEY", "production")
        .expect("Should get prod secret")
        .expect("Should find prod secret");
    assert_eq!(prod_retrieved.expose_secret(), "prod_secret");
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn test_aws_provider_special_characters_with_localstack() {
    let providers = get_test_providers();
    if !providers.contains(&"aws".to_string()) {
        println!(
            "Skipping AWS integration test (SECRETSPEC_TEST_PROVIDERS does not include 'aws')"
        );
        return;
    }

    let localstack = LocalStack::default()
        .with_env_var("SERVICES", "secretsmanager")
        .start()
        .await
        .expect("Should start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("Should get LocalStack port");
    let endpoint = format!("http://localhost:{}", host_port);

    let provider_uri = format!("aws://us-east-1?endpoint={}", endpoint);
    let provider =
        Box::<dyn Provider>::try_from(provider_uri.as_str()).expect("Should create AWS provider");

    let project_name = generate_test_project_name();

    // Test special characters in secret value
    let special_value =
        SecretString::new("password=with=symbols!@#$%^&*(){}[]|;':\",./<>?`~".into());
    provider
        .set(&project_name, "SPECIAL_CHARS", &special_value, "default")
        .expect("Should set secret with special characters");

    let retrieved = provider
        .get(&project_name, "SPECIAL_CHARS", "default")
        .expect("Should get secret")
        .expect("Should find secret");

    assert_eq!(
        retrieved.expose_secret(),
        "password=with=symbols!@#$%^&*(){}[]|;':\",./<>?`~"
    );

    // Test multiline value
    let multiline_value = SecretString::new("line1\nline2\nline3".into());
    provider
        .set(&project_name, "MULTILINE", &multiline_value, "default")
        .expect("Should set multiline secret");

    let retrieved = provider
        .get(&project_name, "MULTILINE", "default")
        .expect("Should get multiline secret")
        .expect("Should find multiline secret");

    assert_eq!(retrieved.expose_secret(), "line1\nline2\nline3");
}
