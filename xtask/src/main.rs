use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

const COVERAGE_LINE_FLOOR: f64 = 60.0;

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    match command.as_str() {
        "architecture" => check_architecture(),
        "benchmark-smoke" => benchmark_smoke(),
        "coverage" => coverage(),
        "verify" => verify(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => bail!("unknown command {other:?}; run `cargo xtask help`"),
    }
}

fn print_help() {
    println!("Rift repository tasks:\n");
    println!("  cargo xtask verify           Run the canonical validation firewall");
    println!("  cargo xtask architecture     Check crate dependency boundaries");
    println!("  cargo xtask coverage         Generate and enforce line coverage");
    println!("  cargo xtask benchmark-smoke  Exercise the Prototype 0 benchmark path");
}

fn verify() -> Result<()> {
    run_cargo(&["fmt", "--all", "--check"], &[])?;
    run_cargo(
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        &[],
    )?;
    run_cargo(&["test", "--workspace", "--all-features"], &[])?;
    run_cargo(
        &["doc", "--workspace", "--all-features", "--no-deps"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    check_architecture()?;
    run_cargo(&["deny", "check"], &[])?;
    println!("validation firewall passed");
    Ok(())
}

fn coverage() -> Result<()> {
    fs::create_dir_all(workspace_root().join("target/llvm-cov"))
        .context("unable to create coverage report directory")?;
    let floor = COVERAGE_LINE_FLOOR.to_string();
    run_cargo(
        &[
            "llvm-cov",
            "--workspace",
            "--all-features",
            "--lcov",
            "--output-path",
            "target/llvm-cov/lcov.info",
            "--fail-under-lines",
            &floor,
        ],
        &[],
    )?;
    run_cargo(&["llvm-cov", "report", "--summary-only"], &[])
}

fn benchmark_smoke() -> Result<()> {
    run_cargo(
        &[
            "run",
            "--package",
            "rift-spike",
            "--",
            "bench",
            "--bytes",
            "65536",
            "--protocol-iterations",
            "100",
        ],
        &[],
    )
}

fn run_cargo(arguments: &[&str], environment: &[(&str, &str)]) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .args(arguments)
        .current_dir(workspace_root())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (name, value) in environment {
        command.env(name, value);
    }
    eprintln!("+ cargo {}", arguments.join(" "));
    let status = command
        .status()
        .with_context(|| format!("unable to start `cargo {}`", arguments.join(" ")))?;
    ensure_success(&format!("cargo {}", arguments.join(" ")), status)
}

fn ensure_success(description: &str, status: ExitStatus) -> Result<()> {
    ensure!(status.success(), "`{description}` exited with {status}");
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn check_architecture() -> Result<()> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(workspace_root())
        .output()
        .context("unable to start `cargo metadata`")?;
    if !output.status.success() {
        bail!(
            "`cargo metadata` failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: Value =
        serde_json::from_slice(&output.stdout).context("`cargo metadata` returned invalid JSON")?;
    let policy = DependencyPolicy::from_metadata(&metadata)?;
    policy.validate()?;
    println!("architecture dependency policy passed");
    Ok(())
}

#[derive(Debug, Default)]
struct DependencyPolicy {
    direct_dependencies: BTreeMap<String, BTreeSet<String>>,
    requirements: BTreeMap<(String, String), String>,
}

impl DependencyPolicy {
    fn from_metadata(metadata: &Value) -> Result<Self> {
        let packages = metadata
            .get("packages")
            .and_then(Value::as_array)
            .context("cargo metadata has no packages array")?;
        let mut policy = Self::default();
        for package in packages {
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .context("cargo metadata package has no name")?;
            let dependencies = package
                .get("dependencies")
                .and_then(Value::as_array)
                .context("cargo metadata package has no dependencies array")?;
            let direct = policy
                .direct_dependencies
                .entry(name.to_owned())
                .or_default();
            for dependency in dependencies {
                let dependency_name = dependency
                    .get("name")
                    .and_then(Value::as_str)
                    .context("cargo metadata dependency has no name")?;
                let requirement = dependency
                    .get("req")
                    .and_then(Value::as_str)
                    .context("cargo metadata dependency has no version requirement")?;
                direct.insert(dependency_name.to_owned());
                policy.requirements.insert(
                    (name.to_owned(), dependency_name.to_owned()),
                    requirement.to_owned(),
                );
            }
        }
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        for package in ["rift-core", "rift-protocol", "rift-transport-iroh"] {
            ensure!(
                self.direct_dependencies.contains_key(package),
                "required production package {package} is missing from the workspace"
            );
        }

        self.reject_reachable("rift-core", &["iroh", "iroh-relay", "rift-transport-iroh"])?;
        self.reject_reachable(
            "rift-protocol",
            &["iroh", "iroh-relay", "rift-transport-iroh"],
        )?;
        self.reject_direct("rift-transport-iroh", "iroh-relay")?;
        self.require_exact("rift-transport-iroh", "iroh", "=1.0.3")?;
        self.require_exact("rift-spike", "iroh", "=1.0.3")?;
        self.require_exact("rift-spike", "iroh-relay", "=1.0.3")?;
        Ok(())
    }

    fn reject_direct(&self, package: &str, forbidden: &str) -> Result<()> {
        if self
            .direct_dependencies
            .get(package)
            .is_some_and(|dependencies| dependencies.contains(forbidden))
        {
            bail!("architecture violation: {package} must not depend directly on {forbidden}");
        }
        Ok(())
    }

    fn reject_reachable(&self, package: &str, forbidden: &[&str]) -> Result<()> {
        let mut pending = vec![package.to_owned()];
        let mut visited = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            let Some(dependencies) = self.direct_dependencies.get(&current) else {
                continue;
            };
            for dependency in dependencies {
                if forbidden.contains(&dependency.as_str()) {
                    bail!(
                        "architecture violation: {package} reaches forbidden dependency {dependency}"
                    );
                }
                pending.push(dependency.clone());
            }
        }
        Ok(())
    }

    fn require_exact(&self, package: &str, dependency: &str, expected: &str) -> Result<()> {
        let key = (package.to_owned(), dependency.to_owned());
        let actual = self.requirements.get(&key).with_context(|| {
            format!("{package} must declare the validated {dependency} dependency")
        })?;
        ensure!(
            actual == expected,
            "{package} must pin {dependency} to {expected}; found {actual}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy() -> DependencyPolicy {
        let mut policy = DependencyPolicy::default();
        for package in [
            "rift-core",
            "rift-protocol",
            "rift-spike",
            "rift-transport-iroh",
        ] {
            policy
                .direct_dependencies
                .entry(package.to_owned())
                .or_default();
        }
        policy
            .direct_dependencies
            .entry("rift-transport-iroh".to_owned())
            .or_default()
            .insert("iroh".to_owned());
        policy
            .direct_dependencies
            .entry("rift-spike".to_owned())
            .or_default()
            .extend(["iroh".to_owned(), "iroh-relay".to_owned()]);
        for (package, dependency) in [
            ("rift-transport-iroh", "iroh"),
            ("rift-spike", "iroh"),
            ("rift-spike", "iroh-relay"),
        ] {
            policy.requirements.insert(
                (package.to_owned(), dependency.to_owned()),
                "=1.0.3".to_owned(),
            );
        }
        policy
    }

    #[test]
    fn current_dependency_direction_is_allowed() -> Result<()> {
        valid_policy().validate()
    }

    #[test]
    fn transitive_transport_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy
            .direct_dependencies
            .entry("rift-core".to_owned())
            .or_default()
            .insert("helper".to_owned());
        policy
            .direct_dependencies
            .insert("helper".to_owned(), BTreeSet::from(["iroh".to_owned()]));
        assert!(policy.validate().is_err());
    }

    #[test]
    fn protocol_iroh_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy
            .direct_dependencies
            .entry("rift-protocol".to_owned())
            .or_default()
            .insert("iroh".to_owned());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn production_relay_server_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy
            .direct_dependencies
            .entry("rift-transport-iroh".to_owned())
            .or_default()
            .insert("iroh-relay".to_owned());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn unpinned_iroh_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy.requirements.insert(
            ("rift-transport-iroh".to_owned(), "iroh".to_owned()),
            "1.0.3".to_owned(),
        );
        assert!(policy.validate().is_err());
    }

    #[test]
    fn command_failure_is_propagated() -> Result<()> {
        let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .arg("--rift-intentional-invalid-option")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("unable to start rustc for command-failure test")?;
        assert!(ensure_success("intentional failure", status).is_err());
        Ok(())
    }
}
