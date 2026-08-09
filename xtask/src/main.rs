use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
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
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        &[],
    )?;
    run_cargo(&["test", "--locked", "--workspace", "--all-features"], &[])?;
    run_cargo(
        &[
            "doc",
            "--locked",
            "--workspace",
            "--all-features",
            "--no-deps",
        ],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    check_architecture()?;
    run_cargo(&["deny", "--locked", "check"], &[])?;
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
            "--locked",
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
            "--locked",
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

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    resolve: CargoResolve,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    #[serde(default)]
    dependencies: Vec<ManifestDependency>,
}

#[derive(Debug, Deserialize)]
struct ManifestDependency {
    name: String,
    req: String,
}

#[derive(Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoResolveNode>,
}

#[derive(Debug, Deserialize)]
struct CargoResolveNode {
    id: String,
    #[serde(default)]
    deps: Vec<CargoResolvedDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoResolvedDependency {
    pkg: String,
}

#[derive(Debug, Default)]
struct DependencyPolicy {
    package_names: BTreeMap<String, String>,
    workspace_members: BTreeSet<String>,
    resolved_dependencies: BTreeMap<String, BTreeSet<String>>,
    requirements: BTreeMap<(String, String), String>,
}

impl DependencyPolicy {
    fn from_metadata(metadata: &Value) -> Result<Self> {
        let metadata: CargoMetadata = serde_json::from_value(metadata.clone())
            .context("cargo metadata has an unexpected schema")?;
        let package_names = metadata
            .packages
            .iter()
            .map(|package| (package.id.clone(), package.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let workspace_members = metadata.workspace_members.into_iter().collect();
        let mut requirements = BTreeMap::new();
        for package in metadata.packages {
            for dependency in package.dependencies {
                requirements.insert((package.id.clone(), dependency.name), dependency.req);
            }
        }

        let mut resolved_dependencies = BTreeMap::new();
        for node in metadata.resolve.nodes {
            ensure!(
                package_names.contains_key(&node.id),
                "cargo resolve node {0} has no matching package",
                node.id
            );
            let dependencies = node
                .deps
                .into_iter()
                .map(|dependency| dependency.pkg)
                .collect::<BTreeSet<_>>();
            for dependency in &dependencies {
                ensure!(
                    package_names.contains_key(dependency),
                    "cargo resolved dependency {dependency} has no matching package"
                );
            }
            resolved_dependencies.insert(node.id, dependencies);
        }

        Ok(Self {
            package_names,
            workspace_members,
            resolved_dependencies,
            requirements,
        })
    }

    fn validate(&self) -> Result<()> {
        for package in ["rift-core", "rift-protocol", "rift-transport-iroh"] {
            self.workspace_package_id(package)?;
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

    fn workspace_package_id(&self, package: &str) -> Result<String> {
        let mut matching = self.workspace_members.iter().filter(|package_id| {
            self.package_names
                .get(*package_id)
                .is_some_and(|name| name == package)
        });
        let package_id = matching
            .next()
            .cloned()
            .with_context(|| format!("required workspace package {package} is missing"))?;
        ensure!(
            matching.next().is_none(),
            "workspace contains multiple packages named {package}"
        );
        Ok(package_id)
    }

    fn package_name<'a>(&'a self, package_id: &str) -> Result<&'a str> {
        self.package_names
            .get(package_id)
            .map(String::as_str)
            .with_context(|| format!("resolved package {package_id} has no package metadata"))
    }

    fn reject_direct(&self, package: &str, forbidden: &str) -> Result<()> {
        let package_id = self.workspace_package_id(package)?;
        let Some(dependencies) = self.resolved_dependencies.get(&package_id) else {
            return Ok(());
        };
        for dependency in dependencies {
            if self.package_name(dependency)? == forbidden {
                bail!("architecture violation: {package} must not depend directly on {forbidden}");
            }
        }
        Ok(())
    }

    fn reject_reachable(&self, package: &str, forbidden: &[&str]) -> Result<()> {
        let mut pending = vec![self.workspace_package_id(package)?];
        let mut visited = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            let Some(dependencies) = self.resolved_dependencies.get(&current) else {
                continue;
            };
            for dependency in dependencies {
                let dependency_name = self.package_name(dependency)?;
                if forbidden.contains(&dependency_name) {
                    bail!(
                        "architecture violation: {package} reaches forbidden dependency {dependency_name}"
                    );
                }
                pending.push(dependency.clone());
            }
        }
        Ok(())
    }

    fn require_exact(&self, package: &str, dependency: &str, expected: &str) -> Result<()> {
        let package_id = self.workspace_package_id(package)?;
        let key = (package_id.clone(), dependency.to_owned());
        let actual = self.requirements.get(&key).with_context(|| {
            format!("{package} must declare the validated {dependency} dependency")
        })?;
        ensure!(
            actual == expected,
            "{package} must pin {dependency} to {expected}; found {actual}"
        );
        let has_resolved_dependency = self
            .resolved_dependencies
            .get(&package_id)
            .into_iter()
            .flatten()
            .any(|resolved_id| {
                self.package_names
                    .get(resolved_id)
                    .is_some_and(|name| name == dependency)
            });
        ensure!(
            has_resolved_dependency,
            "{package} must resolve its direct {dependency} dependency"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid_policy() -> DependencyPolicy {
        let mut policy = DependencyPolicy::default();
        let workspace_packages = [
            ("workspace#rift-core", "rift-core"),
            ("workspace#rift-protocol", "rift-protocol"),
            ("workspace#rift-spike", "rift-spike"),
            ("workspace#rift-transport-iroh", "rift-transport-iroh"),
        ];
        for (package_id, package_name) in workspace_packages {
            policy
                .package_names
                .insert(package_id.to_owned(), package_name.to_owned());
            policy.workspace_members.insert(package_id.to_owned());
        }
        policy.package_names.extend([
            ("registry#iroh@1.0.3".to_owned(), "iroh".to_owned()),
            (
                "registry#iroh-relay@1.0.3".to_owned(),
                "iroh-relay".to_owned(),
            ),
        ]);
        policy
            .resolved_dependencies
            .insert("workspace#rift-core".to_owned(), BTreeSet::new());
        policy
            .resolved_dependencies
            .insert("workspace#rift-protocol".to_owned(), BTreeSet::new());
        policy.resolved_dependencies.insert(
            "workspace#rift-transport-iroh".to_owned(),
            BTreeSet::from(["registry#iroh@1.0.3".to_owned()]),
        );
        policy.resolved_dependencies.insert(
            "workspace#rift-spike".to_owned(),
            BTreeSet::from([
                "registry#iroh@1.0.3".to_owned(),
                "registry#iroh-relay@1.0.3".to_owned(),
            ]),
        );
        policy
            .resolved_dependencies
            .insert("registry#iroh@1.0.3".to_owned(), BTreeSet::new());
        policy
            .resolved_dependencies
            .insert("registry#iroh-relay@1.0.3".to_owned(), BTreeSet::new());
        for (package, dependency) in [
            ("workspace#rift-transport-iroh", "iroh"),
            ("workspace#rift-spike", "iroh"),
            ("workspace#rift-spike", "iroh-relay"),
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
            .package_names
            .insert("registry#helper@1.0.0".to_owned(), "helper".to_owned());
        policy.resolved_dependencies.insert(
            "workspace#rift-core".to_owned(),
            BTreeSet::from(["registry#helper@1.0.0".to_owned()]),
        );
        policy.resolved_dependencies.insert(
            "registry#helper@1.0.0".to_owned(),
            BTreeSet::from(["registry#iroh@1.0.3".to_owned()]),
        );
        assert!(policy.validate().is_err());
    }

    #[test]
    fn protocol_iroh_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy.resolved_dependencies.insert(
            "workspace#rift-protocol".to_owned(),
            BTreeSet::from(["registry#iroh@1.0.3".to_owned()]),
        );
        assert!(policy.validate().is_err());
    }

    #[test]
    fn production_relay_server_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy.resolved_dependencies.insert(
            "workspace#rift-transport-iroh".to_owned(),
            BTreeSet::from(["registry#iroh-relay@1.0.3".to_owned()]),
        );
        assert!(policy.validate().is_err());
    }

    #[test]
    fn unpinned_iroh_dependency_is_rejected() {
        let mut policy = valid_policy();
        policy.requirements.insert(
            (
                "workspace#rift-transport-iroh".to_owned(),
                "iroh".to_owned(),
            ),
            "1.0.3".to_owned(),
        );
        assert!(policy.validate().is_err());
    }

    fn metadata_fixture() -> Value {
        json!({
            "packages": [
                {
                    "id": "workspace#rift-core",
                    "name": "rift-core",
                    "dependencies": [
                        { "name": "iroh", "req": "=1.0.3", "optional": true },
                        { "name": "helper", "req": "=1.0.0" }
                    ]
                },
                {
                    "id": "workspace#rift-protocol",
                    "name": "rift-protocol",
                    "dependencies": []
                },
                {
                    "id": "workspace#rift-spike",
                    "name": "rift-spike",
                    "dependencies": [
                        { "name": "iroh", "req": "=1.0.3" },
                        { "name": "iroh-relay", "req": "=1.0.3" }
                    ]
                },
                {
                    "id": "workspace#rift-transport-iroh",
                    "name": "rift-transport-iroh",
                    "dependencies": [
                        { "name": "iroh", "req": "=1.0.3" }
                    ]
                },
                {
                    "id": "registry#iroh@1.0.3",
                    "name": "iroh",
                    "dependencies": []
                },
                {
                    "id": "registry#iroh-relay@1.0.3",
                    "name": "iroh-relay",
                    "dependencies": []
                },
                {
                    "id": "registry#helper@1.0.0",
                    "name": "helper",
                    "dependencies": []
                },
                {
                    "id": "registry#helper@2.0.0",
                    "name": "helper",
                    "dependencies": [
                        { "name": "iroh", "req": "=1.0.3" }
                    ]
                }
            ],
            "workspace_members": [
                "workspace#rift-core",
                "workspace#rift-protocol",
                "workspace#rift-spike",
                "workspace#rift-transport-iroh"
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "workspace#rift-core",
                        "deps": [
                            { "pkg": "registry#helper@1.0.0" }
                        ]
                    },
                    {
                        "id": "workspace#rift-protocol",
                        "deps": []
                    },
                    {
                        "id": "workspace#rift-spike",
                        "deps": [
                            { "pkg": "registry#iroh@1.0.3" },
                            { "pkg": "registry#iroh-relay@1.0.3" }
                        ]
                    },
                    {
                        "id": "workspace#rift-transport-iroh",
                        "deps": [
                            { "pkg": "registry#iroh@1.0.3" }
                        ]
                    },
                    {
                        "id": "registry#iroh@1.0.3",
                        "deps": []
                    },
                    {
                        "id": "registry#iroh-relay@1.0.3",
                        "deps": []
                    },
                    {
                        "id": "registry#helper@1.0.0",
                        "deps": []
                    },
                    {
                        "id": "registry#helper@2.0.0",
                        "deps": [
                            { "pkg": "registry#iroh@1.0.3" }
                        ]
                    }
                ]
            }
        })
    }

    #[test]
    fn resolved_graph_uses_package_ids_for_duplicate_versions() -> Result<()> {
        let policy = DependencyPolicy::from_metadata(&metadata_fixture())?;
        policy.validate()
    }

    #[test]
    fn inactive_optional_dependencies_are_not_treated_as_reachable() -> Result<()> {
        let policy = DependencyPolicy::from_metadata(&metadata_fixture())?;
        let core_dependencies = policy
            .resolved_dependencies
            .get("workspace#rift-core")
            .context("fixture is missing the rift-core resolve node")?;
        assert!(!core_dependencies.iter().any(|dependency| {
            policy
                .package_names
                .get(dependency)
                .is_some_and(|name| name == "iroh")
        }));
        policy.validate()
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
