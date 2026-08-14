use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Serialize;

use crate::workspace::Workspace;

pub struct AffectedOptions {
    base: Option<String>,
    head: String,
    changed_files: Vec<PathBuf>,
    github_output: Option<PathBuf>,
    json: bool,
}

impl AffectedOptions {
    pub fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut base = None;
        let mut head = "HEAD".to_owned();
        let mut changed_files = Vec::new();
        let mut github_output = None;
        let mut json = false;
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--base" => base = Some(next_value(&mut arguments, "--base")?),
                "--head" => head = next_value(&mut arguments, "--head")?,
                "--changed-file" => {
                    changed_files
                        .push(PathBuf::from(next_value(&mut arguments, "--changed-file")?));
                }
                "--github-output" => {
                    github_output = Some(PathBuf::from(next_value(
                        &mut arguments,
                        "--github-output",
                    )?));
                }
                "--json" => json = true,
                _ => return Err(format!("unknown affected option: {argument}").into()),
            }
        }
        Ok(Self {
            base,
            head,
            changed_files,
            github_output,
            json,
        })
    }
}

fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct AffectedSet {
    pub packages: BTreeSet<String>,
    pub apple: bool,
    pub full: bool,
    pub manifests: bool,
    pub layer_source: bool,
}

pub fn run(workspace: &Workspace, options: AffectedOptions) -> Result<(), Box<dyn Error>> {
    let changed_files = if options.changed_files.is_empty() {
        git_changed_files(
            workspace.root(),
            options.base.as_deref().unwrap_or("HEAD^"),
            &options.head,
        )?
    } else {
        options.changed_files
    };
    let affected = compute(workspace, &changed_files)?;
    let encoded = serde_json::to_string(&affected)?;
    if options.json {
        println!("{encoded}");
    } else {
        println!(
            "Affected packages: {}",
            display_packages(&affected.packages)
        );
        println!("Apple job: {}", affected.apple);
        println!("Full workspace: {}", affected.full);
    }
    if let Some(output) = options.github_output {
        let encoded_packages = serde_json::to_string(&affected.packages)?;
        let package_arguments = affected
            .packages
            .iter()
            .map(|package| format!("-p {package}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut output = OpenOptions::new().create(true).append(true).open(output)?;
        write!(
            output,
            "affected={encoded}\npackages={encoded_packages}\npackage_args={package_arguments}\nhas_packages={}\napple={}\nfull={}\nmanifests={}\nlayer_source={}\n",
            !affected.packages.is_empty(),
            affected.apple,
            affected.full,
            affected.manifests,
            affected.layer_source,
        )?;
    }
    Ok(())
}

fn display_packages(packages: &BTreeSet<String>) -> String {
    if packages.is_empty() {
        "none".to_owned()
    } else {
        packages.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn git_changed_files(root: &Path, base: &str, head: &str) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--no-renames", base, head, "--"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect())
}

pub fn compute(
    workspace: &Workspace,
    changed_files: &[PathBuf],
) -> Result<AffectedSet, Box<dyn Error>> {
    let mut result = AffectedSet::default();
    let mut seeds = BTreeSet::new();
    for path in changed_files {
        let normalized = normalized_path(path);
        if is_full_workspace_path(&normalized) {
            result.full = true;
        }
        if normalized == "Cargo.lock"
            || normalized.ends_with("/Cargo.toml")
            || normalized == "Cargo.toml"
        {
            result.manifests = true;
        }
        if normalized.starts_with("apple/") || normalized == "Package.swift" {
            result.apple = true;
            seeds.extend(ffi_packages(workspace));
            continue;
        }
        if normalized.starts_with("bindings/c/") {
            result.apple = true;
            seeds.extend(ffi_packages(workspace));
            continue;
        }
        if normalized.starts_with("fixtures/") {
            seeds.extend(fixture_consumers(workspace.root(), &normalized)?);
            continue;
        }
        if let Some(package) = workspace.package_for_path(path) {
            if is_layer(&package.directory, workspace.root(), "crates/ffi") {
                result.apple = true;
            }
            seeds.insert(package.name.clone());
            continue;
        }
        if is_ignored_path(&normalized) {
            continue;
        }
        result.full = true;
    }
    result.packages = if result.full {
        workspace.package_names()
    } else {
        workspace.reverse_closure(&seeds)
    };
    result.apple |= result.packages.iter().any(|name| {
        workspace
            .package(name)
            .is_some_and(|package| is_layer(&package.directory, workspace.root(), "crates/ffi"))
    });
    result.layer_source = result.packages.iter().any(|name| {
        workspace
            .package(name)
            .is_some_and(|package| is_l0_or_l1(&package.directory, workspace.root()))
    });
    Ok(result)
}

fn normalized_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_full_workspace_path(path: &str) -> bool {
    path == "Cargo.toml"
        || path == "Cargo.lock"
        || path.starts_with("rust-toolchain")
        || path.starts_with(".cargo/")
        || path.starts_with("xtask/")
        || path.starts_with(".github/workflows/")
}

fn is_ignored_path(path: &str) -> bool {
    path.starts_with("docs/")
        || path.starts_with("plans/")
        || path == "README.md"
        || path == "LICENSE"
        || path == ".gitignore"
}

fn is_l0_or_l1(directory: &Path, root: &Path) -> bool {
    ["crates/contract", "crates/proto", "crates/egress"]
        .iter()
        .any(|prefix| is_layer(directory, root, prefix))
}

fn is_layer(directory: &Path, root: &Path, layer: &str) -> bool {
    directory
        .strip_prefix(root)
        .is_ok_and(|relative| relative.starts_with(layer))
}

fn ffi_packages(workspace: &Workspace) -> BTreeSet<String> {
    workspace
        .packages()
        .filter(|package| {
            package
                .directory
                .strip_prefix(workspace.root())
                .is_ok_and(|path| path.starts_with("crates/ffi"))
        })
        .map(|package| package.name.clone())
        .collect()
}

fn fixture_consumers(root: &Path, changed_path: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut components = changed_path.split('/');
    if components.next() != Some("fixtures") {
        return Ok(BTreeSet::new());
    }
    let bundle = components.next().ok_or("fixture path has no bundle")?;
    let manifest = root.join("fixtures").join(bundle).join("consumers.toml");
    let contents = fs::read_to_string(&manifest)
        .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
    parse_consumers(&contents)
}

fn parse_consumers(contents: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let line = contents
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("consumers"))
        .ok_or("fixture manifest has no consumers")?;
    let (_, value) = line.split_once('=').ok_or("invalid consumers entry")?;
    let value = value.trim();
    let list = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or("consumers must be an array")?;
    list.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .map(str::to_owned)
                .ok_or_else(|| "consumer names must be quoted".into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf};

    use super::{AffectedSet, compute, parse_consumers};
    use crate::workspace::Workspace;

    fn workspace() -> Workspace {
        Workspace::for_test(
            &[
                ("core", &[]),
                ("proto", &["core"]),
                ("server", &["proto"]),
                ("store", &["core"]),
                ("runtime-ffi", &["store"]),
                ("local-server-ffi", &["runtime-ffi", "server"]),
                ("server-e2e", &["local-server-ffi"]),
            ],
            &[
                ("core", "crates/contract/core"),
                ("proto", "crates/proto/proto"),
                ("server", "crates/engine/server"),
                ("store", "crates/store/store"),
                ("runtime-ffi", "crates/ffi/runtime"),
                ("local-server-ffi", "crates/ffi/server"),
                ("server-e2e", "itests/server-e2e"),
            ],
        )
    }

    #[test]
    fn contract_break_reaches_every_dependent() -> Result<(), Box<dyn std::error::Error>> {
        let actual = compute(
            &workspace(),
            &[PathBuf::from("crates/contract/core/src/lib.rs")],
        )?;
        assert_eq!(actual.packages, workspace().package_names());
        assert!(actual.layer_source);
        Ok(())
    }

    #[test]
    fn docs_changes_schedule_no_crates() -> Result<(), Box<dyn std::error::Error>> {
        let actual = compute(&workspace(), &[PathBuf::from("docs/architecture.md")])?;
        assert_eq!(actual, AffectedSet::default());
        Ok(())
    }

    #[test]
    fn store_changes_reach_ffi_and_integration_only() -> Result<(), Box<dyn std::error::Error>> {
        let actual = compute(
            &workspace(),
            &[PathBuf::from("crates/store/store/src/lib.rs")],
        )?;
        assert_eq!(
            actual.packages,
            BTreeSet::from([
                "store".to_owned(),
                "runtime-ffi".to_owned(),
                "local-server-ffi".to_owned(),
                "server-e2e".to_owned(),
            ])
        );
        Ok(())
    }

    #[test]
    fn parses_fixture_consumer_manifests() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_consumers("version = 1\nconsumers = [\"rest\", \"mcp\"]\n")?,
            BTreeSet::from(["mcp".to_owned(), "rest".to_owned()])
        );
        Ok(())
    }
}
