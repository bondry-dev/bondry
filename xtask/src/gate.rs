use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use syn::{Path as SynPath, UseTree, visit::Visit};

use crate::workspace::{Package, Workspace};

const FORBIDDEN_RUNTIME_PACKAGES: &[&str] = &[
    "hyper",
    "hyper-util",
    "rustls",
    "tokio",
    "tokio-rustls",
    "tokio-tungstenite",
    "tungstenite",
];

pub fn run(workspace: &Workspace) -> Result<(), Box<dyn Error>> {
    let mut violations = Vec::new();
    check_layer_dependencies(workspace, &mut violations);
    check_layer_sources(workspace, &mut violations)?;
    check_openssl_confinement(workspace, &mut violations)?;
    check_egress_runtime_tokio_features(workspace, &mut violations)?;
    check_local_mcp_transport_profile(workspace, &mut violations)?;
    check_consumer_profiles(workspace, &mut violations);
    if violations.is_empty() {
        println!("Architecture gates passed");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("gate violation: {violation}");
    }
    Err(format!("{} architecture gate violation(s)", violations.len()).into())
}

fn check_local_mcp_transport_profile(
    workspace: &Workspace,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    if workspace.package("bondry-egress-mcp").is_none() {
        return Ok(());
    }
    let output = Command::new("cargo")
        .args([
            "tree",
            "--package",
            "bondry-transport-net",
            "--no-default-features",
            "--features",
            "http",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--locked",
        ])
        .current_dir(workspace.root())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let tree = String::from_utf8(output.stdout)?;
    let packages = tree
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().next())
        .collect::<BTreeSet<_>>();
    for forbidden in ["rustls", "rustls-platform-verifier", "tokio-rustls"] {
        if packages.contains(forbidden) {
            violations.push(format!(
                "local MCP HTTP transport reaches forbidden TLS package {forbidden}"
            ));
        }
    }
    for required in ["hyper", "tokio"] {
        if !packages.contains(required) {
            violations.push(format!(
                "local MCP HTTP transport omits required package {required}"
            ));
        }
    }
    Ok(())
}

fn check_egress_runtime_tokio_features(
    workspace: &Workspace,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    if workspace.package("bondry-egress-runtime").is_none() {
        return Ok(());
    };
    let output = Command::new("cargo")
        .args([
            "tree",
            "--package",
            "bondry-egress-runtime",
            "--edges",
            "normal,build,features",
            "--prefix",
            "none",
            "--locked",
        ])
        .current_dir(workspace.root())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let tree = String::from_utf8(output.stdout)?;
    let enabled = tree
        .lines()
        .filter_map(|line| {
            line.strip_prefix("tokio feature \"")
                .and_then(|feature| feature.strip_suffix('"'))
        })
        .collect::<BTreeSet<_>>();
    let allowed = ["macros", "rt", "sync", "time", "tokio-macros"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    for forbidden in enabled.difference(&allowed) {
        violations.push(format!(
            "bondry-egress-runtime enables unexpected Tokio feature {forbidden}"
        ));
    }
    for required in ["macros", "rt", "sync", "time"] {
        if !enabled.contains(required) {
            violations.push(format!(
                "bondry-egress-runtime omits required Tokio feature {required}"
            ));
        }
    }
    for forbidden in ["mio ", "socket2 "] {
        if tree.lines().any(|line| line.starts_with(forbidden)) {
            violations.push(format!(
                "bondry-egress-runtime reaches forbidden network package {}",
                forbidden.trim()
            ));
        }
    }
    Ok(())
}

fn check_layer_dependencies(workspace: &Workspace, violations: &mut Vec<String>) {
    let engine_packages = workspace
        .packages()
        .filter(|package| is_layer(package, workspace.root(), "crates/engine"))
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    for package in workspace
        .packages()
        .filter(|package| is_logic_layer(package, workspace.root()))
    {
        let closure = workspace.dependency_closure(&[&package.name]);
        let forbidden = closure
            .iter()
            .filter(|name| {
                FORBIDDEN_RUNTIME_PACKAGES.contains(&name.as_str())
                    || engine_packages.contains(*name)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !forbidden.is_empty() {
            violations.push(format!(
                "{} reaches forbidden runtime dependencies: {}",
                package.name,
                forbidden.join(", ")
            ));
        }
    }
}

fn check_layer_sources(
    workspace: &Workspace,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    for package in workspace
        .packages()
        .filter(|package| is_logic_layer(package, workspace.root()))
    {
        let source = package.directory.join("src");
        for path in rust_files(&source)? {
            let contents = fs::read_to_string(&path)?;
            let syntax = syn::parse_file(&contents)
                .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
            let mut visitor = ForbiddenPathVisitor::default();
            visitor.visit_file(&syntax);
            for forbidden in visitor.forbidden {
                violations.push(format!(
                    "{} uses {forbidden} in {}",
                    package.name,
                    relative_display(workspace.root(), &path)
                ));
            }
        }
    }
    Ok(())
}

fn check_openssl_confinement(
    workspace: &Workspace,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    for package in workspace.packages() {
        if package.name == "bondry-store-sqlcipher" {
            continue;
        }
        let manifest = fs::read_to_string(&package.manifest)?;
        if manifest.lines().map(str::trim).any(|line| {
            line.starts_with("openssl =")
                || line.starts_with("openssl-sys =")
                || line.starts_with("openssl-src =")
        }) {
            violations.push(format!(
                "{} declares an OpenSSL dependency outside the SQLCipher store",
                package.name
            ));
        }
    }
    if workspace.all_package_names().contains("openssl-sys") {
        for package in workspace.packages() {
            let closure = workspace.dependency_closure(&[&package.name]);
            if closure.contains("openssl-sys") && !closure.contains("bondry-store-sqlcipher") {
                violations.push(format!(
                    "{} reaches openssl-sys without the SQLCipher store boundary",
                    package.name
                ));
            }
        }
    }
    Ok(())
}

fn check_consumer_profiles(workspace: &Workspace, violations: &mut Vec<String>) {
    check_profile(
        workspace,
        "credential store FFI",
        &["bondry-credential-store-ffi"],
        &[
            "bondry-auth",
            "bondry-core",
            "bondry-delivery-store",
            "bondry-runtime-ffi",
            "bondry-store-sqlcipher",
            "hyper",
            "hyper-util",
            "rustls",
            "tokio",
            "tokio-rustls",
        ],
        &["crates/egress", "crates/engine", "crates/proto"],
        violations,
    );
    check_profile(
        workspace,
        "capability dispatch",
        &["bondry-core", "bondry-auth"],
        FORBIDDEN_RUNTIME_PACKAGES,
        &["crates/engine", "crates/proto", "crates/egress"],
        violations,
    );
    check_profile(
        workspace,
        "SQLCipher store",
        &["bondry-store-sqlcipher"],
        &[],
        &["crates/engine", "crates/egress"],
        violations,
    );
    check_profile(
        workspace,
        "local server",
        &["bondry-http-server"],
        &[
            "bondry-webhook-ingress",
            "bondry-webhook-ingress-ffi",
            "bondry-webhook-verify",
            "rustls",
            "tokio-rustls",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &["crates/egress"],
        violations,
    );
    check_profile(
        workspace,
        "local server FFI",
        &["bondry-local-server-ffi"],
        &[
            "bondry-webhook-ingress",
            "bondry-webhook-ingress-ffi",
            "bondry-webhook-verify",
            "rustls",
            "tokio-rustls",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &["crates/egress"],
        violations,
    );
    check_profile(
        workspace,
        "webhook ingress",
        &["bondry-webhook-ingress", "bondry-http-server"],
        &[],
        &["crates/egress"],
        violations,
    );
    check_profile(
        workspace,
        "webhook egress",
        &[
            "bondry-egress",
            "bondry-egress-webhook",
            "bondry-egress-runtime",
            "bondry-transport-net",
        ],
        &[
            "bondry-egress-mcp",
            "bondry-webhook-ingress",
            "bondry-webhook-ingress-ffi",
            "bondry-webhook-verify",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &["crates/engine/bondry-http-server"],
        violations,
    );
    check_profile(
        workspace,
        "MCP egress",
        &[
            "bondry-egress",
            "bondry-egress-mcp",
            "bondry-egress-runtime",
        ],
        &[
            "bondry-egress-webhook",
            "bondry-webhook-ingress",
            "bondry-webhook-ingress-ffi",
            "bondry-webhook-verify",
            "rustls",
            "tokio-rustls",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &["crates/engine/bondry-http-server"],
        violations,
    );
    check_profile(
        workspace,
        "Apple egress",
        &["bondry-egress-ffi"],
        &[
            "hyper",
            "hyper-util",
            "bondry-http-server",
            "bondry-webhook-ingress",
            "bondry-webhook-ingress-ffi",
            "bondry-webhook-verify",
            "rustls",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &[
            "crates/engine/bondry-transport-net",
            "crates/proto/bondry-webhook-ingress",
        ],
        violations,
    );
    check_profile(
        workspace,
        "Apple webhook ingress add-on",
        &["bondry-webhook-ingress-ffi"],
        &[
            "bondry-egress",
            "bondry-egress-ffi",
            "bondry-egress-mcp",
            "bondry-egress-runtime",
            "bondry-egress-webhook",
            "bondry-http-server",
            "bondry-local-server-ffi",
            "bondry-transport-net",
            "hyper",
            "hyper-util",
            "rustls",
            "tokio-rustls",
            "tungstenite",
            "tokio-tungstenite",
        ],
        &["crates/egress", "crates/engine"],
        violations,
    );
}

fn check_profile(
    workspace: &Workspace,
    profile: &str,
    roots: &[&str],
    forbidden_packages: &[&str],
    forbidden_workspace_paths: &[&str],
    violations: &mut Vec<String>,
) {
    if !workspace.has_all_packages(roots) {
        return;
    }
    let closure = workspace.dependency_closure(roots);
    let mut forbidden = closure
        .iter()
        .filter(|name| forbidden_packages.contains(&name.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    for package in workspace.packages() {
        if closure.contains(&package.name)
            && forbidden_workspace_paths
                .iter()
                .any(|path| is_layer(package, workspace.root(), path))
        {
            forbidden.insert(package.name.clone());
        }
    }
    if !forbidden.is_empty() {
        violations.push(format!(
            "{profile} closure contains forbidden packages: {}",
            forbidden.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
}

fn is_logic_layer(package: &Package, root: &Path) -> bool {
    ["crates/contract", "crates/proto", "crates/egress"]
        .iter()
        .any(|layer| is_layer(package, root, layer))
}

fn is_layer(package: &Package, root: &Path, layer: &str) -> bool {
    package
        .directory
        .strip_prefix(root)
        .is_ok_and(|path| path.starts_with(layer))
}

fn rust_files(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && !is_test_source(directory, &path)
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn is_test_source(source_root: &Path, path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "tests.rs")
        || path.strip_prefix(source_root).is_ok_and(|relative| {
            relative
                .components()
                .any(|component| component.as_os_str() == "tests")
        })
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[derive(Default)]
struct ForbiddenPathVisitor {
    forbidden: BTreeSet<String>,
}

impl ForbiddenPathVisitor {
    fn inspect(&mut self, segments: &[String]) {
        let path = segments.join("::");
        if is_forbidden_source_path(&path) {
            self.forbidden.insert(path);
        }
    }

    fn inspect_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.inspect(prefix);
                self.inspect_use(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.inspect(prefix);
                prefix.pop();
            }
            UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.inspect(prefix);
                prefix.pop();
            }
            UseTree::Glob(_) => self.inspect(prefix),
            UseTree::Group(group) => {
                for item in &group.items {
                    self.inspect_use(item, prefix);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for ForbiddenPathVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.inspect_use(&node.tree, &mut Vec::new());
        syn::visit::visit_item_use(self, node);
    }

    fn visit_path(&mut self, node: &'ast SynPath) {
        self.inspect(
            &node
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
        );
        syn::visit::visit_path(self, node);
    }
}

fn is_forbidden_source_path(path: &str) -> bool {
    [
        "std::fs",
        "std::net",
        "std::os::unix::net",
        "std::thread::spawn",
        "tokio",
        "hyper",
        "hyper_util",
        "rustls",
        "socket2",
        "tungstenite",
        "tokio_tungstenite",
    ]
    .iter()
    .any(|forbidden| path == *forbidden || path.starts_with(&format!("{forbidden}::")))
}

#[cfg(test)]
mod tests {
    use syn::visit::Visit;

    use super::ForbiddenPathVisitor;

    #[test]
    fn source_lint_catches_nested_socket_imports() -> Result<(), Box<dyn std::error::Error>> {
        let syntax = syn::parse_file("use std::{net::TcpStream, sync::Arc};")?;
        let mut visitor = ForbiddenPathVisitor::default();
        visitor.visit_file(&syntax);
        assert!(visitor.forbidden.contains("std::net"));
        assert!(visitor.forbidden.contains("std::net::TcpStream"));
        assert!(!visitor.forbidden.iter().any(|path| path.contains("Arc")));
        Ok(())
    }

    #[test]
    fn source_lint_catches_executor_spawns() -> Result<(), Box<dyn std::error::Error>> {
        let syntax = syn::parse_file("fn run() { tokio::spawn(async {}); }")?;
        let mut visitor = ForbiddenPathVisitor::default();
        visitor.visit_file(&syntax);
        assert!(visitor.forbidden.contains("tokio::spawn"));
        Ok(())
    }

    #[test]
    fn source_lint_catches_standard_library_io_and_threads()
    -> Result<(), Box<dyn std::error::Error>> {
        let syntax = syn::parse_file(
            "use std::{fs, os::unix::net::UnixStream}; fn run() { std::thread::spawn(|| {}); }",
        )?;
        let mut visitor = ForbiddenPathVisitor::default();
        visitor.visit_file(&syntax);
        assert!(visitor.forbidden.contains("std::fs"));
        assert!(visitor.forbidden.contains("std::os::unix::net"));
        assert!(visitor.forbidden.contains("std::thread::spawn"));
        Ok(())
    }
}
