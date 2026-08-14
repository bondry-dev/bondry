use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    resolve: Option<MetadataResolve>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

#[derive(Deserialize)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Deserialize)]
struct MetadataNode {
    id: String,
    dependencies: Vec<String>,
    deps: Vec<MetadataNodeDependency>,
}

#[derive(Deserialize)]
struct MetadataNodeDependency {
    pkg: String,
    dep_kinds: Vec<MetadataDependencyKind>,
}

#[derive(Deserialize)]
struct MetadataDependencyKind {
    kind: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub directory: PathBuf,
    pub manifest: PathBuf,
}

pub struct Workspace {
    root: PathBuf,
    packages: BTreeMap<String, Package>,
    package_names_by_id: BTreeMap<String, String>,
    artifact_dependencies: BTreeMap<String, BTreeSet<String>>,
    reverse_dependencies: BTreeMap<String, BTreeSet<String>>,
}

impl Workspace {
    pub fn load(root: &Path) -> Result<Self, Box<dyn Error>> {
        let output = Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--locked"])
            .current_dir(root)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        let metadata: Metadata = serde_json::from_slice(&output.stdout)?;
        Self::from_metadata(root.to_path_buf(), metadata)
    }

    fn from_metadata(root: PathBuf, metadata: Metadata) -> Result<Self, Box<dyn Error>> {
        let workspace_ids: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
        let package_names_by_id: BTreeMap<_, _> = metadata
            .packages
            .iter()
            .map(|package| (package.id.clone(), package.name.clone()))
            .collect();
        let mut packages = BTreeMap::new();
        for package in &metadata.packages {
            if !workspace_ids.contains(&package.id) {
                continue;
            }
            let manifest = package.manifest_path.clone();
            let directory = manifest
                .parent()
                .ok_or_else(|| format!("package {} has no directory", package.name))?
                .to_path_buf();
            packages.insert(
                package.name.clone(),
                Package {
                    name: package.name.clone(),
                    directory,
                    manifest,
                },
            );
        }

        let mut artifact_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let mut reverse_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let nodes = metadata
            .resolve
            .ok_or("cargo metadata omitted resolve graph")?
            .nodes;
        for node in nodes {
            let Some(name) = package_names_by_id.get(&node.id) else {
                continue;
            };
            let dependency_names = node
                .dependencies
                .iter()
                .filter_map(|id| package_names_by_id.get(id).cloned())
                .collect::<BTreeSet<_>>();
            if packages.contains_key(name) {
                for dependency in &dependency_names {
                    if packages.contains_key(dependency) {
                        reverse_dependencies
                            .entry(dependency.clone())
                            .or_default()
                            .insert(name.clone());
                    }
                }
            }
            let artifact_dependency_names = node
                .deps
                .iter()
                .filter(|dependency| {
                    dependency
                        .dep_kinds
                        .iter()
                        .any(|kind| kind.kind.as_deref() != Some("dev"))
                })
                .filter_map(|dependency| package_names_by_id.get(&dependency.pkg).cloned())
                .collect();
            artifact_dependencies.insert(name.clone(), artifact_dependency_names);
        }

        Ok(Self {
            root,
            packages,
            package_names_by_id,
            artifact_dependencies,
            reverse_dependencies,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn packages(&self) -> impl Iterator<Item = &Package> {
        self.packages.values()
    }

    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.get(name)
    }

    pub fn package_names(&self) -> BTreeSet<String> {
        self.packages.keys().cloned().collect()
    }

    pub fn package_for_path(&self, path: &Path) -> Option<&Package> {
        let absolute = self.root.join(path);
        self.packages
            .values()
            .filter(|package| absolute.starts_with(&package.directory))
            .max_by_key(|package| package.directory.components().count())
    }

    pub fn reverse_closure(&self, seeds: &BTreeSet<String>) -> BTreeSet<String> {
        closure(seeds, &self.reverse_dependencies)
    }

    pub fn dependency_closure(&self, roots: &[&str]) -> BTreeSet<String> {
        let seeds = roots.iter().map(|name| (*name).to_owned()).collect();
        closure(&seeds, &self.artifact_dependencies)
    }

    pub fn has_all_packages(&self, names: &[&str]) -> bool {
        names.iter().all(|name| self.packages.contains_key(*name))
    }

    pub fn all_package_names(&self) -> BTreeSet<String> {
        self.package_names_by_id.values().cloned().collect()
    }

    #[cfg(test)]
    pub fn for_test(edges: &[(&str, &[&str])], paths: &[(&str, &str)]) -> Self {
        let root = PathBuf::from("/workspace");
        let packages = paths
            .iter()
            .map(|(name, path)| {
                let directory = root.join(path);
                (
                    (*name).to_owned(),
                    Package {
                        name: (*name).to_owned(),
                        manifest: directory.join("Cargo.toml"),
                        directory,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut artifact_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let mut reverse_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        for (name, package_dependencies) in edges {
            artifact_dependencies.insert(
                (*name).to_owned(),
                package_dependencies
                    .iter()
                    .map(|dependency| (*dependency).to_owned())
                    .collect(),
            );
            for dependency in *package_dependencies {
                reverse_dependencies
                    .entry((*dependency).to_owned())
                    .or_default()
                    .insert((*name).to_owned());
            }
        }
        let package_names_by_id = packages
            .keys()
            .map(|name| (name.clone(), name.clone()))
            .collect();
        Self {
            root,
            packages,
            package_names_by_id,
            artifact_dependencies,
            reverse_dependencies,
        }
    }
}

fn closure(
    seeds: &BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut result = seeds.clone();
    let mut pending = VecDeque::from_iter(seeds.iter().cloned());
    while let Some(package) = pending.pop_front() {
        if let Some(neighbors) = edges.get(&package) {
            for neighbor in neighbors {
                if result.insert(neighbor.clone()) {
                    pending.push_back(neighbor.clone());
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::Workspace;

    #[test]
    fn computes_transitive_reverse_closures() {
        let workspace = Workspace::for_test(
            &[("core", &[]), ("proto", &["core"]), ("server", &["proto"])],
            &[
                ("core", "crates/contract/core"),
                ("proto", "crates/proto/proto"),
                ("server", "crates/engine/server"),
            ],
        );
        let affected = workspace.reverse_closure(&BTreeSet::from(["core".to_owned()]));
        assert_eq!(
            affected,
            BTreeSet::from(["core".to_owned(), "proto".to_owned(), "server".to_owned()])
        );
    }
}
