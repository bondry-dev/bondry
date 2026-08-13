# Releasing

Bondry uses GitHub Actions for validation and release publication. No personal access token or signing secret is required; the release job uses the repository-scoped `GITHUB_TOKEN` and GitHub's short-lived OIDC identity.

## Repository Setup

Before the first release:

1. Make `main` the default branch and require the CI workflow to pass before merge.
2. Create a GitHub environment named `release` with a required reviewer.
3. Allow GitHub Actions to request read and write repository permissions.
4. Make the repository public so the release can receive a public Sigstore provenance attestation.
5. Enable immutable releases before publishing the first release.

The release workflow deliberately refuses to publish while the repository is private. Pull-request workflows have read-only repository permissions. Only the manually dispatched release job requests write and OIDC permissions, and its protected environment provides the human approval boundary.

## Preparing a Version

Update every workspace package to the same numeric semantic version, then run:

```sh
apple/scripts/prepare-release.sh 0.0.1
```

The command performs a verified XCFramework build with the release timestamp, computes its SwiftPM checksum, and renders the root `Package.swift`. Review and commit the manifest with the rest of the version change. The archive remains below the ignored `target` directory.

Push the release commit to `main` and wait for CI to pass. From the Actions tab, run the `Release` workflow from `main`, enter the version without a `v` prefix, and approve the `release` environment deployment.

## Publication Contract

The release job:

1. Verifies repository visibility, branch, version consistency, and tag availability.
2. Runs the Rust, Swift, formatting, lint, and shell checks.
3. Rebuilds and verifies every XCFramework slice with pinned Rust and Xcode versions.
4. Requires the rebuilt checksum and generated release manifest to match the committed `Package.swift` exactly.
5. Creates a public provenance attestation for the archive.
6. Creates an annotated `v<version>` tag at the reviewed `main` commit.
7. Publishes the archive and checksum as a GitHub prerelease protected by the repository's immutable-release policy.

No tag is created when validation, compilation, artifact verification, checksum comparison, or attestation fails. Published versions and their assets must never be replaced.
