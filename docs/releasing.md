# Releasing

Bondry uses GitHub Actions for release preparation and publication. No personal access token or signing secret is required; the workflows use the repository-scoped `GITHUB_TOKEN` and GitHub's short-lived OIDC identity.

## Repository Setup

Before the first release:

1. Make `main` the default branch and create a branch ruleset that requires pull
   requests and the `CI gate` status check before merge.
2. Create a GitHub environment named `release` with a required reviewer.
3. Allow GitHub Actions to request read and write repository permissions.
4. Make the repository public so the release can receive a public Sigstore provenance attestation.
5. Enable immutable releases before publishing the first release.

Release preparation deliberately refuses to run while the repository is private. The build job and pull-request workflows have read-only repository permissions. A separate protected publication deployment receives the write and OIDC permissions required to attest and publish the prepared artifact.

## Preparing a Version

Update every workspace package to the same numeric semantic version, commit the source changes, push them to `main`, and wait for CI to pass. From the Actions tab, run `Prepare Release` from `main` and enter the version without a `v` prefix.

Preparation builds and verifies each binary once, computes SwiftPM checksums from those exact archives, renders `Package.swift`, and creates the release commit and annotated tag as Cocoa. It stores the five archives, checksums, and preparation metadata together as a workflow artifact, then queues `Publish Release` from the new tag. Approve the `release` environment deployment after preparation succeeds.

## Publication Contract

The preparation workflow:

1. Verifies repository visibility, branch, version consistency, and tag availability.
2. Runs the Rust, Swift, formatting, lint, and shell checks.
3. Builds and verifies every XCFramework slice with pinned Rust and Xcode versions.
4. Computes each archive checksum and writes it into the release manifest.
5. Stores the exact archives with their checksums and release metadata.
6. Creates the release commit and annotated `v<version>` tag.

The publication deployment:

1. Downloads the exact archives produced by the successful preparation run.
2. Verifies the workflow run, tag, release commit, metadata, archives, checksum files, and `Package.swift` agree.
3. Creates a public provenance attestation for every archive.
4. Uses a pinned release action to upload all ten assets to a draft with bounded API retries.
5. Publishes the draft as a GitHub prerelease protected by the repository's immutable-release policy.
6. Downloads all published assets and compares them with the prepared files.

Publication never rebuilds a binary. A failed publication can retry the prepared artifacts without changing their checksums. Published versions and their assets must never be replaced.
