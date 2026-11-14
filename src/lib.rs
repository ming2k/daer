// SPDX-License-Identifier: AGPL-3.0-only

//! Workspace-level test harness package.
//!
//! This package contains no production code. Its only targets are the two integration test
//! binaries under `tests/`: `integration` (unprivileged component composition) and `e2e`
//! (privileged, real daemon and kernel). Keeping one package with two test targets means the
//! workspace pays for two test link steps instead of one per crate, and the tests can share
//! `tests/common` fixtures without a second published helper crate.
//!
//! The `daer-test-support` crate is the infrastructure layer reused by both these tests and
//! the in-crate unit tests. It is a dev-dependency only; an architecture test asserts that no
//! production crate can link it.
