#![allow(missing_docs)]

mod affected;
mod gate;
mod workspace;

use std::{env, error::Error, path::PathBuf, process::ExitCode};

use affected::AffectedOptions;
use workspace::Workspace;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask has no workspace parent")?
        .to_path_buf();
    let workspace = Workspace::load(&root)?;
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("affected") => affected::run(&workspace, AffectedOptions::parse(arguments)?)?,
        Some("gate") => gate::run(&workspace)?,
        Some(command) => return Err(format!("unknown command: {command}").into()),
        None => return Err("usage: cargo xtask <affected|gate>".into()),
    }
    Ok(())
}
