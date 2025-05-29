# codeintel-Build-Process-Integrity-Checker
Verifies the integrity of the build process by checking for unexpected modifications to build scripts, dependencies, or compiler settings. Alerts on potential tampering or supply chain attacks. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-build-process-integrity-checker`

## Usage
`./codeintel-build-process-integrity-checker [params]`

## Parameters
- `--build-script`: No description provided
- `--dependency-file`: No description provided
- `--compiler-settings`: No description provided
- `--baseline-hash-build-script`: Baseline SHA256 hash of the build script. If provided, script hash will be checked against it.
- `--baseline-hash-dependency-file`: Baseline SHA256 hash of the dependency file. If provided, dependency file hash will be checked against it.
- `--baseline-hash-compiler-settings`: Baseline SHA256 hash of the compiler settings file. If provided, compiler settings file hash will be checked against it.
- `--run-bandit`: Run Bandit security scanner.
- `--run-flake8`: Run Flake8 code linter.
- `--run-pylint`: Run Pylint code analyzer.
- `--run-pyre`: Run Pyre type checker.
- `--offensive-scan`: No description provided

## License
Copyright (c) ShadowStrikeHQ
