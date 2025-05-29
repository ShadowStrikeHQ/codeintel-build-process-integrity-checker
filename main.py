import argparse
import hashlib
import logging
import os
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description='Verifies the integrity of the build process.')
    parser.add_argument('--build-script', type=str, required=True,
                        help='Path to the build script (e.g., build.sh, build.py)')
    parser.add_argument('--dependency-file', type=str, required=False,
                        help='Path to the dependency file (e.g., requirements.txt, package.json)')
    parser.add_argument('--compiler-settings', type=str, required=False,
                        help='Path to a file containing compiler settings (e.g., compiler_flags.txt)')
    parser.add_argument('--baseline-hash-build-script', type=str, required=False,
                        help='Baseline SHA256 hash of the build script. If provided, script hash will be checked against it.')
    parser.add_argument('--baseline-hash-dependency-file', type=str, required=False,
                        help='Baseline SHA256 hash of the dependency file. If provided, dependency file hash will be checked against it.')
    parser.add_argument('--baseline-hash-compiler-settings', type=str, required=False,
                        help='Baseline SHA256 hash of the compiler settings file. If provided, compiler settings file hash will be checked against it.')
    parser.add_argument('--run-bandit', action='store_true', help='Run Bandit security scanner.')
    parser.add_argument('--run-flake8', action='store_true', help='Run Flake8 code linter.')
    parser.add_argument('--run-pylint', action='store_true', help='Run Pylint code analyzer.')
    parser.add_argument('--run-pyre', action='store_true', help='Run Pyre type checker.')
    parser.add_argument('--offensive-scan', action='store_true', help='Enable offensive scanning tools (potentially more sensitive).')
    return parser.parse_args()


def calculate_sha256(filepath):
    """
    Calculates the SHA256 hash of a file.

    Args:
        filepath (str): The path to the file.

    Returns:
        str: The SHA256 hash of the file, or None if the file does not exist.
    """
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return None

    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None


def check_file_integrity(filepath, baseline_hash):
    """
    Checks the integrity of a file against a baseline hash.

    Args:
        filepath (str): The path to the file.
        baseline_hash (str): The expected SHA256 hash of the file.

    Returns:
        bool: True if the file's hash matches the baseline hash, False otherwise.
    """
    if not filepath or not baseline_hash:
        return True # If no file or baseline hash provided, skip check

    calculated_hash = calculate_sha256(filepath)

    if calculated_hash is None:
        return False  # Indicate failure to read file.

    if calculated_hash == baseline_hash:
        logging.info(f"Integrity check passed for {filepath}")
        return True
    else:
        logging.warning(f"Integrity check failed for {filepath}. Expected hash: {baseline_hash}, calculated hash: {calculated_hash}")
        return False


def run_security_scan(tool, target, offensive=False):
    """
    Runs a security scan using a specified tool.

    Args:
        tool (str): The name of the security scanning tool (bandit, flake8, pylint, pyre).
        target (str): The target file or directory to scan.
        offensive (bool): Whether to enable offensive scanning.

    Returns:
        bool: True if the scan completed successfully, False otherwise.
    """

    try:
        command = []
        if tool == 'bandit':
            command = ['bandit', '-r', target]
        elif tool == 'flake8':
            command = ['flake8', target]
        elif tool == 'pylint':
            command = ['pylint', target]
        elif tool == 'pyre':
            command = ['pyre', 'check'] # Assuming project dir already pyre-initialized.
        else:
            logging.error(f"Invalid security tool: {tool}")
            return False

        if offensive and tool == 'bandit':
            command.extend(['-lll']) # Enables High, Medium, and Low severity

        logging.info(f"Running {tool} scan on {target}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"{tool} scan failed with return code {process.returncode}")
            logging.error(f"Stdout: {stdout.decode()}")
            logging.error(f"Stderr: {stderr.decode()}")
            return False

        logging.info(f"{tool} scan completed successfully.")
        print(stdout.decode())
        return True

    except FileNotFoundError:
        logging.error(f"Tool not found: {tool}. Please ensure it is installed.")
        return False
    except Exception as e:
        logging.error(f"Error running {tool}: {e}")
        return False


def main():
    """
    Main function to orchestrate the build process integrity checks.
    """
    args = setup_argparse()

    # Input Validation
    if not os.path.exists(args.build_script):
        logging.error(f"Build script not found: {args.build_script}")
        sys.exit(1)
    if args.dependency_file and not os.path.exists(args.dependency_file):
        logging.error(f"Dependency file not found: {args.dependency_file}")
        sys.exit(1)
    if args.compiler_settings and not os.path.exists(args.compiler_settings):
        logging.error(f"Compiler settings file not found: {args.compiler_settings}")
        sys.exit(1)

    # Integrity Checks
    build_script_integrity = check_file_integrity(args.build_script, args.baseline_hash_build_script)
    dependency_file_integrity = check_file_integrity(args.dependency_file, args.baseline_hash_dependency_file)
    compiler_settings_integrity = check_file_integrity(args.compiler_settings, args.baseline_hash_compiler_settings)

    if not build_script_integrity or not dependency_file_integrity or not compiler_settings_integrity:
        logging.error("One or more integrity checks failed. Aborting.")
        sys.exit(1)

    # Security Scans
    if args.run_bandit:
        if not run_security_scan('bandit', args.build_script, args.offensive_scan):
            logging.warning("Bandit scan failed. Continuing...")

    if args.run_flake8:
        if not run_security_scan('flake8', args.build_script):
            logging.warning("Flake8 scan failed. Continuing...")

    if args.run_pylint:
        if not run_security_scan('pylint', args.build_script):
            logging.warning("Pylint scan failed. Continuing...")

    if args.run_pyre:
        if not run_security_scan('pyre', '.'): # Assuming current dir is root
            logging.warning("Pyre scan failed. Continuing...")


    logging.info("Build process integrity checks completed.")
    sys.exit(0)


if __name__ == "__main__":
    main()