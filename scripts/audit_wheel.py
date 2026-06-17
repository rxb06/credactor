"""Verify wheel contents match the source repo exactly."""
import os
import subprocess
import sys
import zipfile


def audit(dist_dir: str = 'dist') -> None:
    errors: list[str] = []

    # An empty or missing dist/ must fail loudly: this gate runs right before
    # "Publish to PyPI", and a half-failed build (sdist only, or nothing)
    # previously slid through with "Wheel audit passed" despite auditing nothing.
    try:
        wheels = [f for f in os.listdir(dist_dir) if f.endswith('.whl')]
    except FileNotFoundError:
        wheels = []
    if not wheels:
        errors.append(f"no .whl file found in {dist_dir}")

    for f in wheels:
        with zipfile.ZipFile(os.path.join(dist_dir, f)) as z:
            wheel_files = set(z.namelist())

            # Get repo-tracked source files
            repo_files = set(
                subprocess.check_output(
                    ['git', 'ls-files', 'credactor/'],
                    text=True
                ).strip().splitlines()
            )

            # Wheel Python files under credactor/
            wheel_pkg_files = {
                name for name in wheel_files
                if name.startswith('credactor/') and not name.endswith('.pyc')
            }

            # Metadata only (credactor-X.dist-info/): require the .dist-info/
            # segment so a smuggled top-level file that merely shares the
            # 'credactor-' prefix cannot ride the whitelist.
            expected_non_pkg = {
                name for name in wheel_files
                if name.startswith('credactor-') and '.dist-info/' in name
            }

            unexpected = wheel_files - wheel_pkg_files - expected_non_pkg
            errors.extend(f"UNEXPECTED: {uf}" for uf in sorted(unexpected))

            extra_in_wheel = wheel_pkg_files - repo_files
            errors.extend(f"NOT IN REPO: {ef}" for ef in sorted(extra_in_wheel))

            # Symmetric check: a tracked source file that failed to make it
            # into the wheel would otherwise pass the audit and break for
            # every installer — the docstring promises an exact match.
            missing_from_wheel = repo_files - wheel_pkg_files
            errors.extend(f"MISSING FROM WHEEL: {mf}"
                          for mf in sorted(missing_from_wheel))

    if errors:
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
    print("Wheel audit passed")


if __name__ == '__main__':
    audit(sys.argv[1] if len(sys.argv) > 1 else 'dist')
