"""Relink the programs in fex_fixtures.py and run them with aps5-fex.

    python3 run_fex_fixtures.py <relinker> <aps5-fex> <patched prx directory>

Each program reports its result through its exit status and standard output."""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fex_fixtures  # noqa: E402

EXPECTED = {
    "hello": (42, "hello from x86-64 guest code on arm64\n"),
    "floating": (41, ""),
    "sorting": (19, ""),
    "variadic": (0, "42 x 2.50 4 5 6\nprinted 7\n"),
    "opening": (0, None),
    "threading": (42, None),
    "extended": (42, ""),
}


def created_with_mode(directory):
    path = directory / "created.txt"
    if not path.exists():
        return "created.txt was not created"
    mode = path.stat().st_mode & 0o777
    expected = 0o640 & ~current_umask()
    return None if mode == expected else f"created.txt has mode {mode:o}, expected {expected:o}"


def current_umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


CHECKS = {"opening": created_with_mode}


def main():
    relinker, runner, libraries = (pathlib.Path(argument).resolve() for argument in sys.argv[1:4])
    failures = []
    for name, (status, output) in EXPECTED.items():
        with tempfile.TemporaryDirectory(prefix=f"aps5-fex-{name}-") as directory:
            directory = pathlib.Path(directory)
            (directory / "input.elf").write_bytes(fex_fixtures.FIXTURES[name]())
            relinked = subprocess.run([str(relinker), "--skip-sce-module", "input.elf", "eboot.elf"], cwd=directory,
                                      capture_output=True, text=True, timeout=60)
            if relinked.returncode != 0:
                failures.append(f"{name}: relink failed: {relinked.stderr.strip()}")
                continue
            (directory / "libs").symlink_to(libraries, target_is_directory=True)
            executed = subprocess.run([str(runner), "eboot.elf"], cwd=directory, capture_output=True, text=True, timeout=60)
            if executed.returncode != status or (output is not None and executed.stdout != output):
                failures.append(f"{name}: exit {executed.returncode}, expected {status}; output {executed.stdout!r}, "
                                f"expected {output!r}; {executed.stderr.strip()[-400:]}")
            elif name in CHECKS and (problem := CHECKS[name](directory)):
                failures.append(f"{name}: {problem}")
    for failure in failures:
        print(failure)
    if failures:
        sys.exit(1)
    print(f"{len(EXPECTED)} guest programs ran through FEXCore")


if __name__ == "__main__":
    main()
