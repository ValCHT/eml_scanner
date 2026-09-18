# Cross-platform execution policy

Target: Python 3.11 on Windows, macOS and Linux with the same repository and tests.

## Environment

Create a venv with the platform's Python 3.11 executable:

macOS/Linux:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

After activation, use the same commands everywhere:

```text
python -m pip install -e ".[dev]"
python -m pip check
python -m pytest -q -m "not live"
```

## Engineering constraints

- Use `pathlib.Path` and `tempfile` rather than platform-specific paths.
- Use UTF-8 explicitly for textual artifacts; use raw bytes for RFC822 input and attachments.
- Use `subprocess.run(list_args, shell=False)` in application code.
- Do not require Bash/PowerShell commands at runtime.
- Do not rely on symlink behavior or executable bits.
- Keep optional native dependencies behind feature flags; prefer packages that publish wheels for the three OSes.
- Never let Git or an editor rewrite `.eml` fixture line endings after fixture hashes are defined.
- Keep environment configuration in variables / `.env.example`, never OS-specific source files.

## CI

`.github/workflows/cross-platform.yml` runs Python 3.11 non-live tests on:

- `ubuntu-latest`
- `macos-latest`
- `windows-latest`

This catches path, encoding, filesystem and dependency-wheel issues early. Live provider tests remain explicit and are not run in generic CI.
