# Reproducible validation

## Linux or cross-platform source tests

From a clean clone:

```text
python -m venv .venv
python -m pip install -r requirements.txt
python -m pip install pytest pip-audit
python -m pytest -q
python -m pip check
python -m pip_audit
```

## Windows validation

Use an x64 Native Tools Command Prompt for VS 2022 with the C++ workload
installed. Run the repository validation script after installing dependencies:

```text
scripts\install_windows.cmd
.venv\Scripts\python.exe -m pytest -q
```

The full validation must use fresh throwaway keys and temporary files. Never
point it at production keys, user ciphertext, or a live witness database.

## Publication gate

A release candidate is publishable only when a clean clone passes the test
suite, no secret or generated binary is tracked, the working tree is clean,
and the report records the exact Python, compiler, dependency, and platform
versions used.

