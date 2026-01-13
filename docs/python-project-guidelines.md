# Python Project Guidelines (Python 3.13+)

A comprehensive, adoption-ready reference for professional Python development. Applicable to new and existing projects targeting Python 3.13+.

## 1. Code Structure and Organization

### 1.1 Recommended Project Layout

```
project-root/
├─ pyproject.toml                # Build, tools and metadata
├─ README.md                     # Project overview and usage
├─ LICENSE                       # License file
├─ docs/                         # Documentation and ADRs
├─ src/your_package/             # Application/package code (src/ layout)
│  ├─ __init__.py                # Public API re-exports, version
│  ├─ core/                      # Pure domain logic
│  ├─ adapters/                  # IO boundaries (DB, HTTP, FS)
│  ├─ services/                  # Application orchestration
│  └─ cli.py                     # Entry points (if any)
├─ tests/                        # Test suite
│  ├─ unit/                      # Fast unit tests (pure logic)
│  ├─ integration/               # Service boundaries
│  └─ e2e/                       # End-to-end scenarios
└─ .pre-commit-config.yaml       # Pre-commit hooks
```

### 1.2 Module and Package Organization
- Group by responsibility (domain/core, services, adapters). Keep modules small and cohesive.
- Keep IO concerns at boundaries (adapters); keep core logic pure and reusable.
- Prefer single-source-of-truth for business rules in `core/`; orchestrate in `services/`.

### 1.3 Import Conventions
- Prefer absolute imports for clarity: `from your_package.core.rules import calculate_price`
- Relative imports allowed only within the same package when local cohesion is obvious.
- Avoid wildcard imports; explicitly export a curated API via `__all__`.

### 1.4 `__init__.py` Usage Patterns

```python
# src/your_package/__init__.py
# Public API surface: re-export stable entry points for consumers
from .core.rules import calculate_price  # Expose key domain function
from .version import __version__         # Expose version constant

__all__ = ["calculate_price", "__version__"]  # Controlled public API
```


## 2. Functional Programming Practices

### 2.1 Pure Functions

```python
# Pure transformation: deterministic; no IO; no global state
from collections.abc import Iterable

def dedup_sorted(xs: Iterable[int]) -> list[int]:
    # Remove duplicates and return sorted list
    return sorted(set(xs))
```

### 2.2 Immutability

```python
# Immutable model using frozen dataclass
from dataclasses import dataclass

@dataclass(frozen=True)
class Money:
    amount: int
    currency: str

# MappingProxyType prevents mutation of dict
from types import MappingProxyType
config = MappingProxyType({"timeout": 5, "retries": 2})  # read-only view
```

### 2.3 Higher-Order Functions and Lambdas

```python
# Compose small transformations; prefer named functions for clarity
from typing import Callable, TypeVar

T = TypeVar("T")

def compose(*funcs: Callable[[T], T]) -> Callable[[T], T]:
    def _composed(value: T) -> T:
        for f in reversed(funcs):
            value = f(value)
        return value
    return _composed

# Example composition
normalize = compose(str.strip, str.lower)
assert normalize("  Hello ") == "hello"
```

### 2.4 Avoid Side Effects and Global State
- Isolate IO in adapters (HTTP, DB, FS); keep core logic pure.
- Use dependency injection to pass side-effecting functions into orchestrators.
- Prefer function parameters over module-level globals.


## 3. Strong Typing Implementation

### 3.1 Type Hinting (PEPs 484, 526, 585, 586, 589, 604)
- Use native generics: `list[str]`, `dict[str, int]` (PEP 585).
- Prefer union syntax: `T | U` and `T | None` (PEP 604).
- Use `Literal` for finite sets; `TypedDict` for dict-shaped data; `Final` for constants.

```python
from typing import Literal, TypedDict

Color = Literal["red", "green", "blue"]  # finite set of values

class UserTD(TypedDict):
    id: int
    name: str
    is_admin: bool
```

### 3.2 Python 3.13 Typing Enhancements
- Defaults for type parameters (PEP 696).
- `typing.TypeIs` for intuitive type narrowing (PEP 742).
- `typing.ReadOnly` to mark `TypedDict` items immutable (PEP 705).
- `warnings.deprecated()` decorator to signal deprecations to type checkers (PEP 702).

```python
# TypeVar default (PEP 696)
from typing import Generic, TypeVar

T = TypeVar("T", default=int)  # default type argument is int

class Box(Generic[T]):
    def __init__(self, value: T):
        self.value = value

Box(1)          # T defaults to int
Box[str]("x")   # Explicit override
```

```python
# Type narrowing with TypeIs (PEP 742)
from typing import TypeIs

def is_nonempty_str(x: str | None) -> TypeIs[str]:
    # Returns True only if x is a non-empty string, enabling narrowing
    return isinstance(x, str) and len(x) > 0

val: str | None = "hello"
if is_nonempty_str(val):
    reveal_type(val)  # type checkers narrow to 'str'
```

```python
# Read-only TypedDict items (PEP 705)
from typing import TypedDict, ReadOnly, NotRequired

class AccountTD(TypedDict):
    id: ReadOnly[int]        # cannot be mutated
    name: str
    plan: NotRequired[str]   # optional key
```

```python
# Deprecation markers (PEP 702)
import warnings

@warnings.deprecated("use 'new_func' instead")
def old_func() -> None:
    pass
```

### 3.3 Protocols, Generics, NewType, TypeAlias

```python
# Protocol for repository interface
from typing import Protocol, TypeVar, runtime_checkable, NewType, TypeAlias

EntityId = NewType("EntityId", int)  # strong nominal type for IDs
Row: TypeAlias = dict[str, str]

T = TypeVar("T")

@runtime_checkable
class Repository(Protocol[T]):
    def get(self, id: EntityId) -> T: ...
    def save(self, entity: T) -> None: ...
```

### 3.4 Mypy Strict Mode

`mypy.ini` recommended baseline:

```ini
[mypy]
python_version = 3.13
warn_unused_configs = True
strict = True

# Common strict flags (enabled by 'strict') documented for clarity
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_return_any = True
no_implicit_reexport = True
strict_equality = True
```

Guidelines:
- Favor gradual typing: add hints to hot paths and public APIs first.
- Use `# type: ignore[code]` with justification comments only when necessary.


## 4. Testing Methodology

### 4.1 Pytest Configuration and Fixtures

```ini
# pytest.ini
[pytest]
minversion = 7.0
addopts = -q --strict-markers --disable-warnings
filterwarnings =
    error::DeprecationWarning
```

```python
# tests/unit/test_rules.py
import pytest

@pytest.fixture
def sample_prices() -> list[int]:
    # Provide shared test data
    return [10, 20, 20, 5]

@pytest.mark.parametrize("tax_rate,expected", [(0.0, 35), (0.1, 38)])
def test_total(sample_prices, tax_rate, expected):
    assert int(sum(sample_prices) * (1 + tax_rate)) == expected
```

### 4.2 Property-Based Testing (Hypothesis)

```python
# Property: sorting is idempotent
from hypothesis import given, strategies as st

@given(st.lists(st.integers()))
def test_sort_idempotent(xs: list[int]):
    assert sorted(sorted(xs)) == sorted(xs)
```

### 4.3 Mocking and Patching

```python
# Prefer patching at boundary modules; avoid over-mocking pure logic
from unittest.mock import patch
import requests

@patch("requests.get")
def test_fetch_calls_requests(mock_get):
    mock_get.return_value.status_code = 200
    # Call your function that uses requests.get
    resp = requests.get("https://example.com")
    assert resp.status_code == 200
```

### 4.4 Coverage Measurement

```ini
# pytest.ini additions for coverage when using pytest-cov
[pytest]
addopts = --cov=src/your_package --cov-report=term-missing --cov-report=xml
```

Enforce coverage threshold in CI (e.g., 90%).

### 4.5 Integration and E2E
- Integration tests exercise adapters against real services or testcontainers.
- E2E tests exercise CLI/HTTP endpoints through the full stack.

### 4.6 Performance Benchmarking

```python
# pytest-benchmark example
def test_my_func_benchmark(benchmark):
    def my_func(x: int) -> int: return x * x
    result = benchmark(my_func, 42)
    assert result == 1764
```


## 5. Code Quality Standards

### 5.1 Formatting and Imports
- Use Black for auto-formatting; line length 88 by default.
- Use Ruff (includes isort rules) to manage imports and lint.

```toml
# pyproject.toml (Black + Ruff)
[tool.black]
line-length = 88
target-version = ["py313"]

[tool.ruff]
line-length = 88
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "BLE", "SIM", "PERF", "PL", "NP", "ARG"]
ignore = ["D203", "D212"]

[tool.ruff.lint.isort]
known-first-party = ["your_package"]
combine-as-imports = true
```

### 5.2 Docstrings (Google/Numpy)

```python
def calculate_price(base: int, tax_rate: float) -> int:
    """Compute total price.

    Args:
        base: Base price in cents.
        tax_rate: Tax rate (0–1).

    Returns:
        Total price in cents.
    """
    return int(base * (1 + tax_rate))
```

### 5.3 Cyclomatic Complexity
- Use Radon to measure complexity and maintainability.
- Prefer small functions; extract logic to reduce branching.

```bash
radon cc -s -n B src/your_package
radon mi src/your_package
```

### 5.4 Security Scanning
- Bandit for code security checks; Safety or pip-audit for dependency CVEs.

```bash
bandit -r src/your_package -x tests -ll
pip-audit --skip-editable
```


## 6. Development Workflow

### 6.1 Git Branching Strategy
- Prefer trunk-based development with protected `main` and short-lived feature branches.
- Use Conventional Commits for clarity (e.g., `feat: add pricing rule`).

### 6.2 Pre-Commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
      - id: ruff-format
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-merge-conflict
      - id: end-of-file-fixer
      - id: trailing-whitespace
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.2
    hooks:
      - id: mypy
        args: ["--strict"]
```

### 6.3 CI/CD Pipeline (GitHub Actions skeleton)

```yaml
# .github/workflows/ci.yaml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: |
          python -m pip install -U pip
          pip install poetry
          poetry install --no-root
      - name: Lint & Format
        run: poetry run ruff check . && poetry run ruff format --check .
      - name: Type Check
        run: poetry run mypy --strict src
      - name: Test
        run: poetry run pytest -q --cov=src/your_package --cov-report=xml
      - name: Build
        run: poetry build
```

### 6.4 Dependency Management (Poetry)

```toml
# pyproject.toml (Poetry excerpt)
[tool.poetry]
name = "your-package"
version = "0.1.0"
description = "Example project"
authors = ["You <you@example.com>"]

[tool.poetry.dependencies]
python = "^3.13"
requests = "^2.32"

[tool.poetry.group.dev.dependencies]
pytest = "^8.3"
pytest-cov = "^5.0"
pytest-benchmark = "^4.0"
hypothesis = "^6.112"
ruff = "^0.6"
black = "^24.10"
mypy = "^1.11"
bandit = "^1.7"
pip-audit = "^2.7"
radon = "^6.0"
pre-commit = "^4.0"
```

### 6.5 Virtual Environment Best Practices
- Use per-project virtualenvs via Poetry (`poetry env use 3.13`).
- Avoid global installs; pin and lock dependencies; enable reproducible builds.


## 7. Starter Config Snippets (Copy-Paste Ready)

- Minimal `pytest.ini`, `mypy.ini` and `pyproject.toml` examples are embedded above; adapt names and paths.
- Prefer tool configuration in `pyproject.toml` where supported.


## 8. Adoption Checklist
- [ ] Create `pyproject.toml` and adopt `src/` layout
- [ ] Enable Black + Ruff in pre-commit
- [ ] Turn on mypy strict and fix type errors
- [ ] Add pytest + hypothesis + coverage baseline
- [ ] Add CI workflow with lint/type/test/coverage gate
- [ ] Integrate security scans (Bandit, pip-audit)
- [ ] Measure complexity (Radon) and refactor hot spots


## 9. References
- What’s New in Python 3.13 — CPython Docs: https://docs.python.org/3/whatsnew/3.13.html
- Real Python: Python 3.13 features overview: https://realpython.com/python313-new-features/
- Trio.dev: Python 3.13 new features summary: https://trio.dev/python-3-13-new-features/
- Typing Specification & Council: https://typing.readthedocs.io/

