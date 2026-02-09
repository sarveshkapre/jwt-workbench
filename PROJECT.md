# PROJECT.md

Exact commands for working in this repo.

## Setup

```bash
make setup
```

## Quality gate

```bash
make check
```

## Run

```bash
jwt-workbench --help
```

## Example

```bash
jwt-workbench sign --payload '{"sub":"user","exp":1735689600}' --key-text "secret123"
```
