# Releasing tatu-hook

## Pre-release checklist

1. All tests pass:
   ```bash
   make tatu-hook-test
   ```

2. Decide the new version following [semver](https://semver.org/):
   - **patch** (0.1.0 → 0.1.1): bug fixes, rule updates
   - **minor** (0.1.0 → 0.2.0): new features, new rule categories
   - **major** (0.1.0 → 1.0.0): breaking changes to CLI, config format, or hook protocol

## Release steps

### 1. Bump the version

Update the version in **both** files:

- `tatu-hook/pyproject.toml` → `version = "X.Y.Z"`
- `tatu-hook/src/tatu_hook/__init__.py` → `__version__ = "X.Y.Z"`

### 2. Commit the version bump

```bash
git add tatu-hook/pyproject.toml tatu-hook/src/tatu_hook/__init__.py
git commit -m "release: tatu-hook vX.Y.Z"
```

### 3. Create and push the tag

```bash
git tag tatu-hook-vX.Y.Z
git push origin main --tags
```

This triggers the GitHub Actions workflow (`.github/workflows/publish-tatu-hook.yml`) which:
1. Runs tests on Python 3.10–3.13
2. Builds the sdist and wheel
3. Publishes to TestPyPI
4. Publishes to PyPI

### 4. Verify the release

```bash
# Check TestPyPI
pip install --index-url https://test.pypi.org/simple/ tatu-hook==X.Y.Z

# Check PyPI (available a few minutes after the workflow completes)
pip install tatu-hook==X.Y.Z

# Verify
tatu-hook --version
```

### 5. Create a GitHub release (optional)

```bash
gh release create tatu-hook-vX.Y.Z \
  --title "tatu-hook vX.Y.Z" \
  --notes "Brief description of changes"
```

## First-time setup

If this is the first release, you need to configure Trusted Publishing on PyPI:

### PyPI

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new pending publisher:
   - Project name: `tatu-hook`
   - Owner: `laboratoriohacker-com`
   - Repository: `tatu`
   - Workflow: `publish-tatu-hook.yml`
   - Environment: `pypi`

### TestPyPI

1. Go to https://test.pypi.org/manage/account/publishing/
2. Same settings but with environment: `testpypi`

### GitHub

1. Go to repo Settings > Environments
2. Create two environments: `pypi` and `testpypi`
3. Optionally add required reviewers on `pypi` for approval before publishing

## Troubleshooting

| Problem | Solution |
|---|---|
| Workflow fails at test step | Fix the failing tests, create a new tag |
| TestPyPI publish fails with 403 | Verify trusted publisher config matches workflow file and environment name |
| PyPI publish fails with "already exists" | You cannot overwrite a version on PyPI — bump the version and re-tag |
| `pip install` can't find the new version | PyPI indexing takes a few minutes — wait and retry |
