# Contributing

## Development environment

We recommend using the provided [Dev
Container](https://code.visualstudio.com/docs/devcontainers/containers). It
gives you a consistent toolchain and avoids “works on my machine” issues.

## Static analysis

```sh
# Formatting with ruff
# See https://docs.astral.sh/ruff/formatter/#sorting-imports for double command
ruff check --select I --fix # Sort imports
uv run ruff format
# Linting with ruff
uv run ruff check
# Type checking with ty
uv run ty check
# Type checking with pyright
uv run pyright
```

## Tests

Run the unit tests locally with uv and pytest:

```sh
uv run pytest
```

- Set `ARCJET_LOG_LEVEL=debug` to see detailed debug logs during development.

### Mocked tests

Mocked tests stub the Decide API protobufs and clients, so no network access is
required.

_The mocked test monkeypatch various internal SDK things and need to be
isolated (read: run entirely seperately) from the other tests._

```sh
uv run pytest tests/mocked
```

## Breaking changes

Check if there are any breaking changes in the public API using Griffe:

```sh
# Check against the most recent tag (default)
uvx griffe check arcjet -s src
# Check against `main` branch
uvx griffe check arcjet -s src --against main
```

## Releasing

1. Create a new branch `git checkout -b release-0.1.0`
2. Bump the version using `uv version --bump` e.g. `uv version --bump patch`.
3. Commit and push the changes to GitHub, then open a PR.
4. Once merged to `main`, create a new Git tag with the new version e.g. `git tag -a v0.1.0 -m v0.1.0`
4. Push the tag to GitHub e.g. `git push --tags`
5. The release workflow will be triggered automatically and must be approved by another member of the team.
6. Once approved, the package will be pushed to PyPI
7. Create a new release in GitHub and link the release to the newly created tag.
