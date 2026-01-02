# Contributing

## Development environment

We recommend using the provided [Dev
Container](https://code.visualstudio.com/docs/devcontainers/containers). It
gives you a consistent toolchain and avoids “works on my machine” issues.

## Tests

Run the unit tests locally with uv and pytest:

```bash
uv run pytest -q
```

- Tests stub the Decide API protobufs and clients, so no network access is
  required.
- Set `ARCJET_LOG_LEVEL=debug` to see detailed debug logs during development.

## Releasing

1. Bump the version using `uv version --bump` e.g. `uv version --bump minor`.
2. Push the changes to GitHub.
3. Create a new Git tag with the new version e.g. `git tag -a v0.1.0 -m v0.1.0`
4. Push the tag to GitHub e.g. `git push --tags`
5. The release will be created automatically by GitHub Actions.
6. Create a new release in GitHub and link the release to the newly created tag.