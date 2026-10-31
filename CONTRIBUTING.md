# Contributing

Thanks for looking. Issues and pull requests are welcome.

## Report a bug or ask for a feature

Open a GitHub issue with what you ran, what you expected and what happened.
For a security problem, do not open an issue: see [SECURITY.md](SECURITY.md).

## Send a change

1. Fork, branch from main, and keep the change small.
2. Run the checks before you push:
   - `python3 -m pytest -q`
   - `ruff check .` and `ruff format --check .`
   - `make demo-all` if you touched the gate or a scenario
3. Add a CHANGELOG.md line under [Unreleased] for anything a user would notice.
4. Open a pull request. CI must pass before review.

## Test rule

Every new control ships with a test that fails when the control is removed.
Add a known-answer test for the behavior and a go-red test that takes the
control out (monkeypatch or a scratch copy, never an edit to the repo) and
shows the bad outcome return. A change without that test is not done.

## Style

Plain Python, standard library where it can be. ruff is the formatter and
linter. Comments say why, not what. Write short, plain sentences in docs.

## License

By contributing you agree your work is released under the MIT license.
