# Contributing guide

## Commit guidelines

### Subject line content

The subject line of a commit should explain what files or topic in the project
is being modified as well as the overall change that is being made.

For example, if the overall documentation format is being changed to meet a new
standard, a good subject line would be as follows:

```
documentation: rework to fit standard X
```

Another example, if a specific documentation file is being changed to fix
spelling errors, a good subject line would be as follows:

```
documentation/some-file.md: fix spelling errors
```

### Subject line format

The subject line should be no longer than 72 characters. Past this it will wrap
when reading via a standard sized terminal. If the changes cannot be summarized
in that length then the commit is likely better split into multiple commits.

The `topic: summary of what changed` format is preferred but will not be
enforced. As long as it includes the topic and a summary of what changed it is
acceptable.

### Body content

The body of the commit should explain the why the commit is needed or wanted.

The body may also give more detail on what is being changed or how it is being
changed.

With simple and obvious commits this is not always necessary and the body of the
commit may be omitted.

### Body format

Body text should usually not go past 72 characters per line. This is not a hard
rule and can be broken where appropriate. For example, if error text is included
in the commit body and is longer than 72 characters, it does not need to be
broken into shorter lines.

## Contributing code

If you have improvements to this project, send us your pull requests! For those
just getting started, GitHub has a
[how-to](https://help.github.com/articles/using-pull-requests/).

Here are some general guidelines and philosophy for contributing code:
*   Include unit tests when you contribute new features, as they help to a)
    prove that your code works correctly, and b) guard against future breaking
    changes to lower the maintenance cost.
*   Bug fixes also generally require unit tests, because the presence of bugs
    usually indicates insufficient test coverage.
*   Keep API compatibility in mind when you change code in core design,
    e.g., code in
    [common/python](https://github.com/cc-api/evidence-api/tree/main/common/python).

Project team members will be assigned to review your pull requests. Once the
pull requests are approved and pass continuous integration checks,
your pull request will be merged automatically on GitHub.

Before sending your pull request for
[review](https://github.com/cc-api/evidence-api/pulls),
make sure your changes are consistent with the guidelines and follow the
coding style.

### Python coding style

Changes to Python code should conform to
[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

Use `pylint` to check your Python changes. To install `pylint` and check a file
with `pylint` against custom style definition:

```bash
source setupenv.sh
pip install pylint
pylint --rcfile=.github/pylintrc myfile.py
```

Note `pylint --rcfile=.github/pylintrc` should run from the
top level project directory.
