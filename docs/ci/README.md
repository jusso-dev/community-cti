# CI

The live workflow is [.github/workflows/ci.yml](../../.github/workflows/ci.yml). It installs with a frozen lockfile, builds, and runs the test suite, the isolation suite, the red-team fixtures, the scripted agent eval, and the pilot metrics script.

The copy in this folder matches that file. It stays here so the steps are visible in review without opening the workflow directory. The GitHub token for this repository has the `workflow` scope, so the workflow file can live under `.github/workflows/`.
