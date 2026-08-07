# Security policy

Meerkat is an open-source research tool. If you find a vulnerability, please
report it privately so it can be fixed before it is public.

## Reporting

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository, then **Report a vulnerability**. This opens a private thread with
the maintainer. Please do not open a public issue for a security problem.

Include what the problem is, how to reproduce it, and its impact. A proof of
concept helps.

## Scope

The code in `core/`, `meerkat/` and `bench/`, and the model-loading and
export paths in particular, since they read files a user may not have
produced. The bundled AIT alert data is a public dataset and is out of scope.

## Supported versions

The latest release on the `main` branch is the one that receives fixes.
