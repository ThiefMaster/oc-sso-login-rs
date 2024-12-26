# oc-sso-login-rs

This is a Rust implementation of the [Python-based `oc sso-login` util][oc-sso-login] from the
CERN PaaS guys.

I mainly wrote this, because besides the fact that I wanted to try doing something in Rust, I was
annoyed by the fact that depending on my active Python environment, I could not use `oc sso-login`
because of its dependency on *requests* and *dnspython* (which I do not have installed in every
single Python environment I'm working on).

[oc-sso-login]: https://gitlab.cern.ch/paas-tools/oc-sso-login
