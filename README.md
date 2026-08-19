# Vault Plugin: Harbor Secrets Backend

A [HashiCorp Vault](https://www.vaultproject.io) secrets engine that issues
[Harbor](https://goharbor.io) robot accounts on demand and deletes them from
Harbor when their lease ends.

Harbor measures a robot account's own expiry in whole days, which is too coarse
to hand one to a build job. Binding the account to a Vault lease makes the lease
its real lifetime: revoke the lease and the account stops working within
seconds, whatever its expiry says. Harbor's expiry stays as a backstop, so an
account that Vault somehow loses track of still disappears on its own.

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [Harbor robot account API](https://goharbor.io/docs/latest/administration/robot-accounts/)
- [Vault plugin system](https://developer.hashicorp.com/vault/docs/plugins)

## Getting Started

This is a [Vault secrets plugin](https://developer.hashicorp.com/vault/docs/secrets)
and is meant to work with Vault. Familiarity with
[plugin registration](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture)
is assumed.

### Build

```sh
make linux
```

The result is a static binary with no runtime dependencies. Put it in the
directory named by `plugin_directory` in the Vault server configuration.

### Register and enable

```sh
SHA=$(sha256sum vault-plugin-secrets-harbor-linux-amd64 | cut -d' ' -f1)

vault plugin register \
  -sha256="$SHA" \
  -command=vault-plugin-secrets-harbor \
  -version=v0.1.0 \
  secret vault-plugin-secrets-harbor

vault secrets enable \
  -path=harbor \
  -plugin-version=v0.1.0 \
  vault-plugin-secrets-harbor
```

## Usage

### Configure the connection

The account you give the engine must be allowed to manage robot accounts, which
a project-level robot cannot do. Either a Harbor administrator or a system-level
robot works; the robot is the smaller grant and is what the examples assume.

Create it as a system robot. The permissions it needs are split across the two
steps of the wizard, and the split is not obvious: the engine creates and
deletes accounts with project permissions but lists them with a system one.

On **Select System Permissions**, one box:

| Resource | List |
| --- | --- |
| Robot Account | yes |

That covers verifying the configuration and finding accounts left behind by an
interrupted create. Listing is refused with only the project permission.

On **Select Project Permissions**, either tick **Cover all projects** or select
the projects your roles will name, and grant:

| Resource | Create | Delete | Pull | Push |
| --- | --- | --- | --- | --- |
| Robot Account | yes | yes | | |
| Repository | | | yes | yes |

Robot Account here is what allows an account to be issued at all; the system
permission above does not cover it. Repository is what the issued accounts
receive, and Harbor does not let a robot grant permissions it does not hold
itself, so an engine account without Push will happily issue accounts that
cannot push and the failure only shows up at `docker push`.

Give the account no expiry of its own. It is the engine's root credential, and
its lifetime is a rotation question rather than an expiry one.

In API terms that is `resource: robot` with `list` under `kind: system`, plus
`resource: robot` with `create` and `delete` and `resource: repository` with
`pull` and `push` under `kind: project`.

```sh
vault write harbor/config \
  url=https://harbor.example.com \
  username=admin \
  password=...
```

Writing the configuration verifies the credentials against Harbor and refuses
them if the instance rejects them, so a typo fails immediately rather than at
the first issued credential. Reading the configuration never returns the
password.

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Base URL of the Harbor instance |
| `username` | yes | Account allowed to manage robot accounts |
| `password` | yes | Password for that account |
| `insecure_tls` | no | Skip verification of the Harbor certificate |

### Define a role

A role decides which project an issued account may act on and what it may do
there. The project is part of the role rather than of the request, which is what
lets a Vault policy confine a caller to one project: grant `harbor/creds/ci` and
the caller cannot reach any other project, because there is nowhere in the
request to name one.

```sh
vault write harbor/roles/ci \
  project=my-project \
  push=true \
  ttl=1h \
  max_ttl=8h
```

| Field | Required | Description |
| --- | --- | --- |
| `project` | yes | Harbor project the issued accounts may act on |
| `push` | no | Grant push in addition to pull, defaults to pull only |
| `ttl` | no | Lifetime of an issued account |
| `max_ttl` | no | Longest an issued account may be renewed for |

`max_ttl` cannot exceed the lifetime of the robot account itself, and a role
asking for more is refused when it is written rather than when a credential is
first issued.

### Issue a credential

```sh
vault read harbor/creds/ci
```

```
Key                Value
---                -----
lease_id           harbor/creds/ci/9kPmT...
lease_duration     1h
lease_renewable    true
name               robot$my-project+vault-ci-1755612345678901234
secret             ...
```

`name` and `secret` are the username and password for `docker login`. When the
lease expires or is revoked, the account is deleted from Harbor.

```sh
vault lease revoke harbor/creds/ci/9kPmT...
```

### Restricting a caller to one project

```hcl
path "harbor/creds/ci" {
  capabilities = ["read"]
}
```

That policy grants exactly one project with exactly the permissions its role
carries. Nothing in the request can widen it.

## Developing

```sh
make test
```

The tests run against a stub of the Harbor API, so no Harbor instance is needed
to work on the plugin. They cover the parts worth protecting: that an issued
account is scoped to the project its role names, that revoking a lease deletes
the account, and that a lease can never be renewed past the point where the
account stops existing.

```sh
make build   # host binary
make linux   # linux/amd64 binary for a Vault server
make lint
```

If Vault is interrupted between creating an account in Harbor and recording the
lease, that account is left behind with nothing pointing at it. Vault cannot
find it again: Harbor's robot listing returns only system-level accounts, so an
issued project account is invisible to the engine once its id is lost. What
bounds the damage instead is the expiry the engine sets on every account it
creates, after which Harbor stops honouring it.

## Releases

A release carries the `linux/amd64` binary and its `SHA256SUMS`, because that is
what a Vault server needs to fetch and verify. Versions and release notes come
from the commit messages, and the build is attached in the same run, using only
the token GitHub gives the workflow.

## Authorship

Written with [Claude](https://claude.ai). The test suite covers what the plugin
promises, so its behaviour can be checked rather than taken on trust.

## License

Apache License 2.0, see [LICENSE](LICENSE).
