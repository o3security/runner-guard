# Runner Guard

A GitHub Action that watches your CI/CD job for two things: secrets leaving over the network, and connections to places your build has no reason to talk to.

Most build-time security tools see traffic as encrypted blobs — they can tell you *that* the runner phoned home, not *what* it sent. Runner Guard reads TLS at the library level using an eBPF uprobe, so it sees the plaintext request after the app encrypts it. No man-in-the-middle proxy, no fake CA cert, nothing for your build to trust. If a dependency exfiltrates an AWS key during `npm install`, you find out.

## Quick start

```yaml
steps:
  - uses: o3security/runner-guard@v1
    with:
      api_key: ${{ secrets.O3_API_KEY }}
      project_name: my-app

  - name: Build
    run: npm install && npm run build
```

That's it. The guard starts before your build, watches it, and writes a summary to the job. With an `api_key`, findings also show up in the O3 Security dashboard, where you manage allowlists and thresholds.

### No account? Run it inline

You don't need an O3 account to use it. Point it at a policy and it'll monitor or block egress on its own:

```yaml
steps:
  - uses: o3security/runner-guard@v1
    with:
      policy: audit        # just watch and report
      print_only: "true"   # print findings to the job log
```

## Blocking egress

`policy: audit` watches and reports. `policy: block` actually drops connections — anything on TCP 80/443 that isn't in your allowlist doesn't go through.

```yaml
- uses: o3security/runner-guard@v1
  with:
    policy: block
    allowed_domains: |
      api.github.com:443
      registry.npmjs.org:443
      pypi.org:443
    allowed_cidrs: |
      10.0.0.0/8
```

SSH (port 22) is always allowed first, before any block rule. You can't lock yourself out of the runner. The rules are torn down when the job ends, even if it crashes.

Under the hood, block mode installs an iptables chain off `OUTPUT`:

```
1. ACCEPT tcp dpt:22           SSH — always first
2. ACCEPT tcp spt:22           SSH replies
3. ACCEPT on lo                loopback
4. ACCEPT ESTABLISHED,RELATED  don't kill in-flight connections
5. ACCEPT <your allowlist>     allowed_domains / allowed_ips / allowed_cidrs
...
N. DROP tcp dpt:80             everything else
N. DROP tcp dpt:443
```

## Catching secrets

By default the guard looks for common credential shapes. To scan for your own patterns, point it at a YAML file:

```yaml
- uses: o3security/runner-guard@v1
  with:
    policy: block
    patterns: .github/runner-guard-patterns.yaml
```

```yaml
# .github/runner-guard-patterns.yaml
patterns:
  - id: aws_access_key
    regex: 'AKIA[0-9A-Z]{16}'
  - id: github_token
    regex: 'ghp_[A-Za-z0-9]{36}'
```

## Egress baseline

The guard remembers where your builds normally connect. The first few runs are a learning phase; after that, a connection to somewhere new gets flagged as a possible supply-chain change. This is how you catch a compromised dependency that starts reaching out to a server it never used before. Baseline state lives in the backend when you pass an `api_key`.

## Runtime security (optional)

Set `runtime_security: true` to also run KAYO, a kernel-level agent built on eBPF. Where the main guard watches the network, KAYO watches the kernel — file access, process exec, egress — and reports detections to the same dashboard. Rules are pulled from the backend by `project_name`.

```yaml
- uses: o3security/runner-guard@v1
  with:
    api_key: ${{ secrets.O3_API_KEY }}
    project_name: my-app
    runtime_security: true
```

## Inputs

### Dashboard (optional)

| Input | Default | What it does |
|-------|---------|--------------|
| `api_key` | _(empty)_ | O3 Security API key. Leave blank to run inline with no account. |
| `server_url` | `https://api.o3.security/graphql` | O3 API endpoint. |
| `project_name` | _(repo name)_ | Groups findings in the dashboard. |

### Inline policy

| Input | Default | What it does |
|-------|---------|--------------|
| `policy` | `audit` | `audit` watches and reports. `block` drops anything on 80/443 not allowlisted. |
| `allowed_domains` | _(empty)_ | Domains allowed under `block`. One per line or comma-separated. `host:port` works. |
| `allowed_ips` | _(empty)_ | IPs allowed under `block`. |
| `allowed_cidrs` | _(empty)_ | CIDR ranges allowed under `block`. |
| `patterns` | _(empty)_ | Path to a YAML file of secret-detection regexes, or inline YAML. |

### SIEM

| Input | What it does |
|-------|--------------|
| `splunk_url`, `splunk_token` | Send findings to a Splunk HEC endpoint. |
| `es_url`, `es_index`, `es_user`, `es_pass` | Send findings to Elasticsearch. |

### Advanced

| Input | Default | What it does |
|-------|---------|--------------|
| `print_only` | `false` | Print to the job log only — don't upload. |
| `debug` | `false` | Verbose logging. |
| `baseline_enabled` | `true` | Track and flag new egress destinations across runs. |
| `runtime_security` | `false` | Also run the KAYO kernel agent. |
| `docker_image` | _(public ECR)_ | Override the image for air-gapped setups. |

## vs StepSecurity Harden-Runner

Harden-Runner is good at egress control. Where Runner Guard goes further is seeing *inside* the traffic — not just that a connection happened, but what crossed it.

| | Runner Guard | Harden-Runner |
|---|:---:|:---:|
| Runs with no account | yes | no |
| Egress block (iptables) | yes | yes |
| Reads plaintext inside TLS | yes (eBPF uprobe) | no |
| Finds secrets in traffic | yes | no |
| Per-step process context | yes | limited |
| Custom secret patterns | yes | no |
| Splunk / Elasticsearch | yes | no |
| SSH lockout protection | yes | yes |

## Notes

- The action runs on `ubuntu-latest`. It needs a privileged container and host PID/network access, which GitHub-hosted Linux runners allow.
- On GitHub-hosted runners the egress baseline persists through the backend (with an `api_key`). Without one you get a single-run view.

---

Built by [O3 Security](https://o3.security).
