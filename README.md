# Secure CI

A GitHub Action that watches your CI/CD job for two things: secrets leaving over the network, and connections to places your build has no reason to talk to.

Most build-time security tools see traffic as encrypted blobs — they can tell you *that* the runner phoned home, not *what* it sent. Secure CI reads TLS at the library level using an eBPF uprobe, so it sees the plaintext request after the app encrypts it. No man-in-the-middle proxy, no fake CA cert, nothing for your build to trust. If a dependency exfiltrates an AWS key during `npm install`, you find out.

## Quick start

Drop one line above your build. No account, no API key, no config:

```yaml
steps:
  - uses: o3security/secure-ci@v1

  - name: Build
    run: npm install && npm run build
```

That's it. Secure CI starts before your build, watches every TLS connection it makes, and writes a security summary to the job — leaked secrets, where the build connected, and which process did it. Findings print to the job log.

## Get the dashboard, blocking, and history (free account)

Add an `api_key` and your findings go to the O3 Security dashboard, where you get a persisted egress baseline across runs, blocking policy, team management, and SIEM export. [Sign up free at o3.security](https://o3.security) and create an API key, then:

```yaml
steps:
  - uses: o3security/secure-ci@v1
    with:
      api_key: ${{ secrets.O3_API_KEY }}
      project_name: my-app

  - name: Build
    run: npm install && npm run build
```

| | No key (free) | With an `api_key` |
|---|:---:|:---:|
| Reads inside TLS, finds leaked secrets | ✅ | ✅ |
| Catches DNS-tunnel / DoH exfiltration | ✅ | ✅ |
| Per-step process context | ✅ | ✅ |
| Findings in the job summary | ✅ | ✅ |
| Dashboard + cross-run egress baseline | — | ✅ |
| Egress **blocking** policy (allowlist) | — | ✅ |
| Team management + SIEM (Splunk/Elasticsearch) | — | ✅ |
| Runtime security (KAYO kernel agent) | — | ✅ |

## Blocking egress

`policy: audit` watches and reports. `policy: block` actually drops connections — anything on TCP 80/443 that isn't in your allowlist doesn't go through.

```yaml
- uses: o3security/secure-ci@v1
  with:
    api_key: ${{ secrets.O3_API_KEY }}
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

By default it looks for common credential shapes. To scan for your own patterns, point it at a YAML file:

```yaml
- uses: o3security/secure-ci@v1
  with:
    patterns: .github/secure-ci-patterns.yaml
```

```yaml
# .github/secure-ci-patterns.yaml
patterns:
  - id: aws_access_key
    regex: 'AKIA[0-9A-Z]{16}'
  - id: github_token
    regex: 'ghp_[A-Za-z0-9]{36}'
```

## Egress baseline

Secure CI remembers where your builds normally connect. The first few runs are a learning phase; after that, a connection to somewhere new gets flagged as a possible supply-chain change. This is how you catch a compromised dependency that starts reaching out to a server it never used before. Baseline state lives in the backend when you pass an `api_key`.

## Runtime security (optional)

Set `runtime_security: true` to also run KAYO, a kernel-level agent built on eBPF. Where Secure CI watches the network, KAYO watches the kernel — file access, process exec, egress — and reports detections to the same dashboard. KAYO needs an `api_key` and a `project_name` with runtime rules configured (rules are pulled from the backend), so it's part of the account tier.

```yaml
- uses: o3security/secure-ci@v1
  with:
    api_key: ${{ secrets.O3_API_KEY }}
    project_name: my-app
    runtime_security: true
```

## Inputs

### Dashboard (optional)

| Input | Default | What it does |
|-------|---------|--------------|
| `api_key` | _(empty)_ | O3 Security API key. Leave blank for free audit mode; set it for blocking, dashboard, baseline, SIEM. |
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
| `docker_image` | _(public GAR)_ | Override the image for air-gapped setups. |

## What you get

Most build-time egress tools see traffic as encrypted blobs — they can tell you *that* the runner connected somewhere, not *what* it sent. Secure CI reads TLS plaintext at the library level, so it sees inside the request.

- **Reads inside TLS** — plaintext request capture via an eBPF uprobe on `libssl`, no proxy and no CA cert.
- **Finds secrets in traffic** — credentials leaving in request URLs, headers, or bodies, with your own custom regex patterns.
- **Catches DNS-tunnel / DoH exfiltration** — data smuggled out inside an HTTPS request to an otherwise-allowed host.
- **Egress block** — drop outbound 80/443 to anything not on your allowlist (iptables), with SSH always kept open.
- **Per-step process context** — which process made each connection, and what spawned it.
- **Egress baseline** — learns where your builds normally connect and flags new destinations.
- **Runs with no account** — audit mode works with zero config; an `api_key` adds blocking, the dashboard, baselines, and more.
- **SIEM** — stream findings to Splunk or Elasticsearch.

## Notes

- The action runs on `ubuntu-latest`. It needs a privileged container and host PID/network access, which GitHub-hosted Linux runners allow.
- On GitHub-hosted runners the egress baseline persists through the backend (with an `api_key`). Without one you get a single-run view.

---

Built by [O3 Security](https://o3.security).
