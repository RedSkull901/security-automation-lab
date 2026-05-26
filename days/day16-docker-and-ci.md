# Day 16 — Docker + GitHub Actions: Packaging and Protecting the Pipeline

## The problem these solve

After Day 15 the API works on the development machine.
But "works on my machine" is not a deployable statement.

Two things are still missing:

1. **Reproducibility** — someone else (or a server) should be able to run this
   with a single command, without installing Python, setting up virtualenvs,
   or knowing the right startup order.

2. **Safety net** — every code change is currently tested manually, if at all.
   One bad push can break the detector silently and no one notices until
   an attack isn't caught.

Docker solves the first. GitHub Actions solves the second.

---

## Docker: what it actually is

Docker packages your application and everything it needs — Python interpreter,
dependencies, config — into a single portable unit called an **image**.

When you run the image, it creates a **container**: an isolated process that
behaves the same on your laptop, your VPS, and a cloud server.

The analogy that holds: an image is a recipe, a container is the dish.
You can make many containers from one image. You can ship the image anywhere.

### The Dockerfile

The `Dockerfile` is the recipe. It describes how to build the image layer by layer:

```dockerfile
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.12-slim
COPY --from=builder /install /usr/local
COPY . .
CMD ["uvicorn", "security_core.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Multi-stage build** — two `FROM` statements, two stages:

- Stage 1 (`builder`) installs dependencies. This stage gets thrown away.
- Stage 2 (`runtime`) copies only the installed packages from stage 1, then copies the app.

Why two stages? The `builder` stage needs build tools (compilers, headers) to install
some packages. The final image doesn't need those tools at runtime.
Multi-stage builds keep the final image small and free of build-time attack surface.

### Layer caching

Docker builds images in layers. Each instruction in the Dockerfile is one layer.
Layers are cached — if nothing changed in that layer, Docker reuses the cache.

```dockerfile
COPY requirements.txt .          # ← Layer 1
RUN pip install -r requirements  # ← Layer 2 (only re-runs if requirements.txt changed)
COPY . .                         # ← Layer 3 (re-runs on every code change)
```

This is why `requirements.txt` is copied before the application code.
If you copy everything first, any code change invalidates the pip install layer
and you reinstall all dependencies on every build.
Separate them and pip only re-runs when dependencies actually change.

### The non-root user

```dockerfile
RUN useradd -m appuser && chown -R appuser /app
USER appuser
```

By default, Docker containers run as root. That's a security risk — if the
application is compromised, the attacker has root inside the container.
Running as a non-root user limits the blast radius.
This is a standard production hardening step.

### HEALTHCHECK

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
```

Docker polls this command every 30 seconds. If it fails 3 times in a row,
Docker marks the container as unhealthy and can restart it automatically.
This is how a self-healing service works: the container monitors itself.

---

## docker-compose: running multiple containers together

The API needs Redis eventually (Day 17). Even before that, running them
together via `docker-compose` means one command starts the whole stack:

```bash
docker compose up --build
```

`docker-compose.yml` describes the services, their environment variables,
which ports to expose, and which volumes to mount.

### Volumes

```yaml
volumes:
  - /var/log/auth.log:/var/log/auth.log:ro   # host path : container path : mode
  - ./data:/app/data
  - ./config:/app/config:ro
```

Three mounts, three purposes:

- `auth.log` read-only — the container reads system logs but can never write to them
- `./data` read-write — the event store persists across container restarts
- `./config` read-only — secrets stay outside the image, on the host filesystem

The `:ro` flag is a security control. If the application is compromised,
it cannot modify files mounted read-only.

### Service dependencies

```yaml
depends_on:
  redis:
    condition: service_healthy
```

`condition: service_healthy` means the API container waits until Redis
passes its own healthcheck before starting. Without this, the API might
start before Redis is ready, fail to connect, and crash.

### The .dockerignore file

Like `.gitignore` but for Docker builds. Without it, `COPY . .` copies
everything — including `config/api_keys.env`, `data/events.jsonl`,
`__pycache__`, `.git/`.

```
config/
data/
__pycache__/
*.env
.git/
```

Secrets never enter the image. The image is safe to push to a registry.

---

## GitHub Actions: automated CI

CI stands for Continuous Integration — the practice of automatically testing
every code change before it merges.

GitHub Actions runs workflows defined as YAML files in `.github/workflows/`.
Every `git push` triggers the workflow.

### What the workflow does

```yaml
on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]
```

Triggers on every push to `main` or `dev`, and on every pull request targeting `main`.

```yaml
steps:
  - uses: actions/checkout@v4          # pulls the code
  - uses: actions/setup-python@v5      # installs Python 3.12
    with:
      cache: "pip"                     # caches ~/.cache/pip between runs
  - run: pip install -r requirements.txt
  - run: python -m pytest security_core/tests/ -v
```

`cache: "pip"` is a small but meaningful optimisation. The first run downloads
and caches all packages. Subsequent runs restore from cache in seconds instead
of re-downloading.

### The secret check

```yaml
- name: Check for secrets accidentally committed
  run: |
    if grep -r "ABUSEIPDB_API_KEY=[^$]" config/ 2>/dev/null; then
      echo "ERROR: Real API key found in config/"
      exit 1
    fi
```

This step fails the build if a real API key is ever committed to `config/`.
The pattern `[^$]` matches any value that isn't an empty variable reference —
so `ABUSEIPDB_API_KEY=abc123` fails, but `ABUSEIPDB_API_KEY=` passes.

A failed CI build is much better than a leaked credential.

### What CI looks like in practice

```
git push origin main
    │
    ▼
GitHub Actions triggers
    │
    ├── ✓ Checkout code          (2s)
    ├── ✓ Setup Python + cache   (8s)
    ├── ✓ Install dependencies   (12s)
    ├── ✓ Run 32 tests           (4s)
    └── ✓ Secret check           (1s)

Total: ~30 seconds
Status: green ✓ — safe to deploy
```

If any step fails, GitHub shows a red ✗ on the commit and notifies you.
You don't need to remember to run tests. The pipeline enforces it.

---

## Running the full stack

```bash
# Build and start everything
docker compose up --build

# Run in the background
docker compose up --build -d

# Check container status
docker compose ps

# View API logs
docker compose logs api -f

# Run tests inside the container
docker compose exec api python -m pytest security_core/tests/ -v

# Stop everything
docker compose down

# Stop and remove volumes (wipes event store)
docker compose down -v
```

The API will be available at `http://localhost:8000`.
Redis will be available at `localhost:6379`.

---

## Project structure after Day 16

```
security-automation-lab/
├── .github/
│   └── workflows/
│       └── ci.yml               ← runs on every push
├── config/
│   ├── allowlist_ips.txt
│   ├── api_keys.env             ← gitignored, never in image
│   └── webhook.env              ← gitignored, never in image
├── data/
│   └── events.jsonl             ← gitignored, persisted via volume
├── days/
│   └── day2 through day16.md
├── scripts/
│   └── detect_bruteforce_timebased.py   ← original script, untouched
├── security_core/               ← the product
│   ├── api/
│   ├── detectors/
│   ├── engine/
│   ├── enrichment/
│   ├── response/
│   ├── store/
│   ├── tests/
│   ├── utils/
│   └── config.py
├── .dockerignore
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Lessons

**The Dockerfile is infrastructure as code.**
The exact Python version, the exact dependencies, the exact startup command —
all of it is version-controlled alongside the application.
Six months from now, `docker compose up --build` produces the same result
it produces today. No "I think it was Python 3.11?" conversations.

**CI is not about catching bugs. It's about catching regressions.**
A regression is when something that worked starts failing.
Without CI, regressions are caught by users.
With CI, they're caught in 30 seconds on the next push.
The 32 tests written in Days 14–15 exist for exactly this reason —
they define what "working" means so the pipeline can verify it automatically.

**Secrets belong in the environment, not the image.**
The image is a build artifact. It gets pushed to registries, shared with teams,
stored in logs. Any secret baked into the image is a leaked secret.
Volumes and environment variables keep secrets out of the image entirely.
`.dockerignore` is the enforcement mechanism — without it, `COPY . .`
would happily include `config/api_keys.env` in the image.

**Health endpoints earn their keep at 3am.**
When a container crashes at 3am, Docker's HEALTHCHECK restarts it automatically.
Without the `/health` endpoint, Docker has no way to know the service is down.
With it, the service self-heals before anyone wakes up.
