# 🔒 Docker Security Scanner

A beginner-friendly tool to scan Docker images for vulnerabilities and lint
Dockerfiles for security best practices.

---

## 📦 What It Does

| Feature                  | What it checks                                      |
|--------------------------|-----------------------------------------------------|
| **Image CVE Scanning**   | Known vulnerabilities in packages (via Trivy)       |
| **Dockerfile Linting**   | Root user, secrets, dangerous patterns, best practices |
| **HTML Report**          | Beautiful, shareable security report                |

---

## 🚀 Quick Start

### Step 1 — Clone / download the project

```bash
git clone <your-repo>
cd docker-security-scanner
```

### Step 2 — Install Trivy (for image scanning)

```bash
# macOS
brew install trivy

# Ubuntu / Debian
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Windows (via Scoop)
scoop install trivy
```

> ✅ Dockerfile linting works **without** Trivy. Only image scanning needs it.

### Step 3 — Run the scanner

```bash
# Lint a Dockerfile only (no Trivy needed)
python cli.py --dockerfile sample/Dockerfile.bad

# Scan a Docker image only
python cli.py --image nginx:latest

# Scan both image + Dockerfile
python cli.py --image nginx:latest --dockerfile ./Dockerfile

# Save a full HTML report
python cli.py --image nginx:latest --dockerfile ./Dockerfile --output report.html

# Output as JSON (great for CI/CD pipelines)
python cli.py --image nginx:latest --json
```

---

## 📋 Dockerfile Rules

| Rule ID | Severity | What it checks                        |
|---------|----------|---------------------------------------|
| DF001   | HIGH     | Avoid `:latest` tag                   |
| DF002   | MEDIUM   | Untagged FROM instruction             |
| DF003   | CRITICAL | `USER root` in Dockerfile             |
| DF004   | HIGH     | No USER instruction (runs as root)    |
| DF005   | CRITICAL | Hardcoded secrets in ENV              |
| DF006   | CRITICAL | Hardcoded secrets in ARG              |
| DF007   | CRITICAL | `curl \| bash` anti-pattern           |
| DF008   | HIGH     | `sudo` used in RUN                    |
| DF009   | MEDIUM   | `chmod 777` detected                  |
| DF010   | MEDIUM   | apt cache not cleaned after install   |
| DF011   | LOW      | ADD used instead of COPY              |
| DF012   | INFO     | No HEALTHCHECK instruction            |

---

## 📁 Project Structure

```
docker-security-scanner/
├── cli.py                        ← Main entry point (run this!)
├── requirements.txt
├── scanner/
│   ├── image_scanner.py          ← Trivy integration
│   ├── dockerfile_linter.py      ← Regex-based rule engine
│   └── report_generator.py       ← Console + HTML output
└── sample/
    ├── Dockerfile.bad            ← Intentionally broken (test with this!)
    └── Dockerfile.good           ← Best practices example
```

---

## 🧪 Test It Right Now

```bash
# See all the bad practices flagged:
python cli.py --dockerfile sample/Dockerfile.bad

# See a clean result:
python cli.py --dockerfile sample/Dockerfile.good

# Generate a report:
python cli.py --dockerfile sample/Dockerfile.bad --output report.html
open report.html
```

---

## 🔧 Adding Your Own Rules

Open `scanner/dockerfile_linter.py` and add to the `RULES` list:

```python
{
    "id":       "DF013",
    "severity": "HIGH",
    "title":    "My custom rule",
    "pattern":  r"some_regex_pattern",
    "message":  "Why this is bad",
    "fix":      "How to fix it",
    "scope":    "line",
},
```

---

## 🛣️ Roadmap / Next Steps

- [ ] Runtime container auditing (Docker SDK)
- [ ] Secrets detection in files/layers
- [ ] CI/CD integration (GitHub Actions example)
- [ ] Registry scanning (ECR, DockerHub)
- [ ] SBOM (Software Bill of Materials) generation

---

## 📚 Learning Resources

- [Trivy Docs](https://github.com/aquasecurity/trivy)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
