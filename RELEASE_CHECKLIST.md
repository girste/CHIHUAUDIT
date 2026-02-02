# Release Checklist v0.0.10 "Stable"

**⚠️ DO NOT EXECUTE - WAIT FOR USER CONFIRMATION**

This checklist contains all commands needed for GitHub release and Docker Hub publication.

---

## Pre-Release Verification ✅

- [x] All code renamed from mcp-watchdog to Chihuaudit
- [x] Documentation updated (README, CONTRIBUTING, docs/)
- [x] Example outputs have fictional data disclaimers
- [x] Discord propic configured in config files
- [x] UPX compression enabled in .goreleaser.yml
- [x] All tests passing: `go test ./...`
- [x] Binary builds: `make build-upx`
- [x] Docker builds: `docker build -t chihuaudit:latest .`
- [x] No old references in documentation
- [x] All CI/CD workflows updated

---

## Step 1: Final Pre-Release Checks

Run these commands to verify everything is ready:

```bash
cd /opt/chihuaudit

# Run all pre-release checks
make pre-release

# Verify no uncommitted changes
git status

# Check current version
./bin/chihuaudit --version
```

---

## Step 2: Git Commit & Tag

**IMPORTANT:** Make sure GitHub repository has been renamed to `chihuaudit` first!

```bash
cd /opt/chihuaudit

# Stage all changes
git add -A

# Create commit
git commit -m "$(cat <<'EOF'
Release v0.0.10 - Stable Release

Major Changes:
- Renamed project from mcp-watchdog to Chihuaudit
- Added UPX compression (8.6M → 2.6M)
- Updated all documentation and branding
- Added Discord profile picture support
- All example outputs marked as fictional
- Complete renaming across codebase

Technical Updates:
- Go module: github.com/girste/chihuaudit
- Binary name: chihuaudit
- Docker images: girste/chihuaudit
- Config files: .chihuaudit.yaml
- MCP server name: chihuaudit

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"

# Create annotated tag for v0.0.10
git tag -a v0.0.10 -m "Stable Release v0.0.10 - Chihuaudit"

# Verify tag
git tag -l -n9 v0.0.10

# Show what will be pushed
git log --oneline -5
```

---

## Step 3: Push to GitHub

```bash
cd /opt/chihuaudit

# Push main branch
git push origin main

# Push tags
git push origin --tags

# Verify on GitHub
echo "Check: https://github.com/girste/chihuaudit/releases"
```

---

## Step 4: GitHub Release (GoReleaser)

GoReleaser will automatically:
- Build binaries for all platforms (Linux/macOS, amd64/arm64)
- Apply UPX compression to all binaries
- Create checksums
- Sign binaries with Cosign (if configured)
- Create GitHub Release with artifacts

```bash
cd /opt/chihuaudit

# Option A: Use GoReleaser locally (if installed)
goreleaser release --clean

# Option B: Wait for GitHub Actions to auto-release on tag push
# Check workflow: https://github.com/girste/chihuaudit/actions/workflows/release.yml
```

**Expected artifacts:**
- `chihuaudit_0.0.10_linux_amd64.tar.gz` (~2.6M with UPX)
- `chihuaudit_0.0.10_linux_arm64.tar.gz`
- `chihuaudit_0.0.10_darwin_amd64.tar.gz`
- `chihuaudit_0.0.10_darwin_arm64.tar.gz`
- `checksums.txt`
- Cosign signatures (`.sig`, `.pem`)

---

## Step 5: Docker Build & Tag

```bash
cd /opt/chihuaudit

# Build final Docker image
docker build -t chihuaudit:latest -t chihuaudit:0.0.10 .

# Verify build
docker images | grep chihuaudit

# Test image
docker run --rm chihuaudit:0.0.10 version
docker run --rm chihuaudit:0.0.10 --help

# Tag for Docker Hub
docker tag chihuaudit:latest girste/chihuaudit:latest
docker tag chihuaudit:latest girste/chihuaudit:0.0.10
docker tag chihuaudit:latest girste/chihuaudit:stable

# Tag for GHCR
docker tag chihuaudit:latest ghcr.io/girste/chihuaudit:latest
docker tag chihuaudit:latest ghcr.io/girste/chihuaudit:0.0.10
docker tag chihuaudit:latest ghcr.io/girste/chihuaudit:stable

# Verify tags
docker images | grep chihuaudit
```

---

## Step 6: Push to Docker Hub

```bash
# Login to Docker Hub
docker login
# Enter username: girste
# Enter password: [your Docker Hub token]

# Push all tags
docker push girste/chihuaudit:0.0.10
docker push girste/chihuaudit:latest
docker push girste/chihuaudit:stable

# Verify on Docker Hub
echo "Check: https://hub.docker.com/r/girste/chihuaudit"
```

---

## Step 7: Push to GitHub Container Registry (GHCR)

```bash
# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u girste --password-stdin
# Or use: docker login ghcr.io

# Push all tags
docker push ghcr.io/girste/chihuaudit:0.0.10
docker push ghcr.io/girste/chihuaudit:latest
docker push ghcr.io/girste/chihuaudit:stable

# Verify on GHCR
echo "Check: https://github.com/girste/chihuaudit/pkgs/container/chihuaudit"
```

---

## Step 8: Verify Release

### GitHub Release
- [ ] Visit https://github.com/girste/chihuaudit/releases/tag/v0.0.10
- [ ] Verify all binary artifacts are present
- [ ] Check checksums.txt
- [ ] Verify release notes are correct
- [ ] Test download and extract a binary

### Docker Hub
- [ ] Visit https://hub.docker.com/r/girste/chihuaudit/tags
- [ ] Verify tags: `latest`, `0.0.10`, `stable`
- [ ] Check image size (~300-400MB uncompressed)
- [ ] Pull and test: `docker pull girste/chihuaudit:0.0.10`

### GHCR
- [ ] Visit https://github.com/girste/chihuaudit/pkgs/container/chihuaudit
- [ ] Verify tags present
- [ ] Pull and test: `docker pull ghcr.io/girste/chihuaudit:0.0.10`

---

## Step 9: Post-Release Updates

```bash
cd /opt/chihuaudit

# Update README badges if needed
# (They should auto-update from GitHub)

# Create announcement (optional)
echo "v0.0.10 Stable Release - Chihuaudit is now available!"
```

---

## Step 10: Announce Release

- [ ] Update Discord webhook with release announcement
- [ ] Post on social media (if applicable)
- [ ] Update any documentation sites
- [ ] Notify users/contributors

---

## Rollback Plan (if needed)

If something goes wrong:

```bash
# Delete tag locally
git tag -d v0.0.10

# Delete tag on remote
git push origin :refs/tags/v0.0.10

# Delete GitHub Release (via web UI)
# https://github.com/girste/chihuaudit/releases

# Delete Docker images
docker rmi girste/chihuaudit:0.0.10
docker rmi ghcr.io/girste/chihuaudit:0.0.10

# Fix issues and restart from Step 2
```

---

## Notes

- **GoReleaser:** Requires `GITHUB_TOKEN` for release creation
- **Cosign:** Requires `COSIGN_PRIVATE_KEY` secret for signing (optional)
- **Docker Hub:** Requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets
- **GHCR:** Uses `GITHUB_TOKEN` automatically

All GitHub Actions workflows are already configured and will run automatically on tag push.

---

## Quick Command Reference

```bash
# Status check
git status
./bin/chihuaudit --version
docker images | grep chihuaudit

# Full release (all steps)
make pre-release
git add -A && git commit -m "Release v0.0.10"
git tag -a v0.0.10 -m "Stable Release"
git push origin main --tags
docker build -t chihuaudit:0.0.10 .
docker tag chihuaudit:0.0.10 girste/chihuaudit:0.0.10
docker push girste/chihuaudit:0.0.10
```

---

**Remember:** Wait for user confirmation before executing any of these commands!
