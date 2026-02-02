# Docker Hub Release

## Build & Tag
```bash
docker build -t girste/chihuaudit:latest .
docker tag girste/chihuaudit:latest girste/chihuaudit:v1.0
```

## Push
```bash
docker login
docker push girste/chihuaudit:latest
docker push girste/chihuaudit:v1.0
```

## Test Pull
```bash
docker pull girste/chihuaudit:latest
docker run --rm girste/chihuaudit:latest version
```
