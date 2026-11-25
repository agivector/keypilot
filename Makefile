GO_IMAGE ?= golang:1.24-alpine
GO_RACE_IMAGE ?= golang:1.24
PYTHON_IMAGE ?= python:3.12-slim
MAVEN_IMAGE ?= maven:3.9.11-eclipse-temurin-21
IMAGE ?= keypilot:dev

.PHONY: fmt vet test verify build docker-test docker-go-sdk-test docker-python-sdk-test docker-java-sdk-test docker-sdk-test docker-verify docker-python-package-check docker-java-package-check release-package-check docker-build docker-run e2e

fmt:
	cd server && gofmt -w $$(find . -name '*.go' -type f)
	cd sdk/go && gofmt -w $$(find . -name '*.go' -type f)
	cd examples/go && gofmt -w $$(find . -name '*.go' -type f)

vet:
	cd server && go vet ./...
	cd sdk/go && go vet ./...
	cd examples/go && go vet ./...

test:
	cd server && go test ./...
	cd sdk/go && go test ./...

verify: fmt vet test

build:
	cd server && CGO_ENABLED=0 go build -trimpath -o ../bin/keypilot ./cmd/keypilot
	cd server && CGO_ENABLED=0 go build -trimpath -o ../bin/keypilotctl ./cmd/keypilotctl

docker-test:
	docker run --rm --user "$$(id -u):$$(id -g)" \
		-e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
		-v "$(CURDIR)/server:/workspace" -w /workspace \
		$(GO_IMAGE) sh -c 'gofmt -w $$(find . -name "*.go" -type f) && go vet ./... && go test ./...'

docker-go-sdk-test:
	docker run --rm --user "$$(id -u):$$(id -g)" -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
		-v "$(CURDIR):/workspace" -w /workspace/sdk/go \
		$(GO_RACE_IMAGE) sh -c 'gofmt -w *.go && go vet ./... && go test -race ./...'

docker-python-sdk-test:
	docker run --rm -e PYTHONPYCACHEPREFIX=/tmp/pycache \
		-v "$(CURDIR):/workspace:ro" -w /workspace/sdk/python \
		$(PYTHON_IMAGE) sh -c 'pip install --quiet --root-user-action=ignore "cryptography>=42,<47" && PYTHONPATH=src python -m compileall -q src tests && PYTHONPATH=src python -m unittest discover -s tests -v'

docker-java-sdk-test:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp \
		-v "$(CURDIR):/workspace" -w /workspace/sdk/java \
		$(MAVEN_IMAGE) mvn -B -Dmaven.repo.local=/tmp/m2 test

docker-sdk-test: docker-go-sdk-test docker-python-sdk-test docker-java-sdk-test

docker-verify: docker-test docker-sdk-test

docker-python-package-check:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -e PYTHONPYCACHEPREFIX=/tmp/pycache \
		-v "$(CURDIR):/workspace" -w /workspace/sdk/python \
		$(PYTHON_IMAGE) sh -c 'python -m pip install --quiet --disable-pip-version-check build twine && rm -rf /tmp/keypilot-python-dist && python -m build --outdir /tmp/keypilot-python-dist && python -m twine check /tmp/keypilot-python-dist/* && python -c '\''import glob, zipfile; wheel = glob.glob("/tmp/keypilot-python-dist/*.whl")[0]; archive = zipfile.ZipFile(wheel); assert any(name.endswith("/licenses/LICENSE") for name in archive.namelist())'\'''

docker-java-package-check:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp \
		-v "$(CURDIR):/workspace" -w /workspace/sdk/java \
		$(MAVEN_IMAGE) sh -c 'mvn -B -P release -Dgpg.skip=true -Dmaven.repo.local=/tmp/m2 verify && test -f target/keypilot-sdk-$$(cat /workspace/VERSION).jar && test -f target/keypilot-sdk-$$(cat /workspace/VERSION)-sources.jar && test -f target/keypilot-sdk-$$(cat /workspace/VERSION)-javadoc.jar && jar tf target/keypilot-sdk-$$(cat /workspace/VERSION).jar | grep -q "^META-INF/LICENSE$$"'

release-package-check:
	./scripts/verify-release.sh
	$(MAKE) docker-python-package-check
	$(MAKE) docker-java-package-check

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	@test -n "$(KEYPILOT_ADMIN_TOKEN)" || (echo "KEYPILOT_ADMIN_TOKEN is required" && exit 1)
	docker run --rm -p 8080:8080 \
		-e KEYPILOT_ADMIN_TOKEN="$(KEYPILOT_ADMIN_TOKEN)" \
		-v keypilot-data:/data \
		$(IMAGE)

e2e:
	./scripts/e2e.sh
