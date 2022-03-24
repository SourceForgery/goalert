# Code generated by devtools/genmake, DO NOT EDIT.

.PHONY: $(BIN_DIR)/darwin-amd64/_all $(BIN_DIR)/linux-amd64/_all $(BIN_DIR)/linux-arm/_all $(BIN_DIR)/linux-arm64/_all $(BIN_DIR)/windows-amd64/_all
.PHONY: container-goalert-amd64 container-demo-amd64 container-goalert-arm container-demo-arm container-goalert-arm64 container-demo-arm64 container-goalert container-demo

BIN_DIR=bin
GO_DEPS := Makefile.binaries.mk $(shell find . -path ./web/src -prune -o -path ./vendor -prune -o -path ./.git -prune -o -type f -name "*.go" -print) go.sum
GO_DEPS += migrate/migrations/ migrate/migrations/*.sql graphql2/graphqlapp/playground.html web/index.html graphql2/graphqlapp/slack.manifest.yaml swo/*.sql
GO_DEPS += graphql2/mapconfig.go graphql2/maplimit.go graphql2/generated.go graphql2/models_gen.go

ifdef BUNDLE
	GO_DEPS += web/src/build/static/app.js
endif

GIT_COMMIT:=$(shell git rev-parse HEAD || echo '?')
GIT_TREE:=$(shell git diff-index --quiet HEAD -- && echo clean || echo dirty)
GIT_VERSION:=$(shell git describe --tags --dirty --match 'v*' || echo dev-$(shell date -u +"%Y%m%d%H%M%S"))
BUILD_DATE:=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_FLAGS=

export ZONEINFO:=$(shell go env GOROOT)/lib/time/zoneinfo.zip

LD_FLAGS+=-X github.com/target/goalert/version.gitCommit=$(GIT_COMMIT)
LD_FLAGS+=-X github.com/target/goalert/version.gitVersion=$(GIT_VERSION)
LD_FLAGS+=-X github.com/target/goalert/version.gitTreeState=$(GIT_TREE)
LD_FLAGS+=-X github.com/target/goalert/version.buildDate=$(BUILD_DATE)

IMAGE_REPO=docker.io/goalert
IMAGE_TAG=$(GIT_VERSION)

CONTAINER_TOOL:=$(shell which podman || which docker || exit 1)
PUSH:=0


container-demo-amd64: bin/goalert-linux-amd64.tgz bin/linux-amd64/resetdb
	$(CONTAINER_TOOL) pull --platform=linux/amd64 docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=amd64 --platform=linux/amd64 -t $(IMAGE_REPO)/demo:$(IMAGE_TAG) -f devtools/ci/dockerfiles/demo/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/demo:$(IMAGE_TAG)
endif
container-goalert-amd64: bin/goalert-linux-amd64.tgz
	$(CONTAINER_TOOL) pull --platform=linux/amd64 docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=amd64 --platform=linux/amd64 -t $(IMAGE_REPO)/goalert:$(IMAGE_TAG) -f devtools/ci/dockerfiles/goalert/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/goalert:$(IMAGE_TAG)
endif

container-demo-arm: bin/goalert-linux-arm.tgz bin/linux-arm/resetdb
	$(CONTAINER_TOOL) pull --platform=linux/arm docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=arm --platform=linux/arm -t $(IMAGE_REPO)/demo:$(IMAGE_TAG) -f devtools/ci/dockerfiles/demo/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/demo:$(IMAGE_TAG)
endif
container-goalert-arm: bin/goalert-linux-arm.tgz
	$(CONTAINER_TOOL) pull --platform=linux/arm docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=arm --platform=linux/arm -t $(IMAGE_REPO)/goalert:$(IMAGE_TAG) -f devtools/ci/dockerfiles/goalert/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/goalert:$(IMAGE_TAG)
endif

container-demo-arm64: bin/goalert-linux-arm64.tgz bin/linux-arm64/resetdb
	$(CONTAINER_TOOL) pull --platform=linux/arm64 docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=arm64 --platform=linux/arm64 -t $(IMAGE_REPO)/demo:$(IMAGE_TAG) -f devtools/ci/dockerfiles/demo/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/demo:$(IMAGE_TAG)
endif
container-goalert-arm64: bin/goalert-linux-arm64.tgz
	$(CONTAINER_TOOL) pull --platform=linux/arm64 docker.io/library/alpine:3.14
	$(CONTAINER_TOOL) build --build-arg ARCH=arm64 --platform=linux/arm64 -t $(IMAGE_REPO)/goalert:$(IMAGE_TAG) -f devtools/ci/dockerfiles/goalert/Dockerfile.prebuilt .
ifeq ($(PUSH),1)
	$(CONTAINER_TOOL) push $(IMAGE_REPO)/goalert:$(IMAGE_TAG)
endif

container-demo:  container-demo-amd64 container-demo-arm container-demo-arm64
container-goalert:  container-goalert-amd64 container-goalert-arm container-goalert-arm64

$(BIN_DIR)/build/integration/cypress.json: web/src/cypress.json
	sed 's/\.ts/\.js/' web/src/cypress.json >$@

$(BIN_DIR)/build/integration/cypress: node_modules web/src/webpack.cypress.js $(BIN_DIR)/build/integration/cypress.json $(shell find ./web/src/cypress)
	rm -rf $@
	yarn workspace goalert-web webpack --config webpack.cypress.js
	cp -r web/src/cypress/fixtures $@/
	touch $@


$(BIN_DIR)/build/integration/bin/build/goalert-darwin-amd64: $(BIN_DIR)/build/goalert-darwin-amd64
	rm -rf $@
	mkdir -p $@
	cp -r $(BIN_DIR)/build/goalert-darwin-amd64/goalert $@/
	touch $@

$(BIN_DIR)/build/integration/bin/build/goalert-linux-amd64: $(BIN_DIR)/build/goalert-linux-amd64
	rm -rf $@
	mkdir -p $@
	cp -r $(BIN_DIR)/build/goalert-linux-amd64/goalert $@/
	touch $@

$(BIN_DIR)/build/integration/bin/build/goalert-linux-arm: $(BIN_DIR)/build/goalert-linux-arm
	rm -rf $@
	mkdir -p $@
	cp -r $(BIN_DIR)/build/goalert-linux-arm/goalert $@/
	touch $@

$(BIN_DIR)/build/integration/bin/build/goalert-linux-arm64: $(BIN_DIR)/build/goalert-linux-arm64
	rm -rf $@
	mkdir -p $@
	cp -r $(BIN_DIR)/build/goalert-linux-arm64/goalert $@/
	touch $@

$(BIN_DIR)/build/integration/bin/build/goalert-windows-amd64: $(BIN_DIR)/build/goalert-windows-amd64
	rm -rf $@
	mkdir -p $@
	cp -r $(BIN_DIR)/build/goalert-windows-amd64/goalert $@/
	touch $@


$(BIN_DIR)/build/integration/devtools: $(shell find ./devtools/ci)
	rm -rf $@
	mkdir -p $@
	cp -r devtools/ci $@/
	touch $@

$(BIN_DIR)/build/integration/.git: $(shell find ./.git)
	rm -rf $@
	mkdir -p $@
	test -d .git/resource && cp -r .git/resource $@/ || true
	touch $@

$(BIN_DIR)/build/integration/COMMIT: $(BIN_DIR)/build/integration/.git
	git rev-parse HEAD >$@

$(BIN_DIR)/build/integration: $(BIN_DIR)/build/integration/.git $(BIN_DIR)/build/integration/COMMIT $(BIN_DIR)/build/integration/devtools $(BIN_DIR)/build/integration/cypress $(BIN_DIR)/build/integration/bin/build/goalert-darwin-amd64 $(BIN_DIR)/build/integration/bin/build/goalert-linux-amd64 $(BIN_DIR)/build/integration/bin/build/goalert-linux-arm $(BIN_DIR)/build/integration/bin/build/goalert-linux-arm64 $(BIN_DIR)/build/integration/bin/build/goalert-windows-amd64
	touch $@


$(BIN_DIR)/goalert: $(GO_DEPS) graphql2/mapconfig.go
	go build -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert

$(BIN_DIR)/darwin-amd64/goalert: $(GO_DEPS) graphql2/mapconfig.go web/src/build/static/app.js
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert

$(BIN_DIR)/linux-amd64/goalert: $(GO_DEPS) graphql2/mapconfig.go web/src/build/static/app.js
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert

$(BIN_DIR)/linux-arm/goalert: $(GO_DEPS) graphql2/mapconfig.go web/src/build/static/app.js
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert

$(BIN_DIR)/linux-arm64/goalert: $(GO_DEPS) graphql2/mapconfig.go web/src/build/static/app.js
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert

$(BIN_DIR)/windows-amd64/goalert.exe: $(GO_DEPS) graphql2/mapconfig.go web/src/build/static/app.js
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LD_FLAGS)" -o $@ ./cmd/goalert


$(BIN_DIR)/goalert-slack-email-sync: $(GO_DEPS) 
	go build  -o $@ ./cmd/goalert-slack-email-sync

$(BIN_DIR)/darwin-amd64/goalert-slack-email-sync: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./cmd/goalert-slack-email-sync

$(BIN_DIR)/linux-amd64/goalert-slack-email-sync: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./cmd/goalert-slack-email-sync

$(BIN_DIR)/linux-arm/goalert-slack-email-sync: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./cmd/goalert-slack-email-sync

$(BIN_DIR)/linux-arm64/goalert-slack-email-sync: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./cmd/goalert-slack-email-sync

$(BIN_DIR)/windows-amd64/goalert-slack-email-sync.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./cmd/goalert-slack-email-sync


$(BIN_DIR)/mockslack: $(GO_DEPS) 
	go build  -o $@ ./devtools/mockslack/cmd/mockslack

$(BIN_DIR)/darwin-amd64/mockslack: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/mockslack/cmd/mockslack

$(BIN_DIR)/linux-amd64/mockslack: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/mockslack/cmd/mockslack

$(BIN_DIR)/linux-arm/mockslack: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/mockslack/cmd/mockslack

$(BIN_DIR)/linux-arm64/mockslack: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/mockslack/cmd/mockslack

$(BIN_DIR)/windows-amd64/mockslack.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/mockslack/cmd/mockslack


$(BIN_DIR)/pgdump-lite: $(GO_DEPS) 
	go build  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite

$(BIN_DIR)/darwin-amd64/pgdump-lite: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite

$(BIN_DIR)/linux-amd64/pgdump-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite

$(BIN_DIR)/linux-arm/pgdump-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite

$(BIN_DIR)/linux-arm64/pgdump-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite

$(BIN_DIR)/windows-amd64/pgdump-lite.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/pgdump-lite/cmd/pgdump-lite


$(BIN_DIR)/procwrap: $(GO_DEPS) 
	go build  -o $@ ./devtools/procwrap

$(BIN_DIR)/darwin-amd64/procwrap: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/procwrap

$(BIN_DIR)/linux-amd64/procwrap: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/procwrap

$(BIN_DIR)/linux-arm/procwrap: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/procwrap

$(BIN_DIR)/linux-arm64/procwrap: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/procwrap

$(BIN_DIR)/windows-amd64/procwrap.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/procwrap


$(BIN_DIR)/psql-lite: $(GO_DEPS) 
	go build  -o $@ ./devtools/psql-lite

$(BIN_DIR)/darwin-amd64/psql-lite: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/psql-lite

$(BIN_DIR)/linux-amd64/psql-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/psql-lite

$(BIN_DIR)/linux-arm/psql-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/psql-lite

$(BIN_DIR)/linux-arm64/psql-lite: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/psql-lite

$(BIN_DIR)/windows-amd64/psql-lite.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/psql-lite


$(BIN_DIR)/resetdb: $(GO_DEPS) 
	go build  -o $@ ./devtools/resetdb

$(BIN_DIR)/darwin-amd64/resetdb: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/resetdb

$(BIN_DIR)/linux-amd64/resetdb: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/resetdb

$(BIN_DIR)/linux-arm/resetdb: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/resetdb

$(BIN_DIR)/linux-arm64/resetdb: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/resetdb

$(BIN_DIR)/windows-amd64/resetdb.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/resetdb


$(BIN_DIR)/runproc: $(GO_DEPS) 
	go build  -o $@ ./devtools/runproc

$(BIN_DIR)/darwin-amd64/runproc: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/runproc

$(BIN_DIR)/linux-amd64/runproc: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/runproc

$(BIN_DIR)/linux-arm/runproc: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/runproc

$(BIN_DIR)/linux-arm64/runproc: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/runproc

$(BIN_DIR)/windows-amd64/runproc.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/runproc


$(BIN_DIR)/sendit: $(GO_DEPS) 
	go build  -o $@ ./devtools/sendit/cmd/sendit

$(BIN_DIR)/darwin-amd64/sendit: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit

$(BIN_DIR)/linux-amd64/sendit: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit

$(BIN_DIR)/linux-arm/sendit: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit

$(BIN_DIR)/linux-arm64/sendit: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit

$(BIN_DIR)/windows-amd64/sendit.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit


$(BIN_DIR)/sendit-server: $(GO_DEPS) 
	go build  -o $@ ./devtools/sendit/cmd/sendit-server

$(BIN_DIR)/darwin-amd64/sendit-server: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-server

$(BIN_DIR)/linux-amd64/sendit-server: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-server

$(BIN_DIR)/linux-arm/sendit-server: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-server

$(BIN_DIR)/linux-arm64/sendit-server: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-server

$(BIN_DIR)/windows-amd64/sendit-server.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-server


$(BIN_DIR)/sendit-token: $(GO_DEPS) 
	go build  -o $@ ./devtools/sendit/cmd/sendit-token

$(BIN_DIR)/darwin-amd64/sendit-token: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-token

$(BIN_DIR)/linux-amd64/sendit-token: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-token

$(BIN_DIR)/linux-arm/sendit-token: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-token

$(BIN_DIR)/linux-arm64/sendit-token: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-token

$(BIN_DIR)/windows-amd64/sendit-token.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/sendit/cmd/sendit-token


$(BIN_DIR)/simpleproxy: $(GO_DEPS) 
	go build  -o $@ ./devtools/simpleproxy

$(BIN_DIR)/darwin-amd64/simpleproxy: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/simpleproxy

$(BIN_DIR)/linux-amd64/simpleproxy: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/simpleproxy

$(BIN_DIR)/linux-arm/simpleproxy: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/simpleproxy

$(BIN_DIR)/linux-arm64/simpleproxy: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/simpleproxy

$(BIN_DIR)/windows-amd64/simpleproxy.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/simpleproxy


$(BIN_DIR)/waitfor: $(GO_DEPS) 
	go build  -o $@ ./devtools/waitfor

$(BIN_DIR)/darwin-amd64/waitfor: $(GO_DEPS)  
	GOOS=darwin GOARCH=amd64 go build -trimpath  -o $@ ./devtools/waitfor

$(BIN_DIR)/linux-amd64/waitfor: $(GO_DEPS)  
	GOOS=linux GOARCH=amd64 go build -trimpath  -o $@ ./devtools/waitfor

$(BIN_DIR)/linux-arm/waitfor: $(GO_DEPS)  
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath  -o $@ ./devtools/waitfor

$(BIN_DIR)/linux-arm64/waitfor: $(GO_DEPS)  
	GOOS=linux GOARCH=arm64 go build -trimpath  -o $@ ./devtools/waitfor

$(BIN_DIR)/windows-amd64/waitfor.exe: $(GO_DEPS)  
	GOOS=windows GOARCH=amd64 go build -trimpath  -o $@ ./devtools/waitfor




$(BIN_DIR)/darwin-amd64/_all: $(BIN_DIR)/darwin-amd64/goalert-smoketest $(BIN_DIR)/darwin-amd64/goalert $(BIN_DIR)/darwin-amd64/goalert-slack-email-sync $(BIN_DIR)/darwin-amd64/mockslack $(BIN_DIR)/darwin-amd64/pgdump-lite $(BIN_DIR)/darwin-amd64/procwrap $(BIN_DIR)/darwin-amd64/psql-lite $(BIN_DIR)/darwin-amd64/resetdb $(BIN_DIR)/darwin-amd64/runproc $(BIN_DIR)/darwin-amd64/sendit $(BIN_DIR)/darwin-amd64/sendit-server $(BIN_DIR)/darwin-amd64/sendit-token $(BIN_DIR)/darwin-amd64/simpleproxy $(BIN_DIR)/darwin-amd64/waitfor

$(BIN_DIR)/darwin-amd64/goalert-smoketest: $(GO_DEPS)
	GOOS=darwin GOARCH=amd64 go test ./smoketest -c -o $@

$(BIN_DIR)/linux-amd64/_all: $(BIN_DIR)/linux-amd64/goalert-smoketest $(BIN_DIR)/linux-amd64/goalert $(BIN_DIR)/linux-amd64/goalert-slack-email-sync $(BIN_DIR)/linux-amd64/mockslack $(BIN_DIR)/linux-amd64/pgdump-lite $(BIN_DIR)/linux-amd64/procwrap $(BIN_DIR)/linux-amd64/psql-lite $(BIN_DIR)/linux-amd64/resetdb $(BIN_DIR)/linux-amd64/runproc $(BIN_DIR)/linux-amd64/sendit $(BIN_DIR)/linux-amd64/sendit-server $(BIN_DIR)/linux-amd64/sendit-token $(BIN_DIR)/linux-amd64/simpleproxy $(BIN_DIR)/linux-amd64/waitfor

$(BIN_DIR)/linux-amd64/goalert-smoketest: $(GO_DEPS)
	GOOS=linux GOARCH=amd64 go test ./smoketest -c -o $@

$(BIN_DIR)/linux-arm/_all: $(BIN_DIR)/linux-arm/goalert-smoketest $(BIN_DIR)/linux-arm/goalert $(BIN_DIR)/linux-arm/goalert-slack-email-sync $(BIN_DIR)/linux-arm/mockslack $(BIN_DIR)/linux-arm/pgdump-lite $(BIN_DIR)/linux-arm/procwrap $(BIN_DIR)/linux-arm/psql-lite $(BIN_DIR)/linux-arm/resetdb $(BIN_DIR)/linux-arm/runproc $(BIN_DIR)/linux-arm/sendit $(BIN_DIR)/linux-arm/sendit-server $(BIN_DIR)/linux-arm/sendit-token $(BIN_DIR)/linux-arm/simpleproxy $(BIN_DIR)/linux-arm/waitfor

$(BIN_DIR)/linux-arm/goalert-smoketest: $(GO_DEPS)
	GOOS=linux GOARCH=arm GOARM=7 go test ./smoketest -c -o $@

$(BIN_DIR)/linux-arm64/_all: $(BIN_DIR)/linux-arm64/goalert-smoketest $(BIN_DIR)/linux-arm64/goalert $(BIN_DIR)/linux-arm64/goalert-slack-email-sync $(BIN_DIR)/linux-arm64/mockslack $(BIN_DIR)/linux-arm64/pgdump-lite $(BIN_DIR)/linux-arm64/procwrap $(BIN_DIR)/linux-arm64/psql-lite $(BIN_DIR)/linux-arm64/resetdb $(BIN_DIR)/linux-arm64/runproc $(BIN_DIR)/linux-arm64/sendit $(BIN_DIR)/linux-arm64/sendit-server $(BIN_DIR)/linux-arm64/sendit-token $(BIN_DIR)/linux-arm64/simpleproxy $(BIN_DIR)/linux-arm64/waitfor

$(BIN_DIR)/linux-arm64/goalert-smoketest: $(GO_DEPS)
	GOOS=linux GOARCH=arm64 go test ./smoketest -c -o $@

$(BIN_DIR)/windows-amd64/_all: $(BIN_DIR)/windows-amd64/goalert-smoketest $(BIN_DIR)/windows-amd64/goalert.exe $(BIN_DIR)/windows-amd64/goalert-slack-email-sync.exe $(BIN_DIR)/windows-amd64/mockslack.exe $(BIN_DIR)/windows-amd64/pgdump-lite.exe $(BIN_DIR)/windows-amd64/procwrap.exe $(BIN_DIR)/windows-amd64/psql-lite.exe $(BIN_DIR)/windows-amd64/resetdb.exe $(BIN_DIR)/windows-amd64/runproc.exe $(BIN_DIR)/windows-amd64/sendit.exe $(BIN_DIR)/windows-amd64/sendit-server.exe $(BIN_DIR)/windows-amd64/sendit-token.exe $(BIN_DIR)/windows-amd64/simpleproxy.exe $(BIN_DIR)/windows-amd64/waitfor.exe

$(BIN_DIR)/windows-amd64/goalert-smoketest: $(GO_DEPS)
	GOOS=windows GOARCH=amd64 go test ./smoketest -c -o $@

$(BIN_DIR)/goalert-smoketest: $(GO_DEPS)
	go test ./smoketest -c -o $@



$(BIN_DIR)/build/goalert-darwin-amd64: $(BIN_DIR)/darwin-amd64/goalert $(BIN_DIR)/darwin-amd64/goalert-slack-email-sync
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/darwin-amd64/goalert $(BIN_DIR)/darwin-amd64/goalert-slack-email-sync $@/goalert/bin/
	touch $@

$(BIN_DIR)/goalert-darwin-amd64.tgz: $(BIN_DIR)/build/goalert-darwin-amd64
	tar -czvf $(BIN_DIR)/goalert-darwin-amd64.tgz -C $(BIN_DIR)/build/goalert-darwin-amd64/ .

$(BIN_DIR)/goalert-darwin-amd64.zip: $(BIN_DIR)/build/goalert-darwin-amd64
	rm -f $@
	cd $(BIN_DIR)/build/goalert-darwin-amd64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/goalert-linux-amd64: $(BIN_DIR)/linux-amd64/goalert $(BIN_DIR)/linux-amd64/goalert-slack-email-sync
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-amd64/goalert $(BIN_DIR)/linux-amd64/goalert-slack-email-sync $@/goalert/bin/
	touch $@

$(BIN_DIR)/goalert-linux-amd64.tgz: $(BIN_DIR)/build/goalert-linux-amd64
	tar -czvf $(BIN_DIR)/goalert-linux-amd64.tgz -C $(BIN_DIR)/build/goalert-linux-amd64/ .

$(BIN_DIR)/goalert-linux-amd64.zip: $(BIN_DIR)/build/goalert-linux-amd64
	rm -f $@
	cd $(BIN_DIR)/build/goalert-linux-amd64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/goalert-linux-arm: $(BIN_DIR)/linux-arm/goalert $(BIN_DIR)/linux-arm/goalert-slack-email-sync
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-arm/goalert $(BIN_DIR)/linux-arm/goalert-slack-email-sync $@/goalert/bin/
	touch $@

$(BIN_DIR)/goalert-linux-arm.tgz: $(BIN_DIR)/build/goalert-linux-arm
	tar -czvf $(BIN_DIR)/goalert-linux-arm.tgz -C $(BIN_DIR)/build/goalert-linux-arm/ .

$(BIN_DIR)/goalert-linux-arm.zip: $(BIN_DIR)/build/goalert-linux-arm
	rm -f $@
	cd $(BIN_DIR)/build/goalert-linux-arm && zip -r $(abspath $@) .

$(BIN_DIR)/build/goalert-linux-arm64: $(BIN_DIR)/linux-arm64/goalert $(BIN_DIR)/linux-arm64/goalert-slack-email-sync
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-arm64/goalert $(BIN_DIR)/linux-arm64/goalert-slack-email-sync $@/goalert/bin/
	touch $@

$(BIN_DIR)/goalert-linux-arm64.tgz: $(BIN_DIR)/build/goalert-linux-arm64
	tar -czvf $(BIN_DIR)/goalert-linux-arm64.tgz -C $(BIN_DIR)/build/goalert-linux-arm64/ .

$(BIN_DIR)/goalert-linux-arm64.zip: $(BIN_DIR)/build/goalert-linux-arm64
	rm -f $@
	cd $(BIN_DIR)/build/goalert-linux-arm64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/goalert-windows-amd64: $(BIN_DIR)/windows-amd64/goalert.exe $(BIN_DIR)/windows-amd64/goalert-slack-email-sync.exe
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/windows-amd64/goalert.exe $(BIN_DIR)/windows-amd64/goalert-slack-email-sync.exe $@/goalert/bin/
	touch $@

$(BIN_DIR)/goalert-windows-amd64.tgz: $(BIN_DIR)/build/goalert-windows-amd64
	tar -czvf $(BIN_DIR)/goalert-windows-amd64.tgz -C $(BIN_DIR)/build/goalert-windows-amd64/ .

$(BIN_DIR)/goalert-windows-amd64.zip: $(BIN_DIR)/build/goalert-windows-amd64
	rm -f $@
	cd $(BIN_DIR)/build/goalert-windows-amd64 && zip -r $(abspath $@) .



$(BIN_DIR)/build/integration-darwin-amd64: $(BIN_DIR)/darwin-amd64/goalert $(BIN_DIR)/darwin-amd64/mockslack $(BIN_DIR)/darwin-amd64/pgdump-lite $(BIN_DIR)/darwin-amd64/psql-lite $(BIN_DIR)/darwin-amd64/procwrap $(BIN_DIR)/darwin-amd64/simpleproxy $(BIN_DIR)/darwin-amd64/waitfor $(BIN_DIR)/build/integration
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/darwin-amd64/goalert $(BIN_DIR)/darwin-amd64/mockslack $(BIN_DIR)/darwin-amd64/pgdump-lite $(BIN_DIR)/darwin-amd64/psql-lite $(BIN_DIR)/darwin-amd64/procwrap $(BIN_DIR)/darwin-amd64/simpleproxy $(BIN_DIR)/darwin-amd64/waitfor $@/goalert/bin/
	cp -r  $(BIN_DIR)/build/integration/. $@/goalert/
	touch $@

$(BIN_DIR)/integration-darwin-amd64.tgz: $(BIN_DIR)/build/integration-darwin-amd64
	tar -czvf $(BIN_DIR)/integration-darwin-amd64.tgz -C $(BIN_DIR)/build/integration-darwin-amd64/ .

$(BIN_DIR)/integration-darwin-amd64.zip: $(BIN_DIR)/build/integration-darwin-amd64
	rm -f $@
	cd $(BIN_DIR)/build/integration-darwin-amd64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/integration-linux-amd64: $(BIN_DIR)/linux-amd64/goalert $(BIN_DIR)/linux-amd64/mockslack $(BIN_DIR)/linux-amd64/pgdump-lite $(BIN_DIR)/linux-amd64/psql-lite $(BIN_DIR)/linux-amd64/procwrap $(BIN_DIR)/linux-amd64/simpleproxy $(BIN_DIR)/linux-amd64/waitfor $(BIN_DIR)/build/integration
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-amd64/goalert $(BIN_DIR)/linux-amd64/mockslack $(BIN_DIR)/linux-amd64/pgdump-lite $(BIN_DIR)/linux-amd64/psql-lite $(BIN_DIR)/linux-amd64/procwrap $(BIN_DIR)/linux-amd64/simpleproxy $(BIN_DIR)/linux-amd64/waitfor $@/goalert/bin/
	cp -r  $(BIN_DIR)/build/integration/. $@/goalert/
	touch $@

$(BIN_DIR)/integration-linux-amd64.tgz: $(BIN_DIR)/build/integration-linux-amd64
	tar -czvf $(BIN_DIR)/integration-linux-amd64.tgz -C $(BIN_DIR)/build/integration-linux-amd64/ .

$(BIN_DIR)/integration-linux-amd64.zip: $(BIN_DIR)/build/integration-linux-amd64
	rm -f $@
	cd $(BIN_DIR)/build/integration-linux-amd64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/integration-linux-arm: $(BIN_DIR)/linux-arm/goalert $(BIN_DIR)/linux-arm/mockslack $(BIN_DIR)/linux-arm/pgdump-lite $(BIN_DIR)/linux-arm/psql-lite $(BIN_DIR)/linux-arm/procwrap $(BIN_DIR)/linux-arm/simpleproxy $(BIN_DIR)/linux-arm/waitfor $(BIN_DIR)/build/integration
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-arm/goalert $(BIN_DIR)/linux-arm/mockslack $(BIN_DIR)/linux-arm/pgdump-lite $(BIN_DIR)/linux-arm/psql-lite $(BIN_DIR)/linux-arm/procwrap $(BIN_DIR)/linux-arm/simpleproxy $(BIN_DIR)/linux-arm/waitfor $@/goalert/bin/
	cp -r  $(BIN_DIR)/build/integration/. $@/goalert/
	touch $@

$(BIN_DIR)/integration-linux-arm.tgz: $(BIN_DIR)/build/integration-linux-arm
	tar -czvf $(BIN_DIR)/integration-linux-arm.tgz -C $(BIN_DIR)/build/integration-linux-arm/ .

$(BIN_DIR)/integration-linux-arm.zip: $(BIN_DIR)/build/integration-linux-arm
	rm -f $@
	cd $(BIN_DIR)/build/integration-linux-arm && zip -r $(abspath $@) .

$(BIN_DIR)/build/integration-linux-arm64: $(BIN_DIR)/linux-arm64/goalert $(BIN_DIR)/linux-arm64/mockslack $(BIN_DIR)/linux-arm64/pgdump-lite $(BIN_DIR)/linux-arm64/psql-lite $(BIN_DIR)/linux-arm64/procwrap $(BIN_DIR)/linux-arm64/simpleproxy $(BIN_DIR)/linux-arm64/waitfor $(BIN_DIR)/build/integration
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/linux-arm64/goalert $(BIN_DIR)/linux-arm64/mockslack $(BIN_DIR)/linux-arm64/pgdump-lite $(BIN_DIR)/linux-arm64/psql-lite $(BIN_DIR)/linux-arm64/procwrap $(BIN_DIR)/linux-arm64/simpleproxy $(BIN_DIR)/linux-arm64/waitfor $@/goalert/bin/
	cp -r  $(BIN_DIR)/build/integration/. $@/goalert/
	touch $@

$(BIN_DIR)/integration-linux-arm64.tgz: $(BIN_DIR)/build/integration-linux-arm64
	tar -czvf $(BIN_DIR)/integration-linux-arm64.tgz -C $(BIN_DIR)/build/integration-linux-arm64/ .

$(BIN_DIR)/integration-linux-arm64.zip: $(BIN_DIR)/build/integration-linux-arm64
	rm -f $@
	cd $(BIN_DIR)/build/integration-linux-arm64 && zip -r $(abspath $@) .

$(BIN_DIR)/build/integration-windows-amd64: $(BIN_DIR)/windows-amd64/goalert.exe $(BIN_DIR)/windows-amd64/mockslack.exe $(BIN_DIR)/windows-amd64/pgdump-lite.exe $(BIN_DIR)/windows-amd64/psql-lite.exe $(BIN_DIR)/windows-amd64/procwrap.exe $(BIN_DIR)/windows-amd64/simpleproxy.exe $(BIN_DIR)/windows-amd64/waitfor.exe $(BIN_DIR)/build/integration
	rm -rf $@
	mkdir -p $@/goalert/bin/
	cp  $(BIN_DIR)/windows-amd64/goalert.exe $(BIN_DIR)/windows-amd64/mockslack.exe $(BIN_DIR)/windows-amd64/pgdump-lite.exe $(BIN_DIR)/windows-amd64/psql-lite.exe $(BIN_DIR)/windows-amd64/procwrap.exe $(BIN_DIR)/windows-amd64/simpleproxy.exe $(BIN_DIR)/windows-amd64/waitfor.exe $@/goalert/bin/
	cp -r  $(BIN_DIR)/build/integration/. $@/goalert/
	touch $@

$(BIN_DIR)/integration-windows-amd64.tgz: $(BIN_DIR)/build/integration-windows-amd64
	tar -czvf $(BIN_DIR)/integration-windows-amd64.tgz -C $(BIN_DIR)/build/integration-windows-amd64/ .

$(BIN_DIR)/integration-windows-amd64.zip: $(BIN_DIR)/build/integration-windows-amd64
	rm -f $@
	cd $(BIN_DIR)/build/integration-windows-amd64 && zip -r $(abspath $@) .


