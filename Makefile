MODULES := catalog agent engine

.PHONY: check test lint dist

check:
	@for m in $(MODULES); do \
	  echo "==> $$m"; \
	  unformatted="$$(cd $$m && gofmt -l .)"; \
	  if [ -n "$$unformatted" ]; then echo "not gofmt-ed: $$unformatted"; exit 1; fi; \
	  (cd $$m && go vet ./... && golangci-lint run -c ../.golangci.yml ./... && go test -count=1 ./...) || exit 1; \
	done
	@for t in tests/scripts/*.test.sh; do echo "==> $$t"; bash $$t || exit 1; done

test:
	@for m in $(MODULES); do (cd $$m && go test -count=1 ./...) || exit 1; done

lint:
	@for m in $(MODULES); do (cd $$m && golangci-lint run -c ../.golangci.yml ./...) || exit 1; done

dist:
	@bash ci/package.sh $(VERSION)
