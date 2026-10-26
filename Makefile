# -count=1: the Go test cache does not see changes to the schema files.

MODULES := catalog agent engine

.PHONY: check test

check:  ## gofmt, go vet and go test on every module
	@for m in $(MODULES); do \
	  echo "==> $$m"; \
	  unformatted="$$(cd $$m && gofmt -l .)"; \
	  if [ -n "$$unformatted" ]; then echo "not gofmt-ed: $$unformatted"; exit 1; fi; \
	  (cd $$m && go vet ./... && go test -count=1 ./...) || exit 1; \
	done

test:   ## go test on every module
	@for m in $(MODULES); do (cd $$m && go test -count=1 ./...) || exit 1; done
