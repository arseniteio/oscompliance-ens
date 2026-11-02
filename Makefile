MODULES := catalog agent engine

.PHONY: check test dist

check:
	@for m in $(MODULES); do \
	  echo "==> $$m"; \
	  unformatted="$$(cd $$m && gofmt -l .)"; \
	  if [ -n "$$unformatted" ]; then echo "not gofmt-ed: $$unformatted"; exit 1; fi; \
	  (cd $$m && go vet ./... && go test -count=1 ./...) || exit 1; \
	done

test:
	@for m in $(MODULES); do (cd $$m && go test -count=1 ./...) || exit 1; done

dist:
	@bash ci/package.sh $(VERSION)
