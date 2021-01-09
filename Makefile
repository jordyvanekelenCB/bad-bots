SHELL := /bin/bash

BASE := $(shell /bin/pwd)
BUILDDIR := $(BASE)/build
SRCDIR := $(BASE)/LambdaCode
VENVDIR := $(BASE)/.venv

# PIPENV_NOSPIN=1 is added for the following reason:
# https://github.com/pypa/pipenv/issues/3239
pipenv := env PIPENV_NOSPIN=1 PIPENV_VENV_IN_PROJECT=true pipenv

.PHONY: build

pipenv_sync_dev:
	$(pipenv) sync --dev

pull_request: pipenv_sync_dev test

pre_package: build

post_package:

pre_deploy:

post_deploy:

build:
	mkdir -p $(BUILDDIR)
	$(pipenv) lock -r > $(BUILDDIR)/requirements.txt
	cp -R $(SRCDIR)/* $(BUILDDIR)
	$(pipenv) run pip install --isolated --disable-pip-version-check -r $(BUILDDIR)/requirements.txt -t $(BUILDDIR) -U

clean:
	rm -rf $(BUILDDIR)
	rm -rf $(VENVDIR)

test: pipenv_sync_dev
	$(pipenv) run pytest -v || true