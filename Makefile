VIRTUAL_ENV_LOCATION := ./al_aws_access_analyzer_collector_integration_tests_virtualenv
VIRTUAL_ENV_ACTIVATE_CMD := $(VIRTUAL_ENV_LOCATION)/bin/activate

BUILD_DIRECTORY := build
CFT_DIRECTORY := cloudformation
CFT_TEMPLATE := al-aws-access-analyzer-collector.yaml

PUBLIC_REPO_BUCKET := alertlogic-public-repo.us-east-1
LAMBDA_PACKAGES_PREFIX := lambda_packages/

PACKAGE_NAME := $(shell python setup.py --fullname).zip
PACKAGE_PLACEHOLDER_STRING := PACKAGE_PLACEHOLDER

.PHONY: upload dist init
.DEFAULT_GOAL := dist

$(BUILD_DIRECTORY)/$(CFT_DIRECTORY):
	@mkdir -p $(BUILD_DIRECTORY)/$(CFT_DIRECTORY)

init:
	pip install -r requirements.txt

test:
	python -m unittest discover -p '*_tests.py' -v -b

lint:
	pycodestyle .

dist:
	python setup.py ldist --include-version=True

update_cft: | $(BUILD_DIRECTORY)/$(CFT_DIRECTORY)
	@cp $(CFT_DIRECTORY)/$(CFT_TEMPLATE) $(BUILD_DIRECTORY)/$(CFT_DIRECTORY)/$(CFT_TEMPLATE)
	@sed -i '.bak' 's/$(PACKAGE_PLACEHOLDER_STRING)/$(PACKAGE_NAME)/g' $(BUILD_DIRECTORY)/$(CFT_DIRECTORY)/$(CFT_TEMPLATE)

upload: update_cft dist
	python setup.py lupload --s3-bucket=$(PUBLIC_REPO_BUCKET) --s3-prefix=$(LAMBDA_PACKAGES_PREFIX)
	@aws s3 cp $(BUILD_DIRECTORY)/$(CFT_DIRECTORY)/$(CFT_TEMPLATE) s3://$(PUBLIC_REPO_BUCKET)/templates/$(CFT_TEMPLATE)

virtualenv:
	pip install virtualenv; virtualenv $(VIRTUAL_ENV_LOCATION)

virtual_uninstall:
	rm -rf $(VIRTUAL_ENV_LOCATION)
