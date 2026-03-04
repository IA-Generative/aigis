.PHONY: test lint build bundle

# Lancer les tests Rego
test:
	docker run openpolicyagent/opa-control-plane:edge run opa test ./policies -v

# Vérifier la syntaxe + best practices
lint:
	docker run openpolicyagent/opa-control-plane:edge run opa check ./policies
	docker run openpolicyagent/opa-control-plane:edge run opa fmt --diff ./policies

# Formater les fichiers Rego
fmt:
	docker run openpolicyagent/opa-control-plane:edge run opa fmt -w ./policies

# Packager en bundle pour le bundle-server
bundle:
	docker run openpolicyagent/opa-control-plane:edge run opa build ./policies -o ./bundles/authz.tar.gz

# Tester une décision manuellement
eval:
	docker run openpolicyagent/opa-control-plane:edge run opa eval \
	  --input example_input.json \
	  --data ./policies \
	  --format pretty \
	  "data.apisix.authz.allow"