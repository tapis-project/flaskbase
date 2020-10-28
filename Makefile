

build.api:
	docker build -t tapis/flaskbase .

build.test:
	docker build -f Dockerfile-tests -t tapis/flaskbase-tests .

build: build.api build.test

test: build
	docker run -it --rm tapis/flaskbase-tests
