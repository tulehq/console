#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, run as the unprivileged user, and serve its pages: the
# sign-in form, the vendored htmx it was built with, and a redirect to
# sign-in for a signed-out request. It is pointed at an object store that is
# not there, so the sign-in check stops at the form; the end-to-end tests
# drive sign-in against real services.
set -eu

image=${1:?usage: run.sh IMAGE}
name=console-smoke-$$

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::9070 \
	-e TULE_Console_ObjectStoreEndpoint=http://127.0.0.1:1 \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9070/tcp | head -n 1)

form=$(curl -fsS "http://$addr/signin")
case $form in
*'name="accessKeyId"'*'name="secretAccessKey"'*) ;;
*)
	echo "the sign-in page has no key form: $form" >&2
	exit 1
	;;
esac

want=$(sed -n 's/^| SHA-256 of `htmx.min.js` | `\([0-9a-f]*\)` |$/\1/p' third_party/htmx/README.md)
got=$(curl -fsS "http://$addr/static/htmx.min.js" | sha256sum | cut -d' ' -f1)
if [ -z "$want" ] || [ "$got" != "$want" ]; then
	echo "served htmx.min.js has SHA-256 $got, want $want" >&2
	exit 1
fi

location=$(curl -sS -o /dev/null -w '%{redirect_url}' "http://$addr/s3")
case $location in
*/signin\?next=*) ;;
*)
	echo "a signed-out request is sent to $location, want sign-in" >&2
	exit 1
	;;
esac

echo "smoke test passed: $image"
