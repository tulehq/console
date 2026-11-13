# console

A web console for [Tule](https://github.com/tulehq): browse every running
Tule service and do the everyday actions from one place. It is not an AWS
API and has no data of its own; it is a client of the other services,
calling each one's real API with the aws-sdk-go-v2 clients (and the signed
retrieval and inspection APIs of mailbox, queues and functions), signed with
the key you sign in with.

Each service it is pointed at gets a section: object-store's buckets,
secret-store's secrets, accounts' organization, identity's users and keys,
mailbox's messages and identities, queues' queues and functions' functions,
each bucket, secret, queue, function and email identity with its
resource-based policy. A console beside a lone object-store shows only
buckets.

## Running it

With Docker, pointed at services on the host:

```sh
docker run --rm -p 9070:9070 \
  -e TULE_Console_ObjectStoreEndpoint=http://host.docker.internal:9000 \
  -e TULE_Console_MailboxEndpoint=http://host.docker.internal:9040 \
  ghcr.io/tulehq/console:0.3.1
```

Then open <http://localhost:9070> and sign in. The image is based on Alpine
and runs as the unprivileged `nonroot` user. It holds no data and has no
volume, and its Docker health check polls `/_ready`.

From source (Go 1.27.4 or later):

```sh
make build
TULE_Console_ObjectStoreEndpoint=http://localhost:9000 ./build/tule-console
```

It listens on port 9070, after object-store's 9000, secret-store's 9010,
accounts' 9020, identity's 9030, mailbox's 9040, queues' 9050 and functions'
9060, so they can all run at once.

### Every service together, in Docker Compose

[`compose.yaml`](compose.yaml) runs every service and the console, wired
together: one root key everywhere, every service pointed at identity so the
keys identity issues work on all of them, and the console pointed at each.

```sh
docker compose up -d
DOCKER_GID=$(stat -c %g /var/run/docker.sock) docker compose --profile functions up -d
```

functions is behind the `functions` profile, since it runs function
containers through the Docker daemon and needs its socket and the socket's
group (`stat -f %g` on macOS); without it, the Functions section shows the
service as unreachable. The file in full:

```yaml
x-root-key: &root-key
  # The AWS documentation's example key; identity holds access key IDs to at
  # least 16 characters. Use your own outside a local machine.
  TULE_Auth_AccessKeyID: AKIAIOSFODNN7EXAMPLE
  TULE_Auth_SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

x-identity: &identity-endpoint
  TULE_Auth_IdentityEndpoint: http://identity:9030

services:
  identity:
    image: ghcr.io/tulehq/identity:0.5.0
    environment:
      <<: *root-key
      TULE_Identity_AccountsEndpoint: http://accounts:9020
    ports: ["9030:9030"]
    volumes: [identitydata:/data]

  accounts:
    image: ghcr.io/tulehq/accounts:0.5.0
    environment:
      <<: [*root-key, *identity-endpoint]
    ports: ["9020:9020"]
    volumes: [accountsdata:/data]

  object-store:
    image: ghcr.io/tulehq/object-store:0.8.0
    environment:
      <<: [*root-key, *identity-endpoint]
    ports: ["9000:9000"]
    volumes: [objectdata:/data]

  secret-store:
    image: ghcr.io/tulehq/secret-store:0.5.0
    environment:
      <<: [*root-key, *identity-endpoint]
    ports: ["9010:9010"]
    volumes: [secretdata:/data]

  mailbox:
    image: ghcr.io/tulehq/mailbox:0.4.0
    environment:
      <<: [*root-key, *identity-endpoint]
    ports: ["9040:9040"]
    volumes: [maildata:/data]

  queues:
    image: ghcr.io/tulehq/queues:0.4.0
    environment:
      <<: [*root-key, *identity-endpoint]
      # Queue URLs name the host clients on this machine reach queues at.
      TULE_Queues_BaseURL: http://localhost:9050
    ports: ["9050:9050"]
    volumes: [queuesdata:/data]

  functions:
    image: ghcr.io/tulehq/functions:0.4.0
    profiles: [functions]
    depends_on:
      queues: {condition: service_healthy}
    environment:
      <<: [*root-key, *identity-endpoint]
      TULE_Functions_QueuesEndpoint: http://queues:9050
    # The function containers reach the Runtime API as
    # host.docker.internal:9061, so it is published on the same port.
    ports: ["9060:9060", "9061:9061"]
    volumes:
      - functionsdata:/data
      - /var/run/docker.sock:/var/run/docker.sock
    # The group that owns the socket on the Docker host, from DOCKER_GID as
    # above. Unset, it is 0, the root group.
    group_add: ["${DOCKER_GID:-0}"]

  console:
    image: ghcr.io/tulehq/console:0.3.1
    depends_on:
      identity: {condition: service_healthy}
      accounts: {condition: service_healthy}
      object-store: {condition: service_healthy}
      secret-store: {condition: service_healthy}
      mailbox: {condition: service_healthy}
      queues: {condition: service_healthy}
    environment:
      TULE_Console_IdentityEndpoint: http://identity:9030
      TULE_Console_AccountsEndpoint: http://accounts:9020
      TULE_Console_ObjectStoreEndpoint: http://object-store:9000
      TULE_Console_SecretStoreEndpoint: http://secret-store:9010
      TULE_Console_MailboxEndpoint: http://mailbox:9040
      TULE_Console_QueuesEndpoint: http://queues:9050
      TULE_Console_FunctionsEndpoint: http://functions:9060
    ports: ["9070:9070"]

volumes:
  identitydata:
  accountsdata:
  objectdata:
  secretdata:
  maildata:
  queuesdata:
  functionsdata:
```

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Console_ObjectStoreEndpoint` | unset | object-store's base URL, such as `http://localhost:9000`; set, the console has an Object store section |
| `TULE_Console_SecretStoreEndpoint` | unset | secret-store's base URL; the Secret store section |
| `TULE_Console_AccountsEndpoint` | unset | accounts' base URL; the Accounts section |
| `TULE_Console_IdentityEndpoint` | unset | identity's base URL; the Identity section, and the service sign-in asks |
| `TULE_Console_MailboxEndpoint` | unset | mailbox's base URL; the Mailbox section |
| `TULE_Console_QueuesEndpoint` | unset | queues' base URL; the Queues section |
| `TULE_Console_FunctionsEndpoint` | unset | functions' base URL; the Functions section |
| `TULE_Console_Region` | `us-east-1` | The region the console signs its calls for |
| `TULE_Console_SessionTTL` | `12h` | How long a session lasts from sign-in |
| `TULE_Console_SecureCookie` | `false` | Mark the session cookie `Secure` even on a plain-HTTP connection, for a console behind a TLS-terminating proxy. It is marked `Secure` on a TLS connection anyway |
| `TULE_Console_MaxSessions` | `10000` | The most sessions the console holds; at it, sign-in is refused until sessions end or expire |
| `TULE_Console_MaxSessionsPerKey` | `10` | The most sessions of one access key; a new one past it ends that key's oldest |
| `TULE_Console_TrustedProxies` | unset | Comma-separated CIDR prefixes (or addresses) of the proxies in front of the console, whose `X-Forwarded-For` the sign-in limiter reads. Unset, it is never read |
| `TULE_Server_Port` | `9070` | Listen port |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `5m` | How long the server may take to read a request, body included; an upload streams through it |
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `5m` | How long it may take to write a response; a download streams through it |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_UI_Reload` | `false` | Build the templates on every page, as gas/ui's `ui.reload` |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

At least one endpoint must be set; the console refuses to start without one.
Each is an absolute `http` or `https` URL. The console calls the services
server-side only, so an endpoint is the address the console reaches the
service at, such as `http://queues:9050` in Compose, not one the browser
needs to reach.

Logs go to the console only. They never hold a key: requests are logged by
method, path, status and time, never their query, form or cookie.

## Signing in

The sign-in page takes an access key ID, its secret, and, for a role
session, its session token. Every key a service accepts works: the root key
the services are configured with, a key identity issued to a user, and a
role session's key and token from identity's `AssumeRole`.

The console checks the key by making a signed call with it: identity's
`GetCallerIdentity` when identity is configured, which every principal may
call whatever its policies and which also names who signed in (shown at the
top of every page), and otherwise the cheapest read of the first configured
service, in the order of the configuration table (`ListBuckets`,
`ListSecrets`, `DescribeOrganization`, `GetAccount`, `ListQueues`,
`ListFunctions`). A key the service answers `401` or `403` to is refused; a
service that cannot be reached is reported as such, and the key is not
taken. Without identity, a read the service denies by policy, an
`AccessDenied` or `AccessDeniedException` in IAM's form ("User: \<arn\> is
not authorized to perform: ..."), still takes the key and names its
principal: the services answer it only past the signature check. So a key
with no policies signs in either way, and is shown what it is denied.

On success the key is held server-side, in a session in memory. The
browser gets an opaque cookie, `tule_console_session`: a random session ID
and an HMAC of it under a key made at start, `HttpOnly`, `SameSite=Strict`,
for the whole site, and `Secure` over TLS or with
`TULE_Console_SecureCookie`. The key never reaches the browser after
sign-in; pages show the principal's ARN, or the last four characters of an
AWS-length key ID when the console could not ask identity. Signing out, or
the session's `TULE_Console_SessionTTL` passing, drops the key.

**Sessions live in memory.** A restart, which also makes a new cookie key,
signs everyone out. Sessions are not shared between two consoles.

Every request but sign-in, the static files, the probes, `/favicon.ico`
(always `404`; pages declare no icon) and `/robots.txt` (which disallows
everything) needs a session. A signed-out page the browser opens is sent to
sign-in, and comes back to it after; an HTMX request is told to go there;
anything else, a form post, an asset or a background fetch, gets `401`
without a redirect, so it never loads the sign-in page behind an open form.
The sign-in form's token lasts an hour and is kept while it does: opening
the sign-in page again, in a tab or by a background request, leaves an
open form's token good. Signing in again from a signed-in browser ends its old session.
A key holds at most `TULE_Console_MaxSessionsPerKey` sessions, its oldest
ending when it signs in past that, and the console at most
`TULE_Console_MaxSessions`, past which sign-in is refused with a message
saying so: refusing keeps one key's sign-ins from ending everyone else's
sessions.

Signing in is limited per client: ten failed attempts, then one more every
six seconds; successful sign-ins do not count. A client is an IPv4
address, or an IPv6 address's /64. **With no trusted proxies, the client is
the connection's peer address**, so behind a proxy, or Docker Desktop's
port forwarding, every client shares the proxy's limit: set
`TULE_Console_TrustedProxies` to the proxy's addresses, and the client is
the rightmost `X-Forwarded-For` hop that is not one of them. The limiter
remembers the 100,000 clients seen last.

When the service that checks the key cannot be reached or fails, the
sign-in page says which service, and the console's log has the detail;
signed-in error pages show the service's own message.

## Sections

Every page has a stable URL. Pages work without JavaScript; with it, htmx
adds search as you type and in-place answers for revealing a secret and
invoking a function. Each page shows when its service is not ready (its
`/_ready`, probed at most every five seconds) or does not answer, and a
call that fails shows the service's error code and message on the section's
error page instead of a broken one.

Actions are plain form posts that come back to the page with a message of
what happened, or what the service answered when it did not. Deleting asks
first, with JavaScript on.

### Permissions

Every service evaluates identity's policies for the keys identity issued,
with the resource-based policy of what the request acts on where the
service has one ([Resource policies](#resource-policies)); the root key is
always allowed. A principal of another account, such as a member account's
role session, is allowed only what a resource policy shares with it besides
its own identity policies; accounts lets it call only
`DescribeOrganization`, as a member of the organization.
The console asks for nothing beyond what each page needs and shows what the
service answers: a page the signed-in principal may not read shows that
service's `AccessDenied` (or `AccessDeniedException`) and its message, with
the service's status, `403`, or `400` for secret-store and accounts, as
Secrets Manager and Organizations answer it. An htmx answer, such as a
search, a reveal or an invocation filter, is the refusal alone, swapped
where the answer was to go: the layout's htmx configuration swaps `4xx` and
`5xx` answers too. An action that is denied comes back to its page with the
message.

The pages that read a service's inspection API rather than its AWS API need
Tule's own action `tule:Inspect` on `arn:aws:<service>:<region>:<account>:*`
besides: mailbox's messages and rendering failures (`ses`), queues' list and
queue pages (`sqs`), and functions' invocations and each function's last
invocations (`lambda`). A policy such as `{"Effect": "Allow", "Action":
["sqs:*", "tule:Inspect"], "Resource": "*"}` grants a section and its
inspection pages. A function's page without `tule:Inspect` shows its
configuration and says why its invocations are missing.

### Resource policies

A bucket's, secret's, queue's and function's page has a Policy section, and
an email identity's page its sending authorization policies. The section
shows the policy as the service's own read returns it, as JSON, indented, in
a textarea to edit and save with the service's own operation, and a delete;
a resource without one has an empty form with an example naming the
resource. Saving sends the document as it was typed. A document the service
refuses (object-store's `MalformedPolicy`, secret-store's
`MalformedPolicyDocumentException` or `PublicPolicyException`, queues'
`InvalidAttributeValue`, functions' `InvalidParameterValueException`,
mailbox's `BadRequestException`, or any other error) is shown next to the
form with the service's code and message, and the page keeps the document as
it was sent, so nothing is lost.

With an identity endpoint, each service binds the IAM user and role ARNs in
a policy's `Principal` and `NotPrincipal` to the principals' unique IDs when
it stores the policy, as AWS does, and its read shows each one as the
principal's current ARN while that user or role exists, and as its unique
ID (`AIDA...` for a user, `AROA...` for a role) once it is deleted, even
when a user or role of the same name exists again. The section shows the
document so, and saving it again keeps the ID, which still names the
deleted principal and no other. A save naming a user or role ARN that no
principal has is refused, its code above and the service's message shown
next to the form. Account IDs, root ARNs, `*`, role session ARNs, service
principals and ARNs in conditions are kept as written.

A save or delete never loses a change made since the page was read. Each
form sends back the version of the policy the page read (a SHA-256 of the
document as the service's read returns it, empty for none), and the console
reads the policy again before it writes: one that changed, whether another
client replaced it, added a statement with `AddPermission` or deleted it,
refuses the change with `409`, "The policy changed since the page was
loaded", next to the form, which keeps the document as sent and shows the
stored one below it. Saving again from that answer replaces the policy as it
is now. A function's policy is guarded by its `RevisionId` instead, and by
this check when the page read none. A user or role a policy names that is
deleted after the page was read is such a change for a bucket, a secret, a
queue and an email identity, since the service's read then shows its unique
ID where the page read its ARN: the save is refused with `409`, the unique
ID in the stored policy shown below the form. Deleting a principal does not
change a function's `RevisionId`, so a function's save from that page goes
through and stores the document as sent; one that still names the deleted
ARN is refused by functions as naming no principal. The check and the write
are two calls, so a change in between is not caught; creating a named
sending authorization policy is not checked, as mailbox refuses a name the
identity has. Removing one statement by its `Sid` loses nothing else and is
not checked.

A policy the signed-in principal may not read, such as without
`s3:GetBucketPolicy`, shows the service's `AccessDenied` (or
`AccessDeniedException`) in the section's place, and the rest of the page is
shown; a save or delete it may not make is shown next to the form the same
way, with the service's status. Since a save reads the policy first, a
principal that may change a policy but not read it is refused that read.
When a refused save's page cannot read the policy again, the section says
whether one is stored is unknown, rather than showing none; when the page
itself cannot be shown again, the refusal and the page's failure are both
shown.

| Page | Read | Save | Delete | Also |
|---|---|---|---|---|
| Bucket, at its root | `GetBucketPolicy` | `PutBucketPolicy` | `DeleteBucketPolicy` | |
| Secret | `GetResourcePolicy` | `PutResourcePolicy` | `DeleteResourcePolicy` | "Validate", `ValidateResourcePolicy`: its findings, nothing stored; the `BlockPublicPolicy` box, checked to begin with |
| Queue | `GetQueueAttributes` `Policy` | `SetQueueAttributes` `Policy` | `SetQueueAttributes` with an empty `Policy` | Each statement listed, one with a `Sid` removed with `RemovePermission` by that label |
| Function | `GetPolicy` | `PutResourcePolicy` | `DeleteResourcePolicy` | Each statement listed, one removed with `RemovePermission` by its `StatementId`; every change sends the `RevisionId` the page was read with, so a policy changed since is refused with `PreconditionFailedException` rather than overwritten. The `ResourceArn` is the function's, from `GetFunction`, never the form's |
| Email identity | `GetEmailIdentityPolicies` | `CreateEmailIdentityPolicy` for a new name, `UpdateEmailIdentityPolicy` for one it has | `DeleteEmailIdentityPolicy` | Every named policy in a form of its own, and a form to add one by name |

Each statement is listed with its `Sid`, effect, principal, action,
resource and condition. Statements are added through the document; the console has no form for
`AddPermission`, though it lists and removes the statements it writes. A
secret scheduled for deletion has no Policy section, as secret-store
answers it nothing until it is restored.

### Object store

`/s3`: the buckets; create a bucket. A bucket's page browses it by prefix,
with folders for the common prefixes and 200 entries a page; select objects
to delete them; delete the bucket, which object-store refuses unless it is
empty. Upload a file into the current prefix, under its own name or a key
you give, with the file's content type or one you give: the upload streams
through the console in 8 MiB parts (one `PutObject`, or a multipart upload
beyond 8 MiB), so the console never holds a whole file, and a session runs
at most two uploads at once. An object's page has
its size, ETag, type, headers and user metadata, and a download that
streams it through the console.

### Secret store

`/secrets`: every secret, scheduled deletions included, searched by words
of its name and description (secret-store filters nothing, so the console
reads up to 5000 secrets and filters them); create a secret. A secret's page
has its metadata, tags and versions with their staging labels. No value is
read until you reveal it: the current one, or any version's. Put a new
value (it becomes `AWSCURRENT`), delete with a recovery window of 7 to 30
days or at once without recovery, and restore a secret scheduled for
deletion.

### Accounts

`/accounts`: the organization and its tree of the root, organizational
units and accounts, with each account's email and state; create the
organization when there is none; create an account (it joins the root) or
an organizational unit under any root or unit. An account's page has its
details, parent and tags.

### Identity

`/iam`: the IAM users, 50 a page, with each one's access keys, their
status, creation and last use; create a user. A user's page has its keys
and tags: create a key, whose secret is shown on that one answer only (as
AWS does; the page is not cached and htmx keeps it out of history),
activate, deactivate and delete keys, and delete the IAM user, which identity
refuses while it has keys or policies.

A user's page also has its policies. Its inline policies each open on a
page of their own with the document, decoded and indented, in a textarea to
edit and save (`PutUserPolicy`), and a delete; "Add inline policy" opens the
same form empty, and refuses a name the user's inline policies already have
rather than replace that policy, as `PutUserPolicy` would. Its attached
managed policies can be detached, and any of the account's or AWS's managed
policies attached from a list (`ListPolicies`, up to 1000), or by ARN when
the list cannot be read or is cut at 1000.

`/iam/roles`: the roles, 50 a page. Create a role with its name, path,
description, maximum session duration and trust policy, which starts as
trusting the signed-in account. A role's page has its details, its trust
policy, and its inline and attached policies, changed as a user's are;
delete it, which identity refuses while it has policies.

`/iam/policies`: the managed policies, AWS's and the account's, 50 a page,
with their attachment counts. Create a customer managed policy with its
name, path, description and document. A policy's page has its details and
its default version's document; delete it, which identity refuses while it
is attached or has other versions. AWS's policies cannot be deleted, and
the page offers no delete for them.

A document identity refuses, `MalformedPolicyDocument` or any other
validation error, is shown next to its form, with the service's code and
message and the document as it was typed, so nothing is lost. A list on a
user's or role's page the principal may not read says so in its place, and
the rest of the page is shown. The section shows what identity allows the
signed-in principal: a user without IAM permissions sees identity's
`AccessDenied`.

### Mailbox

`/mail/identities`: the email identities, with their type, verification and
whether sending is enabled. An identity's page has its details and its
sending authorization policies ([Resource policies](#resource-policies)).

`/mail`: the messages, newest first, with every filter mailbox's retrieval
API has (from, to, subject, full-text search, since and until, read in
UTC, configuration set, tags as `name:value` separated by commas, and
MessageId), 50 a page; delete every message. A message's page has its
recipients, tags, the text part, the HTML part in a preview frame, every
header, its attachments to download, and its raw MIME to read or save as
`.eml`; delete it. `/mail/failures` lists the rendering failures, filtered
by template, MessageId and time.

### Queues

`/sqs`: the queues with their visible, in-flight and delayed counts;
create a standard or FIFO queue (`.fifo` is added to a FIFO queue's name),
with content-based deduplication. A queue's page has its attributes and its
messages through queues' inspection API, which does not change them,
filtered by state and message group; send a message with a body,
`Name=Value` String attributes, and a delay, or a group and deduplication
ID on a FIFO queue; purge the queue; delete it.

### Functions

`/lambda`: the functions with their state, package type, memory and
timeout. A function's page has its configuration and environment, its
event source mappings, its last invocations, and invoke: a JSON payload
runs it synchronously, and the page shows its status, result and the tail
of its log. `/lambda/invocations` is functions' invocation history,
filtered by function, status, source and time, and each invocation's page
has its payload, result and whole log. `/lambda/mappings` lists every event
source mapping, each enabled or disabled from there.

## Security

- **Escaping.** Every page is an `html/template` page through gas/ui, and
  no template function returns a trusted type, so every name, key, subject,
  body, header and value a service answers is escaped for where it lands.
  The tests render hostile names, keys, subjects and bodies in every section
  and check the parsed page runs nothing.
- **Mail HTML** is the only HTML of a service the console shows, and only
  in an `<iframe sandbox="">` (no scripts, no same origin, no forms, no
  popups), served from its own URL with
  `Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox`,
  so it loads nothing, images and styles included, and runs sandboxed even
  when opened outside the frame. It is served with `Referrer-Policy:
  no-referrer`.
- **Downloads** (objects, attachments, saved `.eml`) are
  `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and
  under the same `default-src 'none'; sandbox` policy, so no object renders
  on the console's origin whatever its type. A raw message to read is
  `text/plain` under that policy.
- **Pages** carry `Content-Security-Policy: default-src 'self';
  script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src
  'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none';
  object-src 'none'`: no inline script or style, and no page of the console
  in another site's frame. htmx runs with `allowEval`, `allowScriptTags`,
  its inline indicator styles and its history cache off, so a revealed
  value or a new key's secret is not kept in the browser's storage.
- **CSRF.** Every state-changing request is a POST and needs the session's
  CSRF token, in the `_csrf` form field (the first field of an upload) or
  the `X-CSRF-Token` header htmx sends, beside Gas's cross-origin
  protection, which refuses a cross-site browser request outright. The
  sign-in form has a token of its own in a cookie for the sign-in path.
- **Static files** are embedded in the binary: one stylesheet, a small
  script, and htmx 2.0.11 from its npm package, unmodified, with its
  license and checksums in [third_party/htmx](third_party/htmx). Nothing is
  loaded from a CDN.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
session. They respond `200` when every part of the console reports healthy
or ready and `503` otherwise, with a JSON object of each one's status.
Readiness does not depend on the services the console shows; each section
shows its service's own readiness.

## Limits

- Sessions are in memory, as above.
- The Functions section's end-to-end tests run against a functions
  checkout and a Docker daemon when both are there, and are skipped
  otherwise.
- Out of scope: policy versions beyond the default's document, editing a
  role's trust policy after it is created, creating and deleting email
  identities, a form for `AddPermission`, groups, permissions boundaries
  and the rest of IAM beyond users, roles, keys and policies, the rarely
  used operations of each API, and views across accounts beyond what the
  signed-in principal's calls return.

## Development

```sh
make test       # unit tests
make test-e2e   # end-to-end tests against the real services
make lint
make image      # build ghcr.io/tulehq/console:dev
make smoke      # build the image, run it, and check it serves its pages
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

The unit tests run the console in-process over a real listener with each
service replaced by a fake, and drive it over HTTP, parsing its pages with
`golang.org/x/net/html` and following htmx requests by their headers. No
browser is involved.

The end-to-end tests build object-store, secret-store, accounts, identity,
mailbox and queues from their checkouts and run them as processes, all with
one root key and all pointed at that identity, and run the console against
them. They sign in with the root key, with keys identity issued, and with
role sessions, drive each section's pages and actions, and check each effect
with the service's own SDK. A user with no policies is shown each service's
`AccessDenied`; one allowed only `s3:ListAllMyBuckets` sees the buckets and
is denied everything else; one allowed the AWS APIs of mailbox, queues and
functions is denied their inspection pages until it is allowed
`tule:Inspect`; a second console pointed at object-store alone, without
identity, refuses a wrong secret and signs in a key with no policies; the
root key sees every page; and a managed policy and a role created through
the console, the one attached to the other, give the role's sessions what
the policy allows. Each Policy section sets, reads and deletes a policy of a
bucket, a secret, a queue, a function and an email identity, checked with
the SDK, is shown the service's error for a malformed document next to its
form, and lists and removes a statement `AddPermission` wrote; and a user
allowed each resource's page but no policy action sees the page with the
service's `AccessDenied` in its Policy section, for reading the policy and
for saving one, and one allowed to read the policies but not change them is
refused each save; and a save from a page read before the SDK changed the
policy is refused, the change kept; and a policy of each resource naming a
user that is then deleted shows that IAM user's unique ID, is saved again
from the page with it, and a save naming the deleted user's ARN is refused
next to the form, and a save from a page read before that user was deleted
is refused as a change made since, but for a function's, which goes through.
They also check that the console's log, captured at trace level, holds none
of the secrets they handled. Each checkout is the console's sibling,
`../<service>`, by default, or the directory `TULE_E2E_<SERVICE>_DIR` names
(`TULE_E2E_OBJECT_STORE_DIR` and so on); CI checks out each at its latest
release and sets them. Without a checkout the tests fail rather than being
skipped. functions is the exception, as under Limits: with `../functions` or
`TULE_E2E_FUNCTIONS_DIR` and a Docker daemon, the tests build a Go function
from `test/e2e/testdata` into an image `FROM scratch` (nothing is pulled)
and drive functions through the console too, the function running with an
execution role the tests create in identity.

## License

[MIT](LICENSE)
