# Email ingestion: out-of-band and read-only

How the agent gets access to a real mailbox for triage without being able to send, delete or
leak anything, on the assumption that it can be manipulated by the mail it reads.

## The architectural decision

A trusted non-agent process holds the mail credential and makes all the network calls. The
agent reads only the files that process writes.

The reason is that a mail tool held by the agent is a tool an attacker can reach by sending an
email, given that the agent is assumed to be injectable by the mail it reads. So ingestion runs
in one direction:

```
  trusted NON-agent fetcher            agent (air-gapped from the mailbox)
  ------------------------             ---------------------------------
  holds the read-only credential
  makes the only network calls
  writes inert JSON records  ------->  reads inbox/*.json with a memory-only toolset
                                       no network tool, no send tool, no credential
                                       writes triage + draft text back into the record
                                            |
                                            v
                                       human reviews on the dashboard
                                            |
                                            v
                                       separate trusted sender (not built here)
```

The agent never holds the credential, never makes a network call, and has no tool that could
act on an instruction embedded in a message. An injection that persuades the model still has
nothing available to carry it out.

## Credential design

- **Gmail API with a read-only OAuth scope (`gmail.readonly`)**, chosen over IMAP with an app
  password because it supports a real read-only scope. IMAP app passwords grant read and send
  together with no read-only option, so they cannot express the constraint this design needs.
- **A dedicated OAuth client**, separate from any other client on the account, so the agent's
  access can be revoked on its own.
- **The consent screen stays in testing mode** with the owner as the only test user. There is
  no third party to publish for, and this avoids restricted-scope verification.
- **Tokens are minted interactively.** `gmail_auth.py` runs a stdlib loopback and PKCE flow and
  refuses to save a token carrying any scope broader than read-only, in case the consent screen
  returns more than was requested.
- **Credentials live outside the repo and outside the agent's reach**, with the directory at
  `700` and files at `600`.
- `gmail_fetch.py` **re-checks the read-only scope at startup** and exits if the token carries
  anything else. This is a second, independent check, since a mutating credential in this system
  would be difficult to contain.

## The fetcher

`scripts/gmail_fetch.py` is a trusted, non-agent process. Each of its invariants is enforced in
code rather than assumed from the OAuth scope:

- **Read-only:** HTTP GET only, and it refuses to run unless the token's scope is exactly
  `gmail.readonly`.
- **Least data:** headers plus a truncated plaintext body. Attachments are never downloaded.
- **Audited:** every run logs one `email.read` event to Tier A with the host and credential id.
  The fetcher logs its own actions, since the harness does not log them for it.
- **Idempotent:** a message already present in `inbox/` is skipped, so a doubled or missed
  scheduled run has no effect.
- **Stdlib only:** the Gmail API is plain REST and JSON, so token refresh, list and get are a
  handful of `urllib` calls. This avoids the official client library, which matters on a host
  where pip cannot reach the network, and keeps both the dependency and egress surface small.
- **Testable without credentials:** `--self-test` exercises MIME parsing and the record writer
  against a synthetic payload, with no token and no network.

### Scoping the egress hole

The fetcher needs to reach the mail API, which a default-deny egress policy blocks. Opening
that without opening everything else took a few attempts:

- A hostname-based firewall rule does not work under a mesh DNS resolver. The resolver answers
  the lookup, so the firewall never sees the A-record it would need to map the API's rotating
  IPs to a hostname, and the rule matches nothing.
- A broad allow on the system Python re-opens external egress for every script sharing that
  interpreter, including the parts that are supposed to stay restricted.

The fix is process isolation: give the fetcher its own Python interpreter, used for nothing
else. Application firewalls key their rules on the real binary, so a dedicated interpreter is a
distinct identity that can hold a network allow while every other interpreter on the host stays
restricted to loopback. Even a broad allow on that binary covers exactly one program.

The cloud-escalation path uses the same pattern: a rule that cannot be scoped by destination
can be scoped by process instead.

Two things to know before writing firewall rules:

- Rules key on the real binary, not the path you invoked. A platform's `python3` may be a
  re-exec stub pointing at a framework binary elsewhere, and a rule written against the stub
  matches nothing.
- A default "allow signed OS programs" setting permits the OS network utilities, which can be
  used to move data out. Explicit per-binary block rules override the default. Check for this
  rather than assuming.

## Triage

The scheduler feeds `inbox/` records to the agent with a memory-only toolset: no network, no
send, no file tools. The agent classifies, summarizes, and may write draft reply text back into
the record, where it sits as inert text on disk.

The triage prompt marks the message body as data rather than instructions, and asks the model
to flag anything that reads as an instruction aimed at it.

That flag is a note for the human digest. Nothing gates on it, since a model that can be talked
into complying can also be talked out of flagging. The containment comes from the absent tool.

## Record lifecycle

```
  new --(scheduler triage, memory-only toolset)--> triaged --(human-approved action)--> actioned
                                                       |
                                                       +-- triage-failed (step error/timeout)
```

Schema and field reference: [`inbox/README.md`](../inbox/README.md).

## The send gate (design, not implemented here)

Sending is the first write capability in the system, so it is built last and separately:

1. The agent drafts. It has no send tool and no credential, so this is all it can do.
2. The draft appears on the dashboard for review, with a push notification, the subject and the
   body. There is no send control in the agent's path.
3. An explicit human approval releases that one draft.
4. A separate trusted process, holding a separate narrow send credential the agent cannot read,
   performs the send and logs it as a Tier B event.

The gate is structural at each step, and the agent is not in the send path at all.

## Operational notes

- Start narrow. Run the first fetch with a tight query and a small `--max` to check the
  pipeline before pulling in bulk.
- `--max` caps the number of NEW records ingested per run, not the listing. The fetcher pages
  the full query window, skips what is already on disk, and takes the OLDEST pending messages
  first, so a backlog drains across successive runs. This ordering is a security property, not
  just tidiness: capping the listing instead would let anyone able to send mail push an older
  message below the cut, where it would age out of the window without ever being ingested. A
  run that leaves messages queued reports the count on stderr, and
  `tests/test_fetch_backlog.py` covers the case offline.
- Re-run the egress negative test after opening the mail allow, and confirm two things: that
  only the mail API opened, and that the agent's own interpreter is still loopback-only.
