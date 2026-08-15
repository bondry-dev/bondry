# Webhook egress

Bondry webhook routes bind a declared JSON payload to a fixed destination and
authentication policy. Event data cannot choose a destination, header, or
secret. Route summaries and delivery records retain only the redacted URL
template.

## URL-template presets

The `{secret}` placeholder must occupy one complete path segment or query
value. Bondry resolves and percent-encodes it immediately before submission,
then verifies that the expanded URL has the configured origin. Store the
secret through the host `SecretProvider`; never put its value in route JSON.

| Receiver | Template | Secret value | Payload shape |
| --- | --- | --- | --- |
| ntfy | `https://ntfy.sh/{secret}` | A high-entropy topic | `{"message":"Power lost"}` |
| Bark | `https://api.day.app/{secret}` | The device key | `{"title":"Bondry","body":"Power lost"}` |
| Discord | `https://discord.com/api/webhooks/<webhook-id>/{secret}` | The webhook token | `{"content":"Power lost"}` |
| Home Assistant | `https://<instance>/api/webhook/{secret}` | The webhook ID | Route-specific JSON |

Replace `<webhook-id>` and `<instance>` in configuration. They are not part of
the URL-template expansion. A Home Assistant webhook ID and an ntfy topic act
as bearer credentials and must be generated as non-guessable secrets.

Use HTTPS for every non-loopback destination. For a private Home Assistant
deployment, prefer HTTPS with a route-specific additional trust anchor.
Private cleartext is an explicit fallback and requires
`allowPrivateCleartext`; Bondry still verifies the connected peer address.

The preset shapes follow the receiver documentation:

- [ntfy publishing](https://docs.ntfy.sh/publish/)
- [Bark POST JSON](https://github.com/Finb/Bark/blob/master/docs/en-us/tutorial.md#request-methods)
- [Discord execute webhook](https://docs.discord.com/developers/resources/webhook#execute-webhook)
- [Home Assistant webhook trigger](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger)

## Manual verification

Use a dedicated test destination and a newly generated secret. Register the
route, confirm that the route listing contains `{secret}` but not the resolved
value, emit one receiver-specific payload, and wait for a terminal `delivered`
status. Confirm receipt in the receiver UI or automation history. Finally,
search host logs and delivery records for the known secret and payload; both
searches must return no matches.

For the public ntfy smoke, use an ephemeral high-entropy topic and remove it
from the environment after the test:

```sh
BONDRY_NTFY_BASE_URL=https://ntfy.sh \
BONDRY_NTFY_TOPIC='<ephemeral-topic>' \
cargo test --locked -p bondry-egress-e2e \
  tests::self_hosted_ntfy_accepts_url_template_delivery -- --ignored --exact
```

The nightly workflow runs the same test against a checksum-pinned self-hosted
ntfy binary. Pull requests use only the in-repository ntfy-contract receiver
and never depend on external services.

On 2026-08-15, this test passed against ntfy 2.26.3 running locally and
against `ntfy.sh` with an ephemeral topic. The topic was neither printed nor
persisted. Bark, Discord, and Home Assistant require receiver-owned test
credentials; use the procedure above in the target environment before the
0.2.0 release.
