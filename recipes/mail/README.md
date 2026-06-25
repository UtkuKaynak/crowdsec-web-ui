# Mail recipes (EXPERIMENTAL)

Engine-side CrowdSec config that powers the Web UI **Mail** page. These are
**not** installed by the Web UI — you drop them on the CrowdSec host once. The
Web UI then reads the results it produces (no companion required).

> ⚠️ **Experimental.** These are hand-written and not validated against every
> Postfix/Dovecot setup. Always run `sudo crowdsec -t` after installing, and use
> `cscli explain` to confirm matches before relying on them. Field assumptions:
> the standard syslog parser sets `evt.Parsed.program` and `evt.Parsed.message`,
> and the Postfix parser sets `evt.Meta.source_ip`.

## What's here

| File | Purpose |
| --- | --- |
| `parsers/s02-enrich/mail-flow.yaml` | Classifies mail events into `mail/<category>` nodes. CrowdSec's per-node counter (`cs_node_hits_ok_total`) is what the **Mail flow by category** chart reads. |
| `scenarios/smtp-auth-burst.yaml` | SMTP/IMAP auth-failure burst from one IP. |
| `scenarios/smtp-dictionary.yaml` | One IP probing many distinct recipients (dictionary / RCPT harvesting). |

### Mail-flow categories (mailgraph-style message accounting)

The parser counts **messages**, not connections, from the same log lines
mailgraph uses. It emits these named nodes — the Web UI keys off these names:

```
mail/received   mail/sent   mail/rejected   mail/bounced   mail/deferred
```

| Node | Source line | Meaning |
| --- | --- | --- |
| `mail/received` | `postfix/smtpd … client=` | message accepted from the network (excludes local/cron mail + bounces, matching mailgraph) |
| `mail/sent` | `postfix/smtp … status=sent` | delivered **outbound** to a remote MX (local mailbox deliveries are not counted, matching mailgraph) |
| `mail/bounced` | `status=bounced` | hard delivery failure |
| `mail/deferred` | `status=deferred` | temporary delivery failure |
| `mail/rejected` | `postfix/smtpd\|cleanup … reject:` | message refused |

Optional `mail/spam` / `mail/virus` (amavis content scanning) are commented out
in the parser — enable them if you run amavis/SpamAssassin.

**Not here on purpose:** SASL auth bursts, spam-bot connections, and dictionary
attacks are *connection/attack* signals, not message accounting — they show up in
the Mail page's **attacks by scenario** panel (and the scenarios below), so the
mail-flow chart stays a clean mailgraph-style message count.

> **Upgrading from an earlier version?** The parser moved from `s02-enrich` to
> `s01-parse` (delivery/queue lines are dropped before s02, so only `rejected`
> showed up). Remove the old copy first:
> `sudo rm -f /etc/crowdsec/parsers/s02-enrich/mail-flow.yaml`

## Install

```bash
# 1. Copy parser + scenarios into the CrowdSec config tree
#    (the parser goes to parsers/s01-parse/ — see the structure under parsers/)
sudo cp -r parsers/*   /etc/crowdsec/parsers/
sudo cp scenarios/*.yaml /etc/crowdsec/scenarios/

# 2. Make sure mail logs are being acquired and the Postfix collection is present
sudo cscli collections install crowdsecurity/postfix   # if not already
#   acquisition: add /var/log/maillog (or your mail log) with type: syslog

# 3. Validate, then reload
sudo crowdsec -t
sudo cscli explain --file /var/log/maillog --type syslog | less   # sanity-check matches
sudo systemctl reload crowdsec     # reload (not restart) preserves metrics counters
```

## Verify it's flowing

```bash
curl -s localhost:6060/metrics | grep 'cs_node_hits_ok_total{name="mail/'
```

Once those counters appear, the Web UI **Mail** page's *Mail flow by category*
chart fills in (it scrapes the same endpoint). The *Mail attacks by scenario*
chart works from existing CrowdSec scenario data and needs none of this.

## Notes

- If you already run a SASL brute-force collection (e.g. `Guezli/postfix-sasl-bf`),
  `smtp-auth-burst` overlaps — keep whichever fits.
- These will become one-click installs once the Tier-2 companion lands; until
  then they are a manual, validated install.
