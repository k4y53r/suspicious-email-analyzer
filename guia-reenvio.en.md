# Automatic forwarding of spam to the analyzer from Thunderbird (or Gmail)

[Castellano](guia-reenvio.md) · **English**

A guide to make Thunderbird forward **as an attachment** to the analyzer's mailbox every new mail that its adaptive
filter classifies as junk. As an attachment, the original headers arrive (SPF, DKIM, DMARC, origin IP) and the analyzer
works in `adjunto_rfc822` mode, the most complete one; forwarded in the body, all of that is lost.

In the examples, `analista@example.org` is the address of the analyzer's mailbox.

Checked in the Thunderbird code (comm-central), not only in the documentation:

| What | Where |
|---|---|
| The filter action "Forward Message To" uses the default forwarding mode | `mailnews/search/src/nsMsgFilterService.cpp` (`kForwardAsDefault`) |
| `mail.forward_message_mode = 0` is attachment; any other value, inline | `mailnews/compose/src/nsMsgComposeService.cpp` (`ForwardMessage`) |
| `mail.filters.forward.enabled = false` disables filter forwards; if it does not exist, it counts as `true` | same file |
| "After classification" filters only apply to new mail | `mailnews/base/src/nsMsgDBFolder.cpp` (`CallFilterPlugins`, `OnMessageClassified`) |

## 1. Requirements on the analyzer

- The address each Thunderbird account forwards from (its default identity) must be in `REMITENTES` of `buzon.py`.
- The forward must go out through that account's SMTP server, so it arrives DKIM-signed by its domain. Without a valid
  signature, `buzon.py` marks it "unverified" and ignores it if `EXIGIR_DKIM=si`.
- Every forwarded mail generates a reply and a pass of the model (~1 min, at most 6 per pass). With a lot of spam there
  will be a queue.

## 2. Global Thunderbird setting (once)

Settings → General → Config Editor:

| Preference | Value | Notes |
|---|---|---|
| `mail.forward_message_mode` | `0` | Forward as attachment. It also affects the normal "Forward" button; inline forwarding is still under Message → Forward As → Inline. |
| `mail.filters.forward.enabled` | do not create it | If it shows up as `false`, set it to `true`. |

There is no way to make only the filter use an attachment: it reads the same global setting.

## 3. On each account

Filters are per account (each one has its own `msgFilterRules.dat`). IMAP accounts each need their own filter; POP
accounts that deliver to the "Global Inbox (Local Folders)" use the Local Folders filters.

1. **Junk controls on**: Account Settings → Junk Settings → "Enable adaptive junk mail controls for this account".
   Without this nothing is classified and the filter does not act.
2. **Whitelist**: add `analista@example.org` to the address book ticked under "Do not mark mail as junk if the sender
   is in…", so the analyzer's replies are not classified as junk.
3. **Filter**: Tools → Message Filters → pick the account → New:
   - Name: `Spam to the analyzer`.
   - Apply the filter when: **Getting New Mail → Filter after Junk Classification**. Untick "Run manually" if you do
     not want to be able to launch it by hand (see 6.2).
   - Match **all** of the following:
     - "Junk Status" **is** "Junk".
     - "From" **doesn't contain** `analista@example.org` (avoids the loop: reply classified as junk → forwarded → new
       reply…).
   - Action: **Forward Message To** `analista@example.org`.
   - No other actions in the same filter: moving or deleting is left to the junk settings (bug 1071628: forwarding and
     moving in the same filter caused problems with inline forwarding).

Thunderbird does not copy filters between accounts: repeat it by hand.

## 4. Check

1. Send one of the accounts a mail that Thunderbird will mark as junk (or wait for the first real one).
2. In the account: the mail must end up with the "Forwarded" status (arrow icon). If not, Tools → Filter Log (turn it
   on first) tells you whether the filter was applied.
3. On the analyzer's machine, the analysis must come out as `adjunto_rfc822` with the sender verification as `pass`:

   ```
   tail -5 ~/.local/state/analista-correo/run.log
   sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT fecha, modo, veredicto, riesgo FROM analisis ORDER BY id DESC LIMIT 5"
   ```

   An "aviso: remitente … sin verificar" in `run.log` means the address does not sign with DKIM or did not go out
   through its SMTP; "ignorado: remitente no autorizado" means it is missing from `REMITENTES`.

## 5. Limits

- Thunderbird has to be open: filters run in the client, not on the server.
- Marking a mail as junk by hand does **not** fire the filter: it only applies to new mail classified on arrival.
- Mail that the server (Gmail, for example) already sends to its Spam folder does not go through the inbox or through
  Thunderbird's classifier: this filter does not see it. For that case, see 6.1.
- The classifier's false positives are forwarded too. They stay on your machine, but the enrichment (if you turn it on)
  queries their domains and IPs at abuse.ch and RDAP (the public lists are only downloaded).
- Not verified: open bugs with "after classification" filters on Linux and IMAP (bugs 1245157 and 1661989), and a 2021
  support thread about filter forwards that failed on messages with attachments.

## 6. Alternatives

### 6.1 Gmail: Apps Script over the Spam folder

For the spam that Gmail already sets aside (Gmail's settings do not work: the account's automatic forwarding excludes
spam, "Report spam" only sends a copy to Google, and filters have no documented operator for Spam).

- A script at script.google.com with a time-driven trigger (minimum 1 min; 10-15 min is enough) that walks
  `GmailApp.getSpamThreads()`, attaches each message with `getRawContent()` as `message/rfc822` in
  `GmailApp.sendEmail(...)` to `analista@example.org`, and marks what was sent (label or property) so it is not
  repeated. `GmailMessage.forward()` is not documented as an attachment: do not use it.
- It runs at Google: it does not need Thunderbird open. It goes out from the Gmail address with `gmail.com` DKIM.
- Personal-account quotas: 100 recipients a day and 90 minutes of triggers a day.
- It requires giving the script permission over all your mail. The script is not included here: write it and review it
  before authorising it.

### 6.2 Thunderbird: spam marked by hand

- Manual forward: select the mail → Message → Forward As → Attachment, to `analista@example.org`.
- In batches: the same filter with "Run manually" ticked, and in the Junk folder Tools → Run Filters on Folder. It
  forwards everything in it: the analyzer recognises the ones already analysed (it replies "YA ANALIZADO" without the
  model), but each one generates a reply.
- Periodic filters (every 10 min by default) are only described in forums for the inbox: not confirmed for the Junk
  folder.

### 6.3 Thunderbird add-ons

There is no current one that automatically forwards mail marked as junk (checked at the time of writing;
addons.thunderbird.net could not be opened, compatibilities not verified):

- FiltaQuilla: extra filter actions, no forwarding as attachment.
- Habu and KnujOn: a button to forward the spam of the open folder; old, probably incompatible.
- Forward: chooses attachment or inline in the normal forward; it is not for spam.

None is recommended.
