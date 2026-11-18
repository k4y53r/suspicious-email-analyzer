# How it works

[← README](../README.md) · **English** · [Castellano](how-it-works.es.md)

1. **Takes the .eml apart** (Python standard library): headers, text (HTML to text, fixes mojibake and invisible padding),
   links and attachments (with their sha256).
2. **Deterministic technical indicators**, with points:
   - SPF, DKIM and DMARC from the most recent `Authentication-Results`: the one added by the last MX, the only reliable
     one. Since 1.8.1 all consecutive ones above the next `Received` are read together, because some providers spread
     dmarc, spf and dkim over three headers.
   - Return-Path, Reply-To and DKIM signature of a different domain than the From; display name with another address;
     domains that look randomly generated (series of 5+ digits, 5+ consonants in a row, almost no vowels) or with 3+
     subdomain levels; frequently abused TLDs. Since 1.7, the Return-Path and DKIM signature of a sending platform
     (`PROVEEDORES_ENVIO`: Mailchimp, SendGrid…) do not count: there they are normal.
   - URLs: IP address, punycode, shorteners, generic hosting (`storage.googleapis.com`…), link text that does not match
     the destination.
   - Click tracking of sending platforms (since 1.9, `SEGUIMIENTO`: `awstrack.me` of Amazon SES, `rs6.net` of Constant
     Contact, `list-manage.com` of Mailchimp, SendGrid, Brevo, HubSpot…): +5 once per mail, because it is legitimate but
     hides the real destination. Those links do not also score for random subdomain or mismatched text.
   - Attachments by name: executables, macros, containers/HTML and double extensions.
   - Attachments from the inside (since 1.12), in memory, without writing or executing anything:
     - Real type from the first bytes (`MAGIA`): a Windows executable (MZ with a PE header), ELF or `.lnk` shortcut under
       another name adds +60 and marks the attachment dangerous; a ZIP, RAR, 7z, CAB, gzip or ISO named `.pdf`, `.jpg`,
       `.doc`… adds +30. A `.docx` or `.xlsx` is a ZIP and does not count.
     - ZIP index (also docx, xlsx, jar) read with `zipfile` over the bytes: only the index is read, nothing is
       decompressed, so a ZIP bomb is harmless; at most 1000 names are kept. An executable inside adds +60 and marks the
       attachment dangerous; macros (`vbaProject.bin` in a `.docx`, or a `.docm` inside) +40, also dangerous; a container
       or HTML inside +20; an encrypted ZIP +30 (the password usually travels in the body so the antivirus cannot see
       it); an unreadable ZIP +10. Inner names go to the report without control or format characters (U+202E:
       `fac<U+202E>txt.exe` reads `facexe.txt`), cut from the front to keep the extension, and without the trailing "."
       and " " that Windows ignores. The attachment name is cleaned too.
     - A readable, unencrypted ZIP with only documents or images (`EXT_SIN_MACROS`: no `.doc`, `.xls`, `.ppt` or `.rtf`,
       which can carry macros that are not inspected) adds +10 instead of the +30 for a container.
     - The newest checks are only tested with synthetic samples (`pruebas/generar_adjuntos.py`, inert contents). Not
       inspected: URLs or JavaScript inside PDF, RAR/7z/ISO contents, ZIP inside ZIP.
     - Legacy Office (OLE2: `.doc`, `.xls`, `.ppt`; since 1.13) with a minimal standard-library reader (`mirar_ole`)
       that only follows sector chains of the file itself, with loops cut, each FAT sector read once and at most 32 MB
       (otherwise a hostile file multiplies the FAT until memory runs out):
       - VBA macros from the directory (`Macros/VBA` in Word, `_VBA_PROJECT_CUR` in Excel): +40, dangerous;
       - Excel 4.0 macro sheets (XLM, macro-type `BOUNDSHEET` in the `Workbook` stream), the classic route without VBA:
         +40, dangerous; the text says whether the sheet is hidden;
       - password-encrypted `.docx`/`.xlsx` (wrapped in an OLE with `EncryptedPackage`): +30;
       - Excel with `FILEPASS`: +15, because a workbook marked "read-only recommended" also carries it and opens without a key;
       - unreadable OLE document: +10. This is the natural evasion route, because Office accepts files this reader
         rejects; the indicator stays in the stored analysis.
       Tested with synthetic samples from `pruebas/generar_adjuntos.py`, cross-checked with `olefile` 0.47 (outside the
       project) and with 6000 corrupted files (none hangs the analysis); a hostile 24.6 MB DIFAT takes 0.21 s with at most
       137 MB. Not inspected: PowerPoint 97 VBA (in another stream), Word encrypted with the old read password, macros
       inside a ZIP.
   - Text addressed to the analyzer rather than to the recipient (since 1.11, `INYECCION`, +30), in Spanish, English,
     Portuguese, French, German and Italian: "ignore the instructions", "note to the system/model…", "classify this mail
     as legitimate", "its risk is 0" and the `<<<`/`CORREO>>>` delimiters. 21 injection phrases and 19 similar legitimate
     ones pass without failures. Possible false positive: a legitimate mail quoting `<<<` (a diff, a quote) adds +30.
   - Hidden text after the visible content (since 1.11, +15, any language): ≥ 80 hidden characters (`display:none`,
     `font-size:0`, `opacity:0`, `max-height:0`, `mso-hide`…) after visible text, or ≥ 20 hidden pieces of 1-2 characters
     (split words). The preview line comes before everything visible and does not count; tracking pixels are images and
     do not count either. The style has to end in zero: `font-size:0.9em` or `opacity:0.8` are visible. The hidden text
     does not reach the model, but it does reach the fingerprint, the campaign template and `INYECCION`. With this
     indicator or the injection one, the model can no longer halve the technical score. Not detected: text in the
     background colour, `text-indent:-9999px`, off-screen `position:absolute`, `font-size:1px`; that text still reaches
     the model.
3. **Local model** (`qwen2.5:7b` by default, configurable). It receives sender, subject, indicators and body as untrusted
   data and answers with a forced JSON schema (`format` of the Ollama API): classification, risk, impersonated brand,
   tactics and explanation. The model has no tools: the worst an injection achieves is changing its answer; the mail's
   `<<<`/`>>>` are replaced so it cannot close the data block.
4. **Final risk** = technical + model points (capped at 100), never below 65 if the model says phishing, fraud or
   malware (15 if it says spam). If the model sees a normal mail with no odd traits, the technical score counts half,
   unless there is an indicator of 20 points or more. If it says spam, its traits add at most 10. ≥ 80 if there is a
   dangerous attachment.
   **Own sender** (since 1.7): DMARC pass, From domain in the Tranco top 100,000, and the origin IP is theirs by PTR or by
   ASN holder. Then the model's brand-impersonation flag is discarded and the per-class minimum does not apply. PTR and
   DMARC alone are not enough: an attacker sets them up on a VPS with their own domain; popularity they cannot fake.
5. **IOCs** (`iocs` in the JSON): extracted, never visited. The IP that delivered the mail to the MX that signs the
   `Authentication-Results` (the only reliable one; `aproximada` if that MX is not recognised), domains with their root
   and role (from, return_path, reply_to, dkim, url), full URLs, addresses and attachment sha256. `compartido` marks
   webmail, social networks, generic hosting, shorteners and IPs of sending providers: there the IOC is the URL or the
   address, not the domain or the IP.
   Verdict: `< 30` legitimate, `30-64` suspicious, `≥ 65` malicious. If the model fails, the technical score stays with
   a warning.

## How to send the mail

- **Forward as attachment** (Gmail: ⋮ → "Forward as attachment"): `adjunto_rfc822` mode, full analysis with the original
  headers.
- **Normal forward**: the original headers are lost. With a "Forwarded message" block, From and subject are taken from
  there (`reenvio_en_linea`). Without it (`--reenviado`, or always from `buzon.py`) only body, links and the Reply-To,
  which Gmail keeps, are analysed (`reenvio_sin_cabeceras`).
- **Automatic from Thunderbird** (mail it files as junk, forwarded as attachment by a filter): [`guia-reenvio.md`](../guia-reenvio.md) (Spanish),
  with alternatives (Apps Script in Gmail, manual forwarding, add-ons).
