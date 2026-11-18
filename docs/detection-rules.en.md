# Detection rules of 1.15

[← README](../README.en.md) · **English** · [Castellano](detection-rules.md)

Rationale: an intimate-bait mail (photos and a secret, with a link) can come out "legitimate" with low risk if it only
adds one enrichment signal and the local model answers "normal conversation", because that answer halves the points. All
rules are generic (no domains or personal names) and none reaches the suspicious threshold by itself.

| Rule | Where | Points | Signal |
|---|---|---|---|
| R1 | `evaluar` | 15 in link, 10 in text | unreplaced template placeholder (`{tag}`, `{{x}}`, `%%x%%`, `[[x]]`, `${x}`, `<%= x %>`, also encoded in the link); the CSS of `<style>` leaking into the visible text is ignored |
| R2 | `evaluar` | 10 + 5 (cap 15) | From name different from the signature or introduction ("Saludos, X", "soy X", "met X"); greeting by alias ("Hola Gebruiker4821") |
| R3 | `evaluar` | 10 | system local part (postmaster, noreply, admin…) with a person's name of 2+ words |
| R5 | `evaluar` + model | 15 (no halving) + 25 from the model | photos/videos/files and a secrecy formula within 400 characters, with a link or non-inline attachment and a body under 800 characters; the model has the `cebo_intimo_o_chantaje` question (trait, not class) |
| R6 | `evaluar` | 0 | dominant language (function words) outside `ANALISTA_CORREO_IDIOMAS` (default `es,en`); only opens the door to R4 |
| R4 | `combinar` | floor 40 | model says legitimate + normal conversation, there is a `List-Unsubscribe` or UUID in a link of the From domain **and** at least one other independent signal (R1, R2, R3, R5, R6, domain younger than a year, own history, model bait). Cancels the halving. Not applied to an own sender |
| R7 | `enriquecer.py` | 20 (was 10/15) | ASN or prefix with 5+ malicious and 85 % or more in 90 days; counts as a strong indicator. Back to 10/15 if the PTR is a sending platform or any domain in the mail is over 2 years old |

R2, R3 and R6 do not apply if the sender is an authenticated own sender. The point-less signals the model sees
(`List-Unsubscribe`, tracking UUID, dominant language, contradiction) go in `senales_info` of the JSON, not in
`indicadores`. Tests: `python3 -I pruebas/probar_reglas.py`; `pruebas/generar_sinteticos.py pruebas/sinteticos`
regenerates the new synthetic samples. Limits: R2 treats "Alejandro" and "Alex" as the same name (3-letter prefix) and
cannot tell nicknames without a common prefix (Robert/Bob adds +10). Rollback: go back to the previous version of your
copy; the database is not reverted (stored rows carry `version` 1.15).
