# Threat model / Модель угроз

## English

- **What a receipt proves.** That this `cert.tlcert` + `bundle.tlbundle` is internally
  consistent (BLAKE3 root), carries a `FINAL` marker, and was signed by a quorum of the
  published operator keys (Ed25519) over exactly this content — checkable offline, with no
  network, key server, or roster lookup.
- **What it does not prove.** The *truth* of the content. A receipt proves a quorum attested to
  this specific document, not that the document's claims are correct.
- **Operator key compromise.** One key is not enough. `VALID FINAL` requires a quorum of
  signatures from *distinct* independent operators, so a single compromised operator key cannot
  forge a receipt. Keys are rotated by publishing a new epoch.
- **Quorum unavailable.** Fail-closed: if a quorum cannot sign, no receipt is issued — you get
  none, never a false one. Receipts already issued stay verifiable offline forever (self-contained).
- **Receipt loss.** The receipt is what you keep; the network stores none of your content
  (only a hash ever leaves you). If a receipt is lost, re-notarize the action to obtain a new one.

## Русский

- **Что доказывает квитанция.** Что данная пара `cert.tlcert` + `bundle.tlbundle` внутренне
  согласована (BLAKE3-корень), несёт маркер `FINAL` и подписана кворумом опубликованных ключей
  операторов (Ed25519) именно над этим содержимым — проверяемо офлайн, без сети, key server и
  обращения к roster.
- **Что она не доказывает.** *Истинность* содержимого. Квитанция доказывает, что кворум заверил
  этот конкретный документ, а не что утверждения в документе верны.
- **Компрометация ключа оператора.** Одного ключа недостаточно. `VALID FINAL` требует кворума
  подписей от *разных* независимых операторов, поэтому один скомпрометированный ключ не позволяет
  подделать квитанцию. Ключи ротируются публикацией новой epoch.
- **Кворум недоступен.** Fail-closed: если кворум не может подписать, квитанция не выдаётся — вы
  получаете ничего, а не ложную квитанцию. Уже выданные квитанции остаются проверяемыми офлайн
  всегда (самодостаточны).
- **Потеря квитанции.** Квитанция — это то, что вы храните; сеть не хранит ваше содержимое (от вас
  уходит только хеш). Если квитанция потеряна — перезаверьте действие, чтобы получить новую.
