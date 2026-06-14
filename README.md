# TimeLayer Verifier

**Check that a TimeLayer receipt is genuine — offline, on your own machine, without trusting anyone.**

A TimeLayer receipt is proof that some action happened and hasn't been altered. The proof
rests on an independent quorum, not on a single signature or a single server. This tool lets
*you* verify a receipt yourself, so you never have to take our word for it.

- Website: https://timelayer-os.com

> 🇷🇺 **Русская версия — ниже.** (Russian version is below.)

---

## What a receipt is

A receipt is **two small files** that belong together:

| File | What it is | Size |
|---|---|---|
| `something.tlcert` | the **certificate** — the compact proof | ~0.4 KB |
| `something.tlbundle` | the **bundle** — the body the holder keeps | a few KB to tens of KB |

You keep both files. To prove the action later, you hand someone the two files and they run
the verifier. No database, no login, no trust in us.

---

## Quick start

1. Download the verifier from this repo (`bin/tl_verifier-linux-amd64`) and make it runnable:
   ```bash
   chmod +x tl_verifier-linux-amd64
   ```
2. Verify a receipt — pass its two files:
   ```bash
   ./tl_verifier-linux-amd64 verify your-receipt.tlcert your-receipt.tlbundle
   ```
3. A genuine, finalized receipt prints:
   ```
   VALID FINAL
   ```

That's it. `VALID FINAL` means the receipt is genuine and finalized; anything else means do not
trust it.

---

## What the result means

| Output | Meaning |
|---|---|
| `VALID FINAL` | The receipt is genuine and finalized. The action is proven. |
| `NOT VALID` (or a read error) | The receipt is altered, incomplete, or not finalized. **Do not trust it.** |

Verification is fully **offline** — the tool reads only the two files. It does not call our
servers, so the result can't be faked by us.

---

## Where receipts come from

You get a receipt whenever you notarize an action through TimeLayer (via our API or an
integration). The service returns the two files — `*.tlcert` and `*.tlbundle` — and **you
download and keep them**. They are yours. We don't store them for you, by design.

(A public "notarize → verify" button on https://timelayer-os.com is coming with launch.)

---

## Store your receipts

A "vault" is just a folder you control:

```bash
mkdir -p ~/timelayer-receipts
# save each receipt as a matching pair, named so you'll recognize it:
#   invoice-4471.tlcert  +  invoice-4471.tlbundle
```

- **Always keep the two files together** (same name, different extension).
- Back the folder up like any important document — the receipts are *your* proof.
- The files are safe to copy and share: a receipt reveals the proof, not your secrets.

---

## Platforms

This release ships a **Linux x86-64** binary. Need macOS or Windows? Open an issue and we'll
add it. A fully auditable source release of the verifier is planned.

## License

MIT — see [LICENSE](LICENSE).

---
---

# TimeLayer Verifier — по-русски

**Проверь, что квитанция TimeLayer настоящая — офлайн, на своём компьютере, никому не доверяя.**

Квитанция TimeLayer — это доказательство, что некое действие произошло и не было изменено.
Доказательство держится на независимом кворуме, а не на одной подписи и не на одном сервере.
Этот инструмент позволяет *тебе самому* проверить квитанцию — чтобы не верить нам на слово.

- Сайт: https://timelayer-os.com

## Что такое квитанция

Квитанция — это **два маленьких файла**, которые идут в паре:

| Файл | Что это | Размер |
|---|---|---|
| `что-то.tlcert` | **сертификат** — компактное доказательство | ~0,4 КБ |
| `что-то.tlbundle` | **тело** — то, что хранит у себя владелец | от нескольких КБ до десятков КБ |

Оба файла ты хранишь у себя. Чтобы потом доказать действие — отдаёшь два файла, и человек
запускает верификатор. Без базы, без логина, без доверия к нам.

## Быстрый старт

1. Скачай верификатор из репозитория (`bin/tl_verifier-linux-amd64`) и сделай исполняемым:
   ```bash
   chmod +x tl_verifier-linux-amd64
   ```
2. Проверь квитанцию — передай её два файла:
   ```bash
   ./tl_verifier-linux-amd64 verify твоя-квитанция.tlcert твоя-квитанция.tlbundle
   ```
3. Настоящая и финализированная квитанция выведет:
   ```
   VALID FINAL
   ```

Всё. `VALID FINAL` — квитанция настоящая и финализирована; что-либо другое — не доверяй ей.

## Что значит результат

| Вывод | Значение |
|---|---|
| `VALID FINAL` | Квитанция настоящая и финализирована. Действие доказано. |
| `NOT VALID` (или ошибка чтения) | Квитанция изменена, неполна или не финализирована. **Не доверяй.** |

Проверка полностью **офлайн** — читаются только два файла. Инструмент не обращается к нашим
серверам, поэтому подделать результат с нашей стороны нельзя.

## Откуда берутся квитанции

Квитанцию ты получаешь, когда заверяешь действие через TimeLayer (через наш API или
интеграцию). Сервис возвращает два файла — `*.tlcert` и `*.tlbundle` — и **ты их скачиваешь и
хранишь**. Они твои. Мы их у себя не держим — так задумано.

(Публичная кнопка «заверить → проверить» на https://timelayer-os.com появится к запуску.)

## Где хранить квитанции

«Контейнер» — это просто папка, которой управляешь ты:

```bash
mkdir -p ~/timelayer-receipts
# сохраняй каждую квитанцию парой, с понятным именем:
#   schet-4471.tlcert  +  schet-4471.tlbundle
```

- **Всегда храни два файла вместе** (одно имя, разные расширения).
- Делай резервную копию папки, как любого важного документа — квитанции это *твоё* доказательство.
- Файлы можно копировать и передавать без опаски: квитанция раскрывает доказательство, а не твои секреты.

## Платформы

В этом релизе — бинарь под **Linux x86-64**. Нужен macOS или Windows? Открой issue, добавим.
Полностью аудируемый релиз исходников верификатора запланирован.

## Лицензия

MIT — см. [LICENSE](LICENSE).
