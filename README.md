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

## How verification works

The verifier reads only the two files and tells you whether the receipt is genuine and
finalized — a plain **`VALID FINAL`** or, if anything is altered or incomplete, a clear
**not-valid** result. It is fully **offline**: it never contacts our servers, so the result
can't be faked by us.

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

## Release

The verifier (binary builds for Linux/macOS/Windows **and** a fully auditable source release)
is being finalized and lands here shortly. Watch this repo for the release.

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

## Как работает проверка

Верификатор читает только два файла и говорит, настоящая ли квитанция и финализирована ли —
простое **`VALID FINAL`** или, если что-то изменено или неполно, понятный результат
**«не валидна»**. Проверка полностью **офлайн**: инструмент не обращается к нашим серверам,
поэтому подделать результат с нашей стороны нельзя.

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

## Релиз

Верификатор (бинарные сборки под Linux/macOS/Windows **и** полностью аудируемый релиз
исходников) сейчас финализируется и появится здесь в ближайшее время. Следи за репозиторием.

## Лицензия

MIT — см. [LICENSE](LICENSE).
