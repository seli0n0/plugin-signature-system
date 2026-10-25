# Plugin Signature System — `exsig`

Подпись плагинов **Exteragram** — и одиночных `.plugin`, и бандлов **`.eaf`** (zip-архив с папкой
плагина) — на базе **SHA-256 + Ed25519**. Сервера подписи нет: подпись ставится локально у автора,
проверка работает офлайн, всё нужное для проверки едет внутри самого файла.

```
exsig keygen / cert-issue / pack / unpack / sign / verify / info / strip / keyring
88 тестов = 29 атак + 10 happy-path + 14 CLI + 31 на .eaf + 4 на реальных файлах
120 настоящих .plugin и 8 настоящих .eaf прогнаны full round-trip (подпись -> проверка -> извлечение)
```

---

## 1. Почему одного SHA-256 недостаточно

SHA-256 отвечает на вопрос «не изменён ли файл», но не на вопрос «кто его сделал»:
хэш пересчитывает кто угодно, поэтому хэш-лист в каталоге подделывается одним движением.
Значит «подпись» = **SHA-256 канонического манифеста**, заверенный асимметричной подписью.

SHA-256 используется на трёх уровнях, и все три обязательны:

| Уровень | Что хэшируется | Зачем |
|---|---|---|
| 1 | байты кода плагина (payload) | ловит изменение кода на 1 байт |
| 2 | канонический JSON манифеста | фиксирует id/версию/автора/размер, а не только байты |
| 3 | `SHA-256(манифест)` внутри Ed25519/pre-hash и в `keyid` | доменное разделение и отпечаток ключа |

`keyid = первые 16 hex-символов SHA-256(публичный ключ)` — короткий человекочитаемый идентификатор;
полный отпечаток выводит `keyring add --show-fingerprint`.

## 2. Модель доверия без сервера

Три уровня ключей, никаких сервисов:

```
Корневой ключ автора        @extera-root      хранится холодно (флэшка/ноутбук автора)
   │                                        подписывает ТОЛЬКО сертификаты, код не трогает
   ▼
Ключ сборки плагина         build-server      живёт на машине сборки, может утечь
   │                                        подписывает .plugin / .eaf, попадает в сертификат
   ▼
Плагин 1231.plugin          = код + манифест + сертификат + подпись  (один файл, всё с собой)
Бандл 1231.eaf              = zip папки + манифест с хэшем каждой записи + сертификат
                               + подпись в комментарии архива  (тоже один файл, всё с собой)

Ключринг проверяющей стороны  keyring.json    = публичные половины корней, обычный файл
```

Что именно заменяет сервер:

1. **Публичный ключ едет в файле.** В блоке подписи лежит сертификат: «публичный ключ X подписывает
   плагины с id ∈ [...] от имени корня Y, срок до T», подписанный корнем Y. Хосту не нужно никуда
   ходить — он проверяет цепочку по байтам файла.
2. **Закреплён только корень.** `keyring.json` — это 1 запись на автора. Его вы передаёте как угодно:
   пост в канале, файл в git, USB, письмо. Это данные, а не сервис.
3. **Отзыв — тоже файл.** `exsig keyring revoke --keyid <id>` создаёт запис-«надгробие» даже для
   ключа, которого в keyring никогда не было (именно так выглядит ключ сборки, который никогда
   туда и не попадал). Отзыв распространяется тем же каналом, что и keyring.
4. **Ротация без участия хоста.** Автор выпускает новый ключ сборки и новый сертификат. Старые
   подписи продолжают работать, пока корень не отозван; скомпрометированный ключ отзывающим
   `revoke` отключается мгновенно и локально.

## 3. Формат артефакта

Подпись **встраивается** в файл, потому что `.plugin` живут и ходят по чатам как один файл:
sidecar-файл `.sig` при пересылке теряется, а Telegram ещё и переименовывает скачанное
(`Bot Login (2).plugin`, `2_5398020107131725147.plugin`).

Блок — это комментарии Python, поэтому загрузчик плагина не меняется: подписанный файл
по-прежнему парсится и исполняется (проверено в `tests/test_sign_verify.py::test_signed_plugin_is_still_loadable_python`
и на 120 реальных файлах).

```python
__id__ = "extera_rpc"
...код плагина...
# ---EXTERA-SIG-V1---
# algo: ed25519
# keyid: bad17382e0aeccdf
# manifest: base64(SHA-256-манифеста)
# cert: base64(сертификата сборки)        # факультативно
# sig: base64(Ed25519)
# ---EXTERA-SIG-V1-END---
```

Манифест (канонический JSON: сортировка ключей, separators `(",", ":")`, ASCII):

```json
{"algo":"ed25519","files":[{"path":"extera_rpc.plugin","sha256":"6296…","size":13480}],
 "format":"EXTERA-SIG-V1","keyid":"bad1…","plugin_author":"@PESSDES_Plugins",
 "plugin_id":"extera_rpc","plugin_name":"Custom Now Playing","plugin_version":"1.1",
 "sealed_at":1792868673}
```

Правила канонизации (`exsig/format.py`):

* `payload` = файл до маркера с отброшенными **только** завершающими `\r`/`\n`; переводы строк
  внутри кода не нормализуются, байты считаются как есть.
* Значит `sign` — это не «приписать файл к файлу», а детерминированное преобразование:
  один и тот же вход даёт один и тот же `payload_sha256`.
* Авторитетен **последний** маркер `START`; если `START` встречается в payload ещё раз — артефакт
  бракуется целиком (атака «два блока»).
* Всё между маркерами — только известные `# key: value`; любой другой текст, дубликат директивы,
  незакрытый блок, байты после `END` = ошибка формата, а не «молча игнорируем».
* `manifest`/`cert` обязаны быть уже в канонической форме. Неканонический JSON бракуется: два
  парсера могли бы разойтись в том, что именно подписано.
* `path` у одиночного плагина — голое имя файла без директорий; оно **ни на что не влияет** при
  проверке (только информация), иначе подпись ломалась бы от переименования в чате.

Доменное разделение (`exsig/keys.py`): подпись плагина считается по `SHA-256("EXTERA-PLUGIN-V1|"+SHA-256(манифест))`,
подпись сертификата — по `SHA-256("EXTERA-CERT-V1|"+SHA-256(тело))`. Подпись сертификата нельзя
выдать за подпись плагина и наоборот (`test_certificate_signature_cannot_be_reused_as_plugin_signature`).

### 3.1 `.eaf`: бандл подписывается пофайлово, блок живёт в комментарии zip

`.eaf` — обычный zip, которым собирает `plugin2eaf`:

```
plugin/                 директория
plugin/meta.yml         id / name / author / version / icon / min_version
plugin/src/main.py      код
plugin/locales/*.yml    строки (факультативно)
refmap.yml              metainfo/main/assets/strings -> пути; читает хост
```

Хэш архива целиком как якорь доверия не годится: распаковка и перепаковка меняют байты контейнера,
а исполняется содержимое записей. Поэтому:

* **манифест несёт по одному SHA-256 + размеру на каждую запись** (директории — нет), список
  отсортирован по пути; это то же поле `manifest.files`, плюс `container: "eaf"`;
* **блок подписи пишется в комментарий архива** (EOCD, максимум 65535 байт), а не отдельным файлом
  внутрь дерева — иначе сама подпись стала бы неподписанным файлом в папке плагина; при переподписи
  существовавший комментарий заменяется;
* **id и версия берутся из `meta.yml`**, на который указывает `refmap.yml`, и попадают в подписанный
  манифест — смена `id`/`version` внутри бандла ломает подпись и упирается в scope сертификата;
* **извлечение и хэширование бракует hostile-архив**: зашифрованная запись, symlink, дубль имени,
  путь наружу (`../`), нетиповой метод сжатия, лимиты 512 записей / 256 MiB распакованного;
* `path` записи проверяется как относительный POSIX-путь, а не голое имя: бандл переживает
  переименование файла так же, как одиночный плагин.

```bash
exsig pack ./demo --out demo.eaf         # папка или одиночный .plugin -> канонический .eaf
exsig sign demo.eaf --key build.key --cert demo.cert.json
exsig verify demo.signed.eaf             # [OK] ... entries=3 content=347da00f...
exsig unpack demo.signed.eaf --dest installed/
```

`pack` детерминирован: одна и та же папка даёт побайтово одинаковый архив (метки времени,
`create_system=0`, сортировка записей и директорий). `tree sha256` из `exsig info` — SHA-256 от
канонического списка записей: он устойчив к перепаковке, в отличие от хэша файла, и именно его
сравнивают логики обновления.

## 4. Алгоритм проверки (порядок фиксирован)

```
0  определить контейнер по байтам: PK\x03\x04 -> .eaf, иначе .plugin
   (тип обязан совпадать с manifest.container, иначе REJECT)
1  размотать блок: для .plugin — комментарии в конце файла, для .eaf — комментарий zip;
   ошибки формата → REJECT (exit 1)
2  распарсить и переканонизировать manifest/cert
3  block.keyid == manifest.keyid                        (иначе подмена ключа)
4  .plugin: SHA-256(payload) == manifest.files[0].sha256
   .eaf:    список записей архива == manifest.files, попарно по path/sha256/size  ← целостность
5  size совпадает, path без директорий (.plugin) / безопасный относительный путь (.eaf)
6  разрешить ключ:
     есть cert → каноничность → issuer в keyring и не отозван → Ed25519 по cert
                   → subject_keyid == SHA-256(subject_pubkey) → plugin_id ∈ cert.plugin_ids
                   → срок действия → subject не отозван
     нет cert  → запись в keyring по keyid (или UNKNOWN)
7  Ed25519(sig) по TBS манифеста
8  ожидания вызывающего: --expect-keyid / --expect-id / --expect-version
```

Три разных вердикта, а не один «fail» — хосту важно различать «подделка» и «я этого не знаю»:

| exit | статус | смысл для хоста |
|---|---|---|
| 0 | `valid` | установить; цепочка ведёт к закреплённому корню |
| 1 | `invalid` | отвергнуть: код ≠ подписанному, подпись битая, ключ/корень отозваны, сертификат не про то |
| 2 | `unsigned` | решения нет: политика для неподписанных (`--policy permissive` → 0) |
| 3 | `untrusted` | математика сходится, ключа нет на Record → показать отпечаток и спросить автора |

## 5. Интеграция в хост

CLI — это и есть интерфейс; встраивание в Exteragram — одна подпроцесс-вызовка на установке:

```python
import json, subprocess, sys

def install_gate(plugin_path: str, expected_version: str | None = None) -> str:
    argv = [sys.executable, "-m", "exsig", "verify", plugin_path, "--json"]
    if expected_version:
        argv += ["--expect-version", expected_version]
    proc = subprocess.run(argv, capture_output=True, text=True)
    report = json.loads(proc.stdout)
    if proc.returncode == 0:
        return "install"
    if proc.returncode == 3:
        return f"ask-user:{report['signer']['keyid']}"   # показать отпечаток, доверять вручную
    return "reject"                                      # 1 и 2
```

Отпечаток автора сверяется вне полосы передачи (его канал, ник, личная встреча) — это единственное
человеческое действие во всей схеме, ровно как в SSH/Tofu.

Один и тот же гейт закрывает оба контейнера: `verify` сам определяет тип по байтам, а `report["container"]`
говорит, что ставить дальше — `.plugin` кладётся в папку плагинов как есть, `.eaf` после `valid`
распаковывается `exsig unpack` (именно там отказ на `../`, symlink, дубли и размеры превращается в
несуществующую установку).

## 6. Что закрыто тестами

| Атака | Контрмера | Тест |
|---|---|---|
| изменить 1 байт в коде | SHA-256 payload | `test_one_flipped_byte_in_the_code_is_rejected`, плюс по 1 байту на 40 реальных файлах |
| подменить байты + пересчитать хэш честно | Ed25519 по манифесту | `test_attacker_substitutes_his_own_digest` |
| перенести подлинную подпись на другой код | digest не сходится | `test_genuine_signature_moved_onto_different_code` |
| выдать старую сборку за новую | версия внутри подписи + `--expect-version` | `test_genuine_old_build_cannot_pass_as_the_new_one` |
| вписать свой блок после настоящего | берём последний маркер, вложенный = брак | `test_nested_marker_smuggling_is_rejected` |
| спрятать маркер в середине строки | маркер обязан быть с начала строки | `test_marker_hiding_inside_a_line_is_rejected` |
| строка кода/мусор внутри блока | неизвестная директива = FormatError | `test_executable_line_inside_the_block_is_rejected`, `test_comment_line_inside_the_block_is_rejected`, `test_bytes_after_the_block_are_rejected` |
| другой JSON-формат того же манифеста | требование каноничности | `test_non_canonical_manifest_is_rejected` |
| rival-автор подписывает своим ключом | `untrusted`, а не `valid` | `test_forged_author_signature_is_untrusted_not_valid` |
| выдать чужой сертификат за свой | issuer обязан быть в keyring | `test_unpinned_root_is_a_prompt_not_a_verdict` |
| сертификат на другой id плагина | scope в cert + сверка | `test_certificate_cannot_authorise_a_different_plugin` |
| расширить/переписать сертификат | подпись по каноническому телу | `test_edited_certificate_is_rejected`, `test_certificate_subject_keyid_must_hash_to_its_own_key` |
| подпись сертификата как подпись плагина | доменная метка TBS | `test_certificate_signature_cannot_be_reused_as_plugin_signature` |
| использовать скомпрометированный ключ сборки | revoke по keyid без публичного ключа | `test_a_leaked_build_key_is_revoked_without_ever_having_been_pinned` |
| скомпрометирован корень | отзыв убивает всю цепочку | `test_revoked_root_key_kills_the_whole_chain` |
| просроченный сертификат | issued_at / expires_at | `test_expired_certificate_is_rejected` |
| подмена `keyid` в блоке | block.keyid == manifest.keyid | `test_keyid_swap_is_rejected` |
| пересылка в чате с новым именем | имя файла не участвует в проверке | `test_signature_survives_a_rename`, `test_real_file_renamed_by_a_chat_still_verifies` |
| **бандл:** поменять файл внутри архива | SHA-256 каждой записи | `test_edited_entry_is_rejected` |
| **бандл:** добавить запись в подписанный архив | сверка списка записей как множества | `test_injected_entry_is_rejected`, `test_every_real_bundle_signs_verifies_and_unpacks` |
| **бандл:** удалить запись | подписанная запись отсутствует | `test_dropped_entry_is_rejected` |
| **бандл:** два файла с одним именем | разводка парсеров: читают первый, исполняют второй | `test_two_entries_with_one_name_are_refused` |
| **бандл:** запись `../escape.py` | отказ до извлечения, дерево не трогается | `test_path_traversal_entry_is_refused`, `test_unpack_refuses_an_entry_that_escapes_the_dest` |
| **бандл:** symlink-запись | бракуется как класс файла | `test_symlink_entry_is_refused` |
| **бандл:** zip-бомба | лимиты записей и распакованного размера | `test_bombs_are_refused_by_the_limits` |
| **бандл:** подпись `.plugin` нацепить на архив и наоборот | `manifest.container` против реальных байтов | `test_single_file_signature_moved_onto_a_bundle_is_rejected`, `test_bundle_signature_moved_onto_a_plain_file_is_rejected` |
| **бандл:** переписать манифест за доверенным ключом | подпись блока в комментарии тоже под Ed25519 | `test_comment_replaced_with_a_forged_manifest_is_rejected` |
| **бандл:** сменить id/version в `meta.yml` | запись `meta.yml` в списке хэшей + scope сертификата | `test_certificate_must_cover_the_id_the_bundle_declares`, `test_bundle_version_downgrade_is_caught_by_expect_version` |

Запуск: `python -m pytest tests -q` → **88 passed**. Тесты на реальных файлах берут
`EXTERAGRAM_PLUGIN_DIR` (по умолчанию `~/Desktop/раб стол/plugin`) и `EXTERAGRAM_EAF_DIR`
(`~/Desktop/раб стол/coremanager` + `~/Desktop/раб стол/elyxbuild`) и сами скипаются, если папок нет:
там полный round-trip на 120 genuine-плагинах (каждый после подписи по-прежнему `ast.parse`-ится)
и на 8 настоящих `.eaf` (подпись -> проверка -> распаковка -> побайтовая сверка записей).

## 7. Ограничения — что система не обещает

* **Не песочница.** Подпись доказывает авторство и неизменность, а не безвредность: плагин от
  доверенного автора всё так же может делать `pre_request_hook` и читать переписку. Нужен отдельный
  permission-модельный слой.
* **Плохой автор остаётся плохим автором.** Отзыв — это локальный файл; пока пользователь не
  импортировал отзыв, старая подпись проходит. Окно отзывa = скорость распространения keyring.
* **`sealed_at` — доверие к часам автора**; это метка, а не неопровержимое время.
* **Комментарий zip конечен.** Блок подписи живёт в EOCD, где максимум 65535 байт: манифест очень
  большого бандла не влезет (при переподписи `pack` держим число записей в разумных пределах).
  Подпись бандла так же перезаписывает существовавший комментарий архива — чужие заметки не сохраняются.
* **Хэш контейнера ≠ якорь доверия.** Проверяются содержимое записей и `tree sha256`, а не байты `.eaf`:
  перепакованный тем же содержимым архив проходит проверку, и это осознанно (иначе подпись ломалась бы
  от любой распаковки). Сравнивать два файла «по хэшу файла» для бандлов нельзя.
* **Приватные ключи на диске открыты**, если не задан `--password`; для корня это обязательно
  (`keygen --password` даёт `ENCRYPTED` PEM, см. `test_passphrase_protected_root_key_signs_and_verifies`).

## 8. Команды

```bash
python -m pip install -e .                      # ставит exsig в PATH, или зовите python -m exsig

exsig keygen    --name @author --out keys [--password ***
exsig keygen    --name build-server --out keys
exsig cert-issue --root keys/@author.key --subject-pub keys/build-server.pub.json \
                --plugin-id extera_rpc --out extera_rpc.cert.json
exsig keyring   add --pub keys/@author.pub.json --note "author root" --show-fingerprint

exsig pack      ./extera_rpc --out extera_rpc.eaf [--root plugin]   # папка или одиночный .plugin
exsig sign      extera_rpc.plugin --key keys/build-server.key --cert extera_rpc.cert.json
exsig sign      extera_rpc.eaf    --key keys/build-server.key --cert extera_rpc.cert.json
exsig verify    extera_rpc.signed.plugin [--policy permissive] [--expect-id …] [--expect-version …] [--json]
exsig verify    extera_rpc.signed.eaf     # тот же путь кода: контейнер определяется по байтам
exsig unpack    extera_rpc.signed.eaf --dest installed/   # с отказом на ../, symlink, дублях, бомбах
exsig info      extera_rpc.signed.eaf     # разобрать блок и список записей без проверки
exsig strip     extera_rpc.signed.eaf     # снять блок, вернуть чистый payload (переподпись после ребилда)
exsig keyring   list | trust | revoke --keyid … | export
```

Без установки пакета: `python -m exsig …` из корня проекта.
keyring по умолчанию `~/.exsig/keyring.json`, переопределяется `--keyring` или `EXSIG_KEYRING`.
`sign` по умолчанию пишет копию `<имя>.signed.plugin` / `<имя>.signed.eaf`; исходник автора
трогается только с `--in-place`. `pack` не перетирает существующий архив без `--force`.

## 9. Структура

```
exsig/format.py    канонизация блока, директивы, AST-разбор метаданных без исполнения
exsig/keys.py      Ed25519, keyid/отпечаток, сертификаты-делегирования, keyring + tombstone-отзыв
exsig/archive.py   .eaf: pack/unpack, пофайловые хэши, комментарий zip, защита путей и лимитов
exsig/core.py      манифест, sign/verify для обоих контейнеров -> Result{status, exit_code}
exsig/cli.py       9 подкоманд, коды возврата 0/1/2/3, UTF-8-безопасный вывод
tests/             test_attacks.py (29) · test_sign_verify.py (10) · test_cli.py (14)
                   test_eaf.py (31, вкл. 8 реальных архивов) · test_real_plugins.py (4)
demo/run_demo.py   весь путь автора+хоста на настоящем .plugin и на собранном из него .eaf,
                   демо/transcript.txt (подпись -> проверка -> распаковка -> впрыск записи -> отзыв)
```
