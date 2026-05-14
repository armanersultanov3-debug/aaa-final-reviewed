# План закрытия открытых пунктов после обзора Codex (2026-05-14)

> **Контекст.** Обзор от 2026-05-14 выделил семь открытых пунктов (O-01 … O-07).
> Этот документ фиксирует решения по каждому из них и служит рабочим планом.
> Чекбоксы (`- [ ]`) — конкретные задачи, которые будут раскрыты при обсуждении.

**Источник анализа:** разбор Codex от 2026-05-14, привязки к `docs/roadmap.md`,
`docs/benchmarks-covering.md §9`, `docs/standards-roadmap.md`,
`docs/testing-real-world-configs.md`, `possibility_follow_up.md`.

---

## Сводка решений

| ID | Тема | Решение | PR |
| --- | --- | --- | --- |
| O-01 | Рост каталога safe-probe (STD-GAP-015) | реализовать (~30 правил одним батчем) | PR-3 |
| O-02 | Детектор ГОСТ TLS / RFC 9189 (STD-GAP-033) | **не реализовывать** | PR-1 (docs) |
| O-03 | Отложенные пробелы Nginx (Gixy: CRLF, SSRF, Host spoofing, alias) | реализовать (TaintAnalyzer + 5 правил) | PR-4 |
| O-04 | Хвост частично покрытых стандартов | HTTP/3 skip + IIS full inheritance + ECH docs | PR-1 (docs) + PR-5 (код) |
| O-05 | Traceability у Lighttpd (`source: LighttpdSourceSpan` для `LighttpdCondition`) | реализовать с инвариант-тестом | PR-2 |
| O-06 | Пакет отложенных вторичных стандартов | 9 отказов + ASVS V8/V11 (как побочный эффект) + CSF docs-блок | PR-1 (downgrade) + PR-6 (follow-ups) |
| O-07 | Вне области проекта (host-level, fuzzing, OOB, exploit chains) | **не реализовывать** | — |

Финальный порядок и зависимости — см. §«Порядок выполнения (финал)» в конце документа.

Плюс по итогам обзора есть отдельный блок «Расхождения документов» — описан в §«Документная синхронизация» в конце документа (входит в PR-1).

---

## O-01 — рост каталога safe-probe (STD-GAP-015)

**Решение:** реализовать. Одна поставка ~30 правил, перекрывающая четыре
тематические категории.

### Источник кандидатов

Базовый источник — `projectdiscovery/nuclei-templates` (директории
`http/exposures/` и `http/exposed-panels/`, лицензия MIT). Из шаблонов берём
только **сигнатуру**: путь, метод, body-matcher (если есть), MIME. Реализация
переводится в наш `SafePathRule`, в код проекта никакие YAML-файлы не
добавляются и зависимости от Nuclei не возникает.

Каждый кандидат проходит ручной фильтр на безопасность (см. «Hard safety
rules» ниже). Кандидаты, которые требуют запросов с побочными эффектами,
аутентификацию, или несколько шагов, отклоняются без обсуждения.

### Объём batch-2

Целевой размер: **~30 правил в одной поставке**, разделённые по четырём
категориям. Один PR проще ревьюить целиком, инфраструктура `SafePathRule`
уже зрелая, регрессионный риск низкий.

### Категории и состав

**A. Cloud / DevOps secrets — ~7 правил, severity high**

| rule_id (предложение) | Путь | Severity | Признак тела |
| --- | --- | --- | --- |
| `external.aws_credentials_exposed` | `/.aws/credentials` | high | секции `[profile]` + `aws_access_key_id` / `aws_secret_access_key` |
| `external.aws_config_exposed` | `/.aws/config` | medium | секции `[default]` или `[profile ...]` |
| `external.docker_config_exposed` | `/.docker/config.json` | high | поля `"auths"` или `"credsStore"` |
| `external.kube_config_exposed` | `/.kube/config` | high | поля `clusters:` + `contexts:` + `users:` |
| `external.ssh_private_key_exposed` | `/id_rsa`, `/id_ed25519`, `/id_ecdsa` | high | `-----BEGIN ... PRIVATE KEY-----` |
| `external.ssh_authorized_keys_exposed` | `/.ssh/authorized_keys` | medium | строки `ssh-rsa`/`ssh-ed25519`/`ecdsa-sha2-` |
| `external.gcp_service_account_exposed` | `/credentials.json` | high | `"type": "service_account"` + `"private_key": "-----BEGIN` |

**B. Spring Boot Actuator deepening — 5 правил**

| rule_id | Путь | Severity | Признак тела |
| --- | --- | --- | --- |
| `external.springboot_actuator_heapdump_exposed` | `/actuator/heapdump` | high | binary-matcher `JAVA PROFILE` (HPROF magic), либо `application/octet-stream` + размер |
| `external.springboot_actuator_threaddump_exposed` | `/actuator/threaddump` | medium | поля `"threadName"` / `"stackTrace"` |
| `external.springboot_actuator_configprops_exposed` | `/actuator/configprops` | medium | поля `"contexts"` + `"properties"` или `"beans"` |
| `external.springboot_actuator_beans_exposed` | `/actuator/beans` | low | поле `"beans"` |
| `external.springboot_actuator_mappings_exposed` | `/actuator/mappings` | low | поле `"mappings"` |

**C. Конфиги веб-фреймворков — ~7 правил, severity high/medium**

| rule_id | Путь | Severity | Признак тела |
| --- | --- | --- | --- |
| `external.rails_master_key_exposed` | `/config/master.key`, `/master.key` | high | строго 32 hex-символа, content-length ≤ 64 |
| `external.rails_credentials_yml_enc_exposed` | `/config/credentials.yml.enc` | medium | base64-блок (зашифровано, но факт раскрытия имени файла) |
| `external.rails_database_yml_exposed` | `/config/database.yml`, `/database.yml` | high | строки `adapter:` + `database:` |
| `external.drupal_settings_php_exposed` | `/sites/default/settings.php` | high | `<?php` + `$databases` |
| `external.magento_env_php_exposed` | `/app/etc/env.php` | high | `return array` + `'crypt'` или `'db'` |
| `external.joomla_configuration_php_exposed` | `/configuration.php` | high | `class JConfig` |
| `external.werkzeug_debug_console_exposed` | `/console` | high | `<title>Console</title>` + `Werkzeug` |

**D. Swagger/OpenAPI + CI/CD configs + старые VCS — ~11 правил, severity low**

| rule_id | Путь | Severity | Признак тела |
| --- | --- | --- | --- |
| `external.swagger_ui_exposed` | `/swagger-ui/`, `/swagger-ui.html` | low | `<title>Swagger UI</title>` или `swagger-ui-bundle.js` |
| `external.openapi_spec_exposed` | `/v2/api-docs`, `/v3/api-docs`, `/api-docs` | low | `"openapi": "3.` или `"swagger": "2.0"` |
| `external.gitlab_ci_yml_exposed` | `/.gitlab-ci.yml` | low | YAML с ключами `stages:` / `script:` / `image:` |
| `external.github_workflow_exposed` | `/.github/workflows/ci.yml` (плюс известные имена) | low | YAML с `on:` + `jobs:` + `runs-on:` |
| `external.travis_ci_exposed` | `/.travis.yml` | low | YAML с `language:` / `script:` |
| `external.jenkinsfile_exposed` | `/Jenkinsfile` | low | `pipeline {` или `node {` |
| `external.circleci_config_exposed` | `/.circleci/config.yml` | low | `version: 2` + `jobs:` |
| `external.dockerfile_exposed` | `/Dockerfile` | low | директива `FROM` + одно из `RUN`/`COPY`/`CMD` |
| `external.docker_compose_exposed` | `/docker-compose.yml`, `/docker-compose.yaml` | low | YAML с `services:` |
| `external.mercurial_metadata_exposed` | `/.hg/store/00manifest.i` или `/.hg/requires` | medium | для `requires` — текст `revlogv1`/`store`; для `00manifest.i` — без body-matcher, только accessible + path |
| `external.bazaar_metadata_exposed` | `/.bzr/branch/format` | medium | строка `Bazaar branch format` |

Итого: ~30 правил.

### Hard safety rules

Жёсткие правила безопасности зонда — соблюдаются на этапе ревью PR и
закрепляются в коде через типы `SafeProbeMethod` и сигнатуру `SafePathRule`:

1. **Метод запроса.** Только `GET` / `HEAD` / `OPTIONS`. Никаких `POST`,
   `PUT`, `PATCH`, `DELETE` — ни напрямую, ни через перенаправления.
2. **Без аутентификации.** Никаких заголовков `Authorization`, `Cookie`
   (кроме session-стороны нашего HTTP-клиента, если есть). Никаких
   client-side certificates.
3. **Никаких side-effect эндпойнтов.** Запрещены пути с известным эффектом
   даже на GET:
   - `/actuator/shutdown`, `/actuator/restart`, `/actuator/refresh`;
   - `/actuator/loggers/*` (изменение конфигурации логирования);
   - `/admin/*action*`, `/?action=`, `/?op=` и аналогичные.
4. **Body-matcher обязателен для severity > info.** Цель — отсеять
   SPA-fallback на `index.html`, WAF-страницы и кастомные 200 OK без
   реального содержимого.
5. **Без mass enumeration.** Каждая проба — один путь (или короткий
   массив явных вариантов). Никаких словарных перечислений.
6. **Без активных payloads.** Никакого SSRF, XSS, SQLi, path traversal
   в URL/параметрах. Это категория `external.*`, а не active scan.
7. **Размер ответа ограничен** существующей инфраструктурой
   `SensitivePathProbe` (read body prefix, не полный body) — это уже
   реализовано, требуется только не обходить.
8. **Server-aware подавление.** Если `ServerIdentification` совпадает с
   `suppress_when_identified` (см. существующий механизм для Apache
   `/server-status`), правило подавляется, чтобы не дублировать local-вывод.

### Стандарты и метаданные

Каждое правило в batch-2 обязано иметь явный список стандартов в `standards=`:
- `cwe(...)` — наиболее частые: 538 (File and Directory Information
  Exposure), 200 (Information Exposure), 306 (Missing Authentication for
  Critical Function), 312 (Cleartext Storage of Sensitive Information),
  522 (Insufficiently Protected Credentials).
- `owasp_top10_2021(...)` — преимущественно `A05:2021` (Security
  Misconfiguration), для secrets/credentials также `A07:2021`.
- `asvs_5(...)` — где применимо (V14 configuration, V8.3 sensitive data),
  с `coverage="partial"` если виден только косвенный признак.

ATT&CK / БДУ secondary-теги — НЕ добавляем индивидуально в правила
(остаются как topic-grouped в `docs/rule-coverage.md`, см. STD-GAP-026 / 032).

### Тестирование

- `tests/test_external_sensitive_paths.py` расширяется по той же схеме,
  что уже используется для существующих 30 правил:
  - happy-path: проба с подходящим body и accessible status → finding;
  - body-matcher негатив: тот же путь, чужой body → нет finding;
  - неподходящий статус (404/403): нет finding;
  - server-aware подавление, если применимо.
- Тесты обязаны проверять, что новое правило зарегистрировано в
  `RULE_REGISTRY` (тест `test_rule_coverage_doc.py` подхватит автоматически
  через `SAFE_PATH_RULE_METAS`).
- `docs/rule-coverage.md` обновляется в той же поставке: новые
  rule_id в external-секции + увеличенные счётчики (registry + docs).

### Задачи (чекбоксы для исполнителя)

- [ ] Curate Nuclei-кандидатов под четыре категории (A-D); зафиксировать
      перечень в виде комментариев в PR-описании.
- [ ] Расширить `src/webconf_audit/external/safe_probe_catalog.py` ~30 новыми
      `SafePathRule(...)` записями. Соблюсти текущий стиль и порядок `order=`
      продолжая нумерацию с `730+`.
- [ ] Для каждого новой `SafePathRule` написать happy-path и negative тесты
      в `tests/test_external_sensitive_paths.py`.
- [ ] Обновить external-секцию `docs/rule-coverage.md` (новые rule_id +
      stdcards-references).
- [ ] Обновить счётчики правил в `README.md`, `docs/architecture.md`,
      `docs/standards-roadmap.md`, `docs/benchmarks-covering.md`,
      `docs/rule-coverage.md`. Поправить `test_rule_coverage_doc.py
      :test_repeated_document_counters_match_registry` ожидания.
- [ ] Прогнать локально `ruff check .`, `pytest -q`,
      `webconf-audit list-rules --format json` и подтвердить новое число
      external-правил (=137 при +30 к текущим 107).
- [ ] В `docs/roadmap.md` перевести STD-GAP-015 из «Remaining active
      backlog» в `done` после landing PR.

---

## O-02 — детектор ГОСТ TLS / RFC 9189 (STD-GAP-033)

**Решение: не реализовывать.**

Обоснование:
- Реализация требует OpenSSL + GOST engine на стороне тестового стенда —
  лишняя инфраструктурная зависимость без подтверждённого спроса.
- В `docs/roadmap.md` пункт уже помечен как `blocked pending ИСПДн user feedback`,
  и такой обратной связи нет.
- ГОСТ-наборы в TLS — диагностика наличия, а не нарушение само по себе:
  ценность вывода без живого ИСПДн-кейса нулевая.

Эффект на репозиторий:
- Документировать как «closed: not pursued» в `docs/benchmarks-covering.md §9`
  (заменить статус `done (research)` на `not pursued — see plan 2026-05-14`).
- Удалить из «активного backlog» в `docs/roadmap.md`.
- Никаких изменений в `src/`.

---

## O-03 — отложенные пробелы Nginx (Gixy)

**Решение:** реализовать обязательно. Полный taint-анализ переменных,
5 новых правил, один PR. «Raw backend response» остаётся deferred.

### Архитектурное решение: полный taint-анализ

Закрытие 4 из 5 отложенных пунктов требует знания, какие переменные
**user-controlled** (могут быть подделаны атакующим). Делаем сразу
полный анализатор, не Phase-1.

**Новый модуль:** `src/webconf_audit/local/nginx/rules/_variable_taint_utils.py`.

Состав:

1. **Известные user-controlled литералы** — встроенный набор префиксов и
   имён, которые в Nginx гарантированно отражают вход пользователя:
   - `$arg_*`, `$args`, `$query_string`;
   - `$http_*`, `$cookie_*`;
   - `$request_uri`, `$request_body`, `$request_method`, `$request_filename`;
   - `$uri` — в host-части `proxy_pass` (контекстно-зависимо: для path
     это нормально, для scheme://host — нет).

2. **Класс `TaintAnalyzer`** — строится один раз на `ConfigAst`.
   Внутри хранит:
   - `set_assignments: dict[str, list[SetAssignment]]` — все `set $X
     <value>` директивы, привязанные к области видимости (http / server /
     location);
   - `map_definitions: dict[str, MapDef]` — `map $A $B { ... }` блоки;
     если входная переменная $A user-controlled, все значения $B,
     возникающие через её ветви, наследуют taint;
   - `geo`, `split_clients`: распознаём, но фиксируем как «не
     user-controlled» (источник — IP / random, а не вход);
   - кэш `Set[str]` посещённых имён в текущей резолюции — защита от
     рекурсивных цепочек `set $a $b; set $b $a;`.

3. **API:**

   ```python
   def is_user_controlled(
       var_name: str,
       scope: BlockNode | None,
       *,
       in_proxy_pass_host: bool = False,
   ) -> bool:
       ...
   ```

   - `scope=None` — глобальный (`http {}` уровень).
   - `in_proxy_pass_host=True` — добавляет `$uri` и `$request_uri` к
     набору user-controlled.

4. **Многошаговая резолюция:**
   - `proxy_pass http://$dest`, выше: `set $dest $arg_target` →
     `is_user_controlled("$dest", location_scope)` возвращает True;
   - `set $a $b; set $b $arg_x; proxy_pass http://$a` → True через
     рекурсивный обход цепочки;
   - `map $arg_role $backend { default upstream_a; admin upstream_b; }`
     + `proxy_pass http://$backend` → True (так как любое user-controlled
     значение в input mapping считается заражённым).

5. **Области видимости** — резолюция идёт от внутреннего к внешнему:
   `location → server → http`. Используется механика из существующего
   `_scope_utils.py` / `_value_utils.py` (если применимо) — без дубля.

6. **Исключения, фиксируемые в helper:**
   - `include` — содержимое уже встроено в AST через парсер (если так
     не работает — отдельный follow-up); taint не пересекает виртуальные
     границы файлов;
   - `geo`, `split_clients` — НЕ user-controlled;
   - `realip_remote_addr` / `binary_remote_addr` — НЕ user-controlled
     (это уже после Trusted-Proxy фильтрации, если она настроена).

**Тесты helper:** `tests/test_nginx_variable_taint.py` — отдельный набор,
покрывает:
- литералы user-controlled;
- 1-hop `set`;
- многошаговый `set`;
- `map` с user-controlled input;
- циклы `set $a $b; set $b $a;` — не виснет, возвращает False для не
  достижимого user-controlled;
- `geo` / `split_clients` — не считаются user-controlled;
- scope-resolution (location перекрывает server).

### Пять новых правил

| rule_id | Что ловит | Severity | Использует TaintAnalyzer |
| --- | --- | --- | --- |
| `nginx.crlf_in_return` | `return [code] <text\|url>` где text/url содержит user-controlled var. Без декодирования; учитывает кавычки. | high | да |
| `nginx.crlf_in_add_header` | `add_header NAME value` (включая `always`-форму) с user-controlled var в value. | high | да |
| `nginx.proxy_pass_user_controlled_destination` | `proxy_pass <url>` где user-controlled var попадает в **scheme/host**-часть URL (до третьего `/`). Path-часть НЕ flagged. | high | да (с `in_proxy_pass_host=True`) |
| `nginx.server_block_accepts_unknown_host` | server-блок без `server_name`, или `server_name _` / wildcard `*`, не отвергающий unknown Host (нет `return 444` / `ssl_reject_handshake on`). НЕ дублирует существующее `nginx.default_server_not_rejecting_unknown_hosts` — целевой случай противоположный: обычный (не-default) server без явного hostname-match. | medium | нет |
| `nginx.alias_traversal_classic_pattern` | `location /prefix` (без trailing slash) → внутри `alias /path/`. Классический Gixy `alias_traversal` shape. Дополняет существующее `nginx.alias_without_trailing_slash`. | medium | нет |

Дополнительные детали по каждому:

- **`crlf_in_return`.** Расположение finding-а — строка `return`, не
  `set`. Severity `high`. Стандарты: `cwe(113)` (HTTP Response
  Splitting), `owasp_top10_2021("A03:2021")` (Injection).

- **`crlf_in_add_header`.** Учитывает `add_header_value` интерполяцию.
  Для `Set-Cookie` и других чувствительных заголовков — та же severity
  high. Стандарты: `cwe(113)`, `owasp_top10_2021("A03:2021")`.

- **`proxy_pass_user_controlled_destination`.** Парсинг URL вручную:
  всё до первого `/` после `scheme://` — host:port. Если переменная
  в этой зоне — flag. `$uri` тоже считается user-controlled в этой
  позиции (через флаг `in_proxy_pass_host`). Стандарты: `cwe(918)`
  (SSRF), `owasp_top10_2021("A10:2021")`.

- **`server_block_accepts_unknown_host`.** Логика: server-блок «принимает
  unknown Host», если выполнено всё:
  1. Не `default_server` (это уже покрыто другим правилом);
  2. `server_name` отсутствует ИЛИ `server_name _` / `*.something`
     wildcard ИЛИ список включает `_`;
  3. Нет `if ($host !~ ...) { return 444; }` или эквивалента в этом блоке;
  4. В блоке есть `proxy_pass` / `root` / `alias` / прочая обработка
     (иначе блок безвреден).
  Стандарты: `cwe(346)` (Origin Validation Error),
  `owasp_top10_2021("A05:2021")`.

- **`alias_traversal_classic_pattern`.** Условие: `location /prefix`
  (без `/` в конце) + внутри `alias /path/` (с `/` в конце). Это
  классический shape, описанный в Gixy README. Severity `medium`,
  совпадает с уровнем существующего `alias_without_trailing_slash`.
  Стандарты: `cwe(22)` (Path Traversal),
  `owasp_top10_2021("A01:2021")`.

### Что НЕ берём в этой итерации

- **Raw backend response reading** (`proxy_intercept_errors off` +
  отсутствие `error_page`). Остаётся `research / deferred`. Возвращаемся,
  когда появится конкретная fixture с подтверждённым false negative.
- **Open redirect через `return 30X $var`** — это перекрывается с
  CRLF-правилом частично; отдельное правило вводить не будем, чтобы
  не дублировать find-ы.
- **`rewrite REGEX REPLACEMENT [FLAG]` CRLF.** Реже встречается как
  security-sensitive (Nginx сам декодирует `%0D%0A` в `rewrite` иначе,
  чем в `return`). Откладываем до конкретной fixture.

### Стандарты и метаданные

Каждое правило обязано иметь `standards=` с минимум CWE + OWASP Top 10
2021 + ASVS V5 (Validation, Sanitization, Encoding) для CRLF/SSRF, плюс
ATT&CK / БДУ secondary-tag через topic-grouped блок в
`docs/rule-coverage.md` (не индивидуально на правиле).

### Fixtures и тесты

**Существующие fixtures** (`tests/fixtures/webserver-configs/`) уже
содержат vulhub CRLF и alias-traversal кейсы с пометкой «reference gap».
После PR — они переходят в «expected findings»:

- `tests/fixtures/webserver-configs/metadata/cases.json` — поправить
  `coverage_notes` и добавить `expected_findings` для соответствующих
  фикстур.
- Дополнить fixtures своими minimal-кейсами для:
  - SSRF через `proxy_pass http://$arg_target`;
  - SSRF через 1-hop `set $b $arg_t; proxy_pass http://$b`;
  - SSRF через `map` — `map $arg_role $b { ... } proxy_pass http://$b`;
  - Host spoofing — обычный server без `server_name`, с `proxy_pass`;
  - Negative-case для каждого правила (та же директива без user-controlled
    var → нет finding).

**Новые тестовые файлы:**
- `tests/test_nginx_variable_taint.py` — unit-тесты helper-а.
- `tests/test_nginx_crlf_response_splitting.py` — CRLF-правила.
- `tests/test_nginx_proxy_pass_ssrf.py` — SSRF.
- `tests/test_nginx_host_validation.py` — host spoofing.
- Расширение `tests/test_nginx_alias_rules.py` (или существующего
  alias-теста, если такой есть) — classic Gixy pattern.

### Стратегия PR

Один PR (`feat(nginx): close Gixy parity gaps`), порядок коммитов:
1. Helper `_variable_taint_utils.py` + unit-тесты — должны быть зелёные сами по себе.
2. `nginx.crlf_in_return` + тесты.
3. `nginx.crlf_in_add_header` + тесты.
4. `nginx.proxy_pass_user_controlled_destination` + тесты.
5. `nginx.server_block_accepts_unknown_host` + тесты.
6. `nginx.alias_traversal_classic_pattern` + тесты.
7. Обновление `cases.json` (фикстуры → expected findings).
8. Обновление документации и счётчиков.

Каждый коммит должен оставлять `pytest -q` зелёным.

### Задачи (чекбоксы для исполнителя)

- [ ] Реализовать `src/webconf_audit/local/nginx/rules/_variable_taint_utils.py`
      по описанной спецификации (TaintAnalyzer + `is_user_controlled`).
- [ ] Написать `tests/test_nginx_variable_taint.py` с покрытием всех
      перечисленных кейсов резолюции.
- [ ] Реализовать 5 правил в `src/webconf_audit/local/nginx/rules/`.
      Order-номера: продолжить за текущим максимумом для местных правил.
- [ ] Написать тесты для каждого правила (happy + negative + scope).
- [ ] Добавить minimal-fixtures под SSRF (1-hop, multi-hop, map) и host
      spoofing в `tests/fixtures/webserver-configs/`.
- [ ] Обновить `cases.json`: vulhub CRLF + alias case-ы переводятся из
      `coverage_notes` в `expected_findings`.
- [ ] Обновить `docs/testing-real-world-configs.md`: убрать четыре
      пункта из «Deferred rule candidates», оставив только raw backend
      response.
- [ ] Обновить `docs/rule-coverage.md` — новые rule_id, ASVS V5 теги.
- [ ] Обновить счётчики правил во всех документах и
      `test_rule_coverage_doc.py`. Ожидаемо: Nginx 85 → 90.
- [ ] В `docs/roadmap.md` отметить deferred Nginx gaps как закрытые
      (раздел про reference gaps).
- [ ] Прогнать локально `ruff`, `pytest -q`, `list-rules`.

---

## O-04 — хвост частично покрытых стандартов

**Решение:** выполнить. Основная работа — полная цепочка наследования IIS.
HTTP/3 и ECH остаются документационными решениями. Всё одним PR.

### Подпункт 1: HTTP/3 (CIS Nginx §4.1.12) — skip с расширенным обоснованием

**Решение: не реализовывать в этой итерации.**

Обоснование, которое пишем в `docs/rule-coverage.md:379` вместо текущей
короткой заметки:

> HTTP/3 detection остаётся deferred. Возможные формы (`listen ... quic`
> + Alt-Svc валидация или модернизационный «TLS без QUIC») недостаточно
> ценны для текущего набора пользователей: HTTP/3 не является широко
> развёрнутым в production-средах, мониторинг которых сейчас в фокусе
> проекта; Alt-Svc валидация даёт операционный, а не security-сигнал, а
> модернизационный nudge — мнение, не bug. Возвращаемся к вопросу,
> когда (а) появятся реальные user-кейсы с QUIC-настроенным Nginx без
> Alt-Svc, ИЛИ (б) появится CIS-обновление, где HTTP/3 становится
> обязательным элементом baseline.

Эффект: одна строка docs, никаких изменений в коде.

### Подпункт 2: IIS — полная цепочка наследования

**Решение:** реализовать полную модель
`machine.config → applicationHost.config → web.config (+ <location>)`
с учётом атрибута `inheritInChildApplications`.

#### Текущее состояние

Уже есть:
- `src/webconf_audit/local/iis/_iis_schema/` — официальные XSD-схемы
  (IIS_schema.xml, ASPNET_schema.xml, FX_schema.xml) с default-значениями
  атрибутов;
- `src/webconf_audit/local/iis/iis_defaults.py` (167 LoC) — частичная
  материализация defaults для абсентных секций;
- `src/webconf_audit/local/iis/effective.py` (550 LoC) — effective-view
  helpers, частично применяемые в IIS-правилах;
- `src/webconf_audit/local/iis/discovery.py` (323 LoC) — поиск конфигов,
  включая multi-file сценарии.

Что не покрыто полноценно:
1. **Многоуровневое наследование.** Сейчас существующие правила
   обращаются преимущественно к `web.config`. `applicationHost.config`
   читается частично; цепочка `machine.config → applicationHost.config`
   формализована только через embedded schema defaults.
2. **`<location>` element precedence.** В `applicationHost.config` и
   `web.config` элемент `<location path="...">` точечно переопределяет
   настройки для указанного пути; текущий effective-layer этим не
   занимается.
3. **`inheritInChildApplications`.** Атрибут на `<location>`-блоке
   (`inheritInChildApplications="false"`), который ОТКЛЮЧАЕТ каскадирование
   в дочерние приложения. Не учитывается.

#### Что строим

**Новый/расширенный модуль:**
`src/webconf_audit/local/iis/_iis_inheritance.py` (либо расширение
`effective.py`, если суммарная длина остаётся управляемой).

**Каноническая версия .NET:** фиксируем **.NET Framework 4.8** как
референс default-значений. Это последний LTS Windows Server feature
release; defaults стабильны и хорошо документированы. Внутри schema
xml эти defaults уже представлены.

> Если в будущем понадобится другая версия (например, .NET 4.5 для
> legacy IIS 8.5), вводим параметр; сейчас одно фиксированное значение.

**Effective-view API:**

```python
@dataclass(frozen=True, slots=True)
class IisEffectiveSettings:
    forms_auth: FormsAuthSettings
    machine_key: MachineKeySettings
    request_filtering: RequestFilteringSettings
    http_cookies: HttpCookiesSettings
    application_pool: AppPoolSettings
    schannel: SchannelSettings
    # ... etc.
    source_breadcrumbs: dict[str, SourceLocation]  # откуда пришло каждое значение

def compute_effective_iis_settings(
    machine_defaults: MachineDefaults,
    app_host: ApplicationHostConfig | None,
    web_config: WebConfig | None,
    location_path: str | None = None,
) -> IisEffectiveSettings: ...
```

`source_breadcrumbs` важен: даёт finding-у точную ссылку, *откуда*
именно пришло опасное значение (например, «default из IIS_schema.xml»
vs «explicit в web.config:42»).

**Правила наследования (порядок применения, перекрывающие позже):**
1. `machine.config` defaults (из embedded schema, версия 4.8).
2. `applicationHost.config` (если есть файл).
3. `web.config` site-level (если есть).
4. `web.config` application-level (если site содержит вложенные
   приложения).
5. `<location path="X">` блоки (на любом уровне) — применяются к точному
   path или его потомкам.
6. `inheritInChildApplications="false"` — обрывает наследование в потомков.

**Адаптация существующих partial-правил:**

Все строки из таблицы `docs/rule-coverage.md:1019-1030`, помеченные
`partial`, проверяются на честность через новый effective-view:

| CIS section | Текущее состояние | Цель |
| --- | --- | --- |
| §1.4/§1.5/§1.6 (app-pool) | partial | covered через `compute_effective_iis_settings(...).application_pool` |
| §2.1/§2.2 (anonymous/auth) | partial | covered |
| §2.5/§2.7/§2.8 (forms auth) | partial | covered |
| §3.x (cookies, machine key, trust, server header) | partial | covered |
| §4.2/§4.3/§4.7/§4.9/§4.10 (request filtering, file ext, ISAPI) | partial | covered |
| §7.1-§7.12 (SChannel) | partial | **остаётся partial** (см. ниже) |

**SChannel — почему остаётся partial.** SChannel protocols/ciphers
живут в **реестре Windows** (`HKLM\SYSTEM\CurrentControlSet\Control\
SecurityProviders\SCHANNEL\...`), а не в IIS-конфигах. Текущие правила
(`iis.schannel_*`) уже работают на registry-экспортах. Глубина
inheritance к этой группе неприменима. Пишем явный комментарий в
`rule-coverage.md`: «SChannel evidence is registry-based; web-config
inheritance does not apply».

**Возможные новые rule_id (не обязательно — зависит от того, какие
кейсы пропускают существующие правила после перехода на effective-view):**

| Возможный rule_id | Когда фиксируем | Severity |
| --- | --- | --- |
| `iis.inheritance_chain_unsafe_default` | Эффективное значение опаснее, чем web.config полагает (наследование откуда-то выше внесло unsafe) | medium |
| `iis.location_overrides_unsafely` | `<location>` в applicationHost.config переопределяет site-level настройку небезопасным значением | medium |
| `iis.inherit_in_child_applications_disabled_unsafely` | `inheritInChildApplications="false"` отключает важную security-настройку для дочерних приложений | low |

Эти три rule_id — заготовки. Решение «вводим / не вводим» принимаем
**после** реализации effective-view: если все existing-partial случаи
закрылись существующими правилами, новые rule_id не нужны. Это
исследовательский результат, не план-обязательство.

**Тесты:**

`tests/test_iis_inheritance.py` — новый файл, unit-тесты на
effective-view:
- Только machine defaults — `IisEffectiveSettings` совпадает с
  ожидаемой baseline-таблицей (.NET 4.8).
- machine + applicationHost — applicationHost перекрывает.
- machine + applicationHost + web.config — web.config выигрывает.
- `<location path="/api">` точечно перекрывает только для `/api/*`.
- `inheritInChildApplications="false"` — child application не получает
  родительскую настройку.
- Конфликт `<location>` в двух разных файлах — побеждает более
  глубокий.
- Breadcrumbs корректны на каждом уровне.

Регрессионные тесты существующих IIS правил остаются зелёными после
миграции на effective-view (важная приёмка: ни один currently-passing
тест не должен сломаться).

### Подпункт 3: ECH — только docs

**Решение:** docs-only.

Обновляем `docs/standards-roadmap.md:346-348`, добавляя триггер
пересмотра:

> ECH stays documented as a probe limitation. The current safe external
> probe stack does not evaluate ECH portably, and the project should not
> invent a noisy «ECH missing» finding. Reconsider when (a) OpenSSL ≥ 3.5
> stable with ECH support is mainstream AND (b) DNS-based ECHConfig
> discovery (RFC 9460 SVCB/HTTPS records) becomes part of the safe-probe
> infrastructure.

Эффект: одна правка docs, никаких изменений в коде.

### Стратегия PR

Один PR (`feat(iis): full inheritance chain + roadmap closures`), порядок
коммитов:
1. Документационные подпункты — обновления `rule-coverage.md`
   (HTTP/3 rationale) и `standards-roadmap.md` (ECH триггер). Должны
   landingиться первыми, чтобы остальной diff не тянул их.
2. IIS effective-view core: `_iis_inheritance.py` + типы
   `IisEffectiveSettings` + unit-тесты в изоляции (без миграции правил).
3. Поэтапная миграция групп IIS правил на effective-view:
   - §1.4-§1.6 (app-pool);
   - §2.1-§2.8 (anonymous, forms);
   - §3.x (cookies, machine key, trust level, server header);
   - §4.x (request filtering, file ext, ISAPI).
4. (Опционально) три новых rule_id (`iis.inheritance_chain_unsafe_default`,
   `iis.location_overrides_unsafely`,
   `iis.inherit_in_child_applications_disabled_unsafely`), если по
   результатам шага 3 видны не-покрытые кейсы.
5. Обновление `docs/rule-coverage.md`: 6 строк IIS partials → covered,
   §7.x остаётся partial с явным комментарием.
6. Обновление счётчиков IIS, если число правил изменилось.

Каждый коммит оставляет `pytest -q` зелёным. Регрессионные тесты на
existing IIS правила — обязательная сетка безопасности при миграции.

### Задачи (чекбоксы для исполнителя)

- [ ] Обновить `docs/rule-coverage.md:379` (HTTP/3 rationale) расширенным
      обоснованием. Один commit.
- [ ] Обновить `docs/standards-roadmap.md:346-348` (ECH триггер пересмотра).
      Тот же commit или отдельный — на выбор.
- [ ] Реализовать `IisEffectiveSettings` + `compute_effective_iis_settings`
      в `src/webconf_audit/local/iis/_iis_inheritance.py` (либо расширить
      существующий `effective.py`).
- [ ] Написать `tests/test_iis_inheritance.py` с покрытием всех уровней
      наследования (см. список выше). Тесты должны проходить до миграции
      существующих правил.
- [ ] Мигрировать IIS правила групп §1.4-§1.6, §2.1-§2.8, §3.x, §4.x на
      effective-view. Регрессионные тесты должны оставаться зелёными
      на каждом шаге.
- [ ] По результатам миграции принять решение, нужны ли три новых
      rule_id (опциональные). Зафиксировать в PR-описании.
- [ ] Обновить `docs/rule-coverage.md` IIS gap-таблицу: 6 строк partials
      → covered. §7.x SChannel остаётся partial с комментарием про registry.
- [ ] Обновить счётчики IIS в README/architecture/standards-roadmap/
      benchmarks-covering/rule-coverage если число правил изменилось.
      Поправить `test_rule_coverage_doc.py` ожидания.
- [ ] Прогнать локально `ruff`, `pytest -q`, `list-rules`. Подтвердить,
      что число правил консистентно во всех документах.
- [ ] В `docs/roadmap.md` отметить O-04 пункты как закрытые.

---

## O-05 — traceability у Lighttpd

**Решение:** выполнить полностью. Required-поле `source` на
`LighttpdCondition`, миграция всех правил, работающих с условными
блоками, на `condition.source`, плюс инвариант-тест.

### Контекст и происхождение задачи

Источник — `possibility_follow_up.md` (заметка CodeRabbit к предыдущему
PR). Конкретный сайт-симптом: в
`src/webconf_audit/local/normalizers/lighttpd_normalizer.py:426`
получается:

```python
source_span = ssl_engine.source if ssl_engine else LighttpdSourceSpan()
```

Когда в `$SERVER["socket"] == ...` нет `ssl.engine` директивы (например,
plain HTTP-listen), normalizer создаёт listen point с **пустым**
source — line/file_path = None. Это ломает report-precision: finding
указывает на listen point без позиции в файле.

Причина: текущая `LighttpdCondition` ([parser.py:14-18](src/webconf_audit/local/lighttpd/parser/parser.py:14))
— frozen dataclass с тремя полями `variable / operator / value` и без
source. Хотя `_parse_block_header()` уже знает `line` и `file_path`,
эта информация дальше не пробрасывается в `_parse_condition()`.

### Архитектурное решение

**Поле `source` — required, без default.**

```python
@dataclass(frozen=True, slots=True)
class LighttpdCondition:
    variable: str
    operator: str
    value: str
    source: LighttpdSourceSpan
```

Обоснование: type-safe, исключает silent regression. Цена — миграция
~15 мест в трёх тестовых файлах (`test_normalizer_lighttpd.py`,
`test_local_lighttpd.py`, `test_lighttpd_conditions.py`). Это
разовая работа на 15 минут.

`LighttpdSourceSpan` — тот же тип, что уже используется на `BlockNode`
/ `DirectiveNode` / `AssignmentNode`. Поля `file_path: str | None`,
`line: int | None`. Не вводим новый тип — однородность модели важнее.

### Что меняется в коде

1. **`src/webconf_audit/local/lighttpd/parser/parser.py`**:
   - Добавить поле `source: LighttpdSourceSpan` в `LighttpdCondition`
     (без default).
   - Пробросить `line` и `file_path` через сигнатуру `_parse_condition()`:

     ```python
     def _parse_condition(
         header: str,
         *,
         line: int | None = None,
         file_path: str | None = None,
     ) -> LighttpdCondition | None:
     ```

   - В `_parse_block_header()` (там, где сейчас есть `line` и
     `file_path` параметры) — передать их в оба вызова
     `_parse_condition()`.
   - В `LighttpdCondition(...)` конструкции в `_parse_condition()` —
     заполнить `source=LighttpdSourceSpan(file_path=file_path, line=line)`.

2. **`src/webconf_audit/local/normalizers/lighttpd_normalizer.py:426`**:

   ```python
   source_span = ssl_engine.source if ssl_engine else condition.source
   ```

3. **Тесты** (3 файла):
   - `tests/test_lighttpd_conditions.py` — добавить `source` в каждый
     `LighttpdCondition(...)`. В юнит-тестах допустимо
     `source=LighttpdSourceSpan()` (line=None, file_path=None), но
     лучше явно указать тестовую позицию для читаемости.
   - `tests/test_normalizer_lighttpd.py` — аналогично + добавить тест,
     проверяющий, что socket-condition без `ssl.engine` теперь даёт
     listen point с заполненным `source.line`.
   - `tests/test_local_lighttpd.py` — миграция конструкций.

### Migration сторонних мест

После изменений нужно пройтись по правилам, использующим
`LighttpdConditionalScope.condition` или работающим с условными блоками
напрямую. Из grep по `condition`:

- `src/webconf_audit/local/lighttpd/rules/rule_utils.py`
- `src/webconf_audit/local/lighttpd/rules/mod_status_public.py`
- `src/webconf_audit/local/lighttpd/rules/missing_http_method_restrictions.py`
- `src/webconf_audit/local/lighttpd/effective.py`

В каждом из них нужно проверить: когда finding создаётся внутри
условного блока, какой `source` использован?
- Если `block.source` (строка открывающей `{`) — мигрируем на
  `condition.source` (строка самого `$HTTP[...]==...`).
- Если уже используется directive's `source` — оставляем, это и так
  точнее.

Список конкретных правил для миграции зафиксируется по PR-описанию
по результатам аудита.

### Инвариант-тест

Новый тест-сторож `tests/test_lighttpd_condition_traceability.py`:

```python
def test_all_conditional_findings_point_at_condition_line(
    all_lighttpd_fixtures,
) -> None:
    """
    For every fixture and every rule, if a finding is emitted inside a
    conditional block, its location.line must equal the condition.source.line,
    not the block.source.line (where `{` is).
    """
```

Реализация:
1. Прогнать все правила Lighttpd на всех Lighttpd-фикстурах.
2. Для каждого finding проверить: попадает ли его line в диапазон
   `[block_open_line, block_close_line]` какого-нибудь условного блока?
3. Если да — line должен совпадать с `condition.source.line` этого
   блока, **или** с line какой-то конкретной директивы внутри блока
   (тогда правило указывает на саму директиву, не на условие — это
   тоже корректно и точнее).
4. Запрещено: line == `block.source.line` (открывающая `{`).

Это сторож против будущих регрессий: если кто-то добавит правило,
которое возвращает `block.source` для conditional-блока, тест упадёт.

### Acceptance criteria

- [ ] Все существующие Lighttpd тесты остаются зелёными после миграции.
- [ ] `LighttpdCondition(...)` без `source` — ошибка типизации (mypy /
      ruff поймают).
- [ ] Listen point из `$SERVER["socket"]` без `ssl.engine` теперь имеет
      `source.line` ≠ None в normalizer-выводе.
- [ ] Инвариант-тест зелёный на всех Lighttpd фикстурах.
- [ ] Никакого изменения сигнатур публичного API за пределами
      добавленного поля и пробрасываемых параметров parser-а.

### Стратегия PR

Один маленький PR (`refactor(lighttpd): add condition source span +
migrate conditional rules to it`), порядок коммитов:

1. Добавить `source` к `LighttpdCondition` + пробросить line/file_path
   через parser. Мигрировать существующие тесты на новый конструктор.
   На этом коммите все тесты должны быть зелёными (новое поле просто
   заполняется парсером; ни один rule пока не использует).
2. Поправить normalizer (`_listen_point_from_socket_condition`) +
   тест на listen point без `ssl.engine`.
3. Миграция правил на `condition.source` (по списку из аудита).
4. Добавить инвариант-тест `test_lighttpd_condition_traceability.py`.
5. Обновить `possibility_follow_up.md` — удалить CodeRabbit-задачу,
   потому что она закрыта.

### Задачи (чекбоксы для исполнителя)

- [ ] Добавить required `source: LighttpdSourceSpan` к `LighttpdCondition`
      в `parser.py`. Заполнить parser-логику.
- [ ] Мигрировать 3 тестовых файла (`test_normalizer_lighttpd.py`,
      `test_local_lighttpd.py`, `test_lighttpd_conditions.py`) — добавить
      source во все ручные `LighttpdCondition(...)` конструкции.
- [ ] Обновить `_listen_point_from_socket_condition()` — fallback на
      `condition.source` вместо пустого span.
- [ ] Добавить регрессионный тест: listen point без `ssl.engine` имеет
      `source.line` ≠ None.
- [ ] Провести аудит правил `rule_utils.py`, `mod_status_public.py`,
      `missing_http_method_restrictions.py`, плюс `effective.py`.
      Зафиксировать список правил для миграции в PR-описании.
- [ ] Мигрировать правила: где finding в conditional блоке использует
      `block.source` — заменить на `condition.source` (или на source
      конкретной директивы, если он точнее).
- [ ] Реализовать инвариант-тест
      `tests/test_lighttpd_condition_traceability.py` по описанной
      спецификации.
- [ ] Удалить CodeRabbit-заметку из `possibility_follow_up.md`
      (или пометить «закрыто, см. PR …»).
- [ ] Прогнать локально `ruff`, `pytest -q`, `list-rules`.

---

## O-06 — пакет отложенных вторичных стандартов

**Решение: частичное.**

Из десяти отложенных идентификаторов **ничего не берём в канон** в текущей итерации,
кроме одного — STD-GAP-037 (ASVS V8/V11 deepening), который реализуем как
побочный продукт O-03 / O-05 (расширение парсера автоматически даёт более
глубокое ASVS-покрытие).

### Решения по каждому стандарту

| ID | Стандарт | Решение | Обоснование |
| --- | --- | --- | --- |
| STD-GAP-017 | NIST SP 800-53 Rev. 5 | не брать | Дубликат поверх OWASP / PCI / ФСТЭК; нет US-федеральной аудитории. Маппинг сохранён в `benchmarks-covering.md §5.2` — можно подключить позже за день, без переделок. |
| STD-GAP-018 | NIST SP 800-44 Rev. 2 | не брать (окончательно) | Документ устарел (2007), полностью поглощён 800-52 / 800-53. |
| STD-GAP-019 | NIST SP 800-63B | не брать | Application-layer (вход пользователя, MFA); видимая на уровне сервера часть уже покрыта SC-23 / IA-5 из 800-53. |
| STD-GAP-020 | NIST CSF 2.0 | не брать как теги; docs-only сводка | На уровне правил CSF даёт один и тот же тег на длинных группах. Делаем отдельный topic-grouped блок «CSF 2.0 alignment» в `docs/rule-coverage.md` — дешёво, без шума на правилах. |
| STD-GAP-022 | CIS Critical Security Controls v8.1 | не брать | Дубликат уже покрытых CIS Benchmarks. |
| STD-GAP-023 | HIPAA Security Rule | не брать | US healthcare — нет аудитории, покрытие косвенное. |
| STD-GAP-025 | BSI IT-Grundschutz APP.3.2 | не брать | DACH-аудитории нет. Если появится — маппинг ложится на CIS Benchmarks без переделок. |
| STD-GAP-028 | OWASP API Security Top 10 (2023) | не брать как стандарт | Большая часть пунктов — application layer. Когда сделаем O-03, добавим одну сноску «вторичное соответствие OWASP API #7 (SSRF)» в `rule-coverage.md`. |
| STD-GAP-034 | ГОСТ Р 57580.1-2017 | не брать | Российский финтех не в целевой аудитории. Делегирующие требования уже покрыты ISO 27002 (STD-GAP-024) и ФСТЭК «Меры ГИС» (STD-GAP-031). |
| STD-GAP-037 | ASVS V8 / V11 deepening | **взять — как побочный эффект O-03 / O-05** | Тип gap-а — `parser-depth`. Та же глубина парсера, которая нужна для taint-модели O-03 и для source-span O-05, автоматически открывает V8 (data protection в логах / заголовках) и V11 (redirect / method abuse). Реализация — теги поверх правил, без отдельной парсерной работы. |

### Задачи

- [ ] Перевести в `docs/benchmarks-covering.md §9` статус девяти отказных
      идентификаторов из `deferred / —` в `closed — not pursued (plan 2026-05-14)`.
      Оставить столбец `Candidate work` как историческое обоснование.
- [ ] STD-GAP-020 (CSF 2.0): добавить docs-only блок «NIST CSF 2.0 alignment»
      в `docs/rule-coverage.md` (как `STD-GAP-026` / `STD-GAP-032`: topic-grouped,
      не колонка, не `StandardReference`). Объём — одна врезка ~30 строк.
- [ ] STD-GAP-028 (OWASP API Top 10): после закрытия SSRF из O-03 добавить
      одну строчку «вторичное соответствие API7:2023 SSRF» к правилу
      `nginx.proxy_pass_user_controlled_destination`.
- [ ] STD-GAP-037 (ASVS V8/V11): после landing O-03 / O-05 добавить
      ASVS-теги к новым правилам и обновить блок ASVS в `docs/rule-coverage.md`.
- [ ] Обновить `docs/roadmap.md`: убрать перечисленные STD-GAP-* из
      «Deferred or out-of-scope decisions» в `closed (not pursued)`.

### Что НЕ делаем

- Не вводим новые типизированные хелперы стандартов в `src/webconf_audit/standards.py`
  для отказанных стандартов.
- Не добавляем `StandardReference` к правилам для STD-GAP-017/018/019/022/023/025/034.

---

## O-07 — вне области проекта

**Решение: не реализовывать.**

Подтверждаем границу проекта: host-level inspection, fuzzing, payload-based
сканирование, OOB-проверки, цепочки эксплойтов — за рамками. Никаких изменений
не требуется; формулировка в `docs/roadmap.md` уже корректна.

---

## Документная синхронизация (расхождения)

Обзор Codex выявил четыре места, где документация разошлась с кодом / статусом.
Эти правки дешёвые и независимые от остальной работы — закроем первой партией.

- [ ] `docs/superpowers/plans/2026-05-04-effective-scope-fixes.md`:
      все чекбоксы помечены открытыми, хотя `needfix.md:12` рапортует «closed».
      Закрыть чекбоксы (или пометить план как `superseded`).
- [ ] `docs/standards-roadmap.md:60`: «IIS / Lighttpd auth normalization
      deferred to PR-08b» — фактически уже сделано (есть
      `tests/test_normalized_auth_locations_iis_lighttpd.py`). Переписать строку
      на `done`.
- [ ] `docs/architecture.md:258`: «Nginx tokenizer не поддерживает single quotes» —
      устарело, тесты single-quoted args присутствуют в
      `tests/test_nginx_tokenizer.py:146`. Переписать формулировку.
- [ ] `demo/local_admin/README.md:303`: счётчики findings (4/19/16/20)
      устарели; локальный прогон сейчас даёт 9/39/28/52. Обновить.

---

## Порядок выполнения (финал)

**Режим:** последовательный, 6 PR подряд. Без параллельной работы — это
гарантирует, что счётчики правил во всех документах и
`test_rule_coverage_doc.py:test_repeated_document_counters_match_registry`
всегда консистентны после каждого мержа.

### Зависимости

Реальная зависимость одна: PR-6 (O-06 follow-ups: OWASP API #7 SSRF tag,
ASVS V8/V11 теги) ждёт landing’а PR-3 (новый `proxy_pass` SSRF rule_id)
и PR-4 (новые external rule_id из O-01). Всё остальное независимо по
модулям.

### Очередь PR

| № | PR | Содержание | Cost | Risk | Оценка |
| --- | --- | --- | --- | --- | --- |
| 1 | `docs: sync after 2026-05-14 review` | 4 расхождения Codex + HTTP/3 rationale (O-04) + ECH trigger (O-04) + downgrade 9 stds (O-06) + убрать STD-GAP-033 из active backlog (O-02) | S | 0 | ~1 час |
| 2 | `refactor(lighttpd): condition source span + traceability invariant` | O-05 полностью | S | низкий | 0.5-1 день |
| 3 | `feat(external): safe-probe batch-2 (~30 rules)` | O-01 полностью | M | низкий | 1-2 дня |
| 4 | `feat(nginx): Gixy parity (taint analyzer + CRLF/SSRF/Host/alias)` | O-03 полностью | L | средний | 3-5 дней |
| 5 | `feat(iis): full inheritance chain (machine → applicationHost → web.config + <location>)` | O-04 код-часть | L | средний-высокий | 4-7 дней |
| 6 | `docs: standards alignment follow-up (CSF, OWASP API, ASVS V8/V11)` | O-06 follow-ups (CSF docs-блок, OWASP API #7 SSRF tag, ASVS V8/V11 теги) | S | 0 | 2-3 часа |

### Почему именно этот порядок

- **PR-1 первым.** Все docs выровнены до начала кодовой работы. Нулевой
  риск, быстрая победа, чистый базис для последующих PR.
- **PR-2 вторым.** Маленький рефакторинг с инвариант-тестом — даёт
  уверенность в инструментах precision-проверки до того, как мы
  начинаем добавлять новые правила.
- **PR-3 третьим.** Полностью аддитивный: 30 новых external правил, ноль
  изменений в парсере и существующих модулях. Простой ревью, никаких
  взаимодействий с другими PR.
- **PR-4 четвёртым.** Большой парсерный блок (новый TaintAnalyzer +
  5 правил). Берёмся после трёх «зелёных» PR — momentum и docs стабильны.
- **PR-5 предпоследним.** Самый сложный и рискованный: IIS inheritance
  трогает 6 групп существующих правил. Хочется landing’а, когда все
  остальные PR уже в `master`, чтобы regression-сетка была максимально
  широкой и не было merge-конфликтов.
- **PR-6 последним.** Зависит от PR-3 (новые external rule_id для
  ASVS-тегов) и PR-4 (новый SSRF rule_id для OWASP API #7 тега).

### Acceptance gate каждого PR

Перед мержем каждого PR обязательно:
- `ruff check .` — зелёное;
- `pytest -q` — зелёное (без `--ignore`);
- `webconf-audit list-rules --format json` — отдаёт ожидаемое число
  правил;
- `test_rule_coverage_doc.py:test_repeated_document_counters_match_registry`
  — зелёное (счётчики в README / architecture / standards-roadmap /
  benchmarks-covering / rule-coverage в синхронности).

### Итоговая оценка трудозатрат

Суммарно ~2-3 рабочие недели sequential, с учётом ревью и доработок.
Из них на парсерные и архитектурные блоки (PR-4 + PR-5) приходится
большая часть — ~70% времени.
