# Пробитие DPI: практические знания (zapret2 / nfqws2)

> Дистиллят, добытый эмпирически при поиске рабочей v2-стратегии для discord.
> Всё ниже — проверено прогонами в изолированной VM (raw ISP path), а не переписано из доки.
> Провайдер/условия: RU ISP, discord за Cloudflare, роутер OpenWrt.

---

## 0. TL;DR — что реально пробивает

**Рабочий рецепт (discord/Cloudflare, TLS ClientHello блок):**
```
--filter-tcp=443 --filter-l7=tls
  --hostlist-domains=discord.com,discordapp.com,discord.gg,gateway.discord.gg,discord.media
  --payload=tls_client_hello
  --lua-desync=fake:blob=@/opt/zapret2/files/fake/stun.bin:badsum:tcp_seq=-10000:repeats=8
  --lua-desync=multisplit:pos=1:seqovl=654
```
**Мягкая замена (если fake где-то мешает):** `--lua-desync=multisplit:pos=host+1`

Обе прошли тройную валидацию (см. §5). Суть: **fake с плохой суммой (badsum) + расщепление ClientHello**.

---

## 1. Как устроен блок (эмпирическая модель)

- **Блок на TLS ClientHello (SNI)**, а не на IP. TCP-handshake проходит, рвётся именно TLS. Классификация blockcheckw: `SNI blocked` (TCP ok, TLS падает) → DPI обходим; `IP blocked` (TCP не встаёт) → только VPN.
- **Блок вероятностный и интермиттентный.** Один и тот же домен за минуты переключается `blocked ↔ open`. discord.com в одном окне отдавал `200, 170KB, 68ms`, в другом — рвал handshake. **Нельзя делать выводы по одной пробе.**
- **Не весь домен-набор блокируется одинаково.** У discord: web-app (`discord.com`) и gateway (`gateway.discord.gg`) — блок; CDN (`discordapp.com`/`cdn.discordapp.com`) — открыт. Стратегию вешать по hostlist только на блокируемые.
- **~16KB DPI cap / троттлинг тела.** Часть DPI пропускает handshake, потом режет/тормозит соединение после ~16KB. Поэтому проверять надо **реальной догрузкой ≥32KB**, а не только рукопожатием.

---

## 2. Две ортогональные оси: handshake ≠ download

Главная ошибка — мерить только handshake. Разделять:

| Ось | Что проверяет | Стоимость | Инструмент |
|---|---|---|---|
| **Handshake bypass** | ClientHello прошёл DPI? | дёшево (~1с/шт, тысячи/сек) | `blockcheckw scan/universal` |
| **Download completion** | тело ≥32KB доехало без столла? | дорого (5-30с/шт) | `blockcheckw check` (throughput) |

**Стратегия может пробить handshake, но завалить/затормозить download** (16KB cap). «2302 handshake-кандидата» ≠ «2302 рабочих». Валидация throughput обязательна.

**Вывод-методология:** сначала дёшево нафильтровать handshake-кандидатов (scan), потом дорого валидировать малый набор реальной догрузкой (check). Funnel, не brute-force.

---

## 3. Ключевой механизм: почему `fake:badsum` «прозрачен»

Это то, что позволяет стратегии **бить DPI и НЕ ломать рабочее соединение** одновременно:

- `fake` шлёт поддельный пакет (fake-ClientHello), который **видит DPI**, но:
- `badsum` ставит **неверную TCP-контрольную сумму** → пакет **дропается сервером/NAT до применения**, реальный стрим не портится.
- DPI обрабатывает fake (десинхронизируется), сервер его игнорирует → **десинк без коррупции**.
- `repeats=8` — послать fake несколько раз (надёжнее against вероятностный DPI).
- `tcp_seq=-10000` (badseq) — сдвинутый seq: ещё один способ, чтобы реальный стек проигнорировал fake, а DPI — нет.

**Следствие (критично):** «грязные» методы БЕЗ этой защиты **ЛОМАЮТ открытое соединение**. В прогоне 12 из 17 стратегий (агрессивные fake без корректного badsum/семантики) завалили discord, когда он был ОТКРЫТ. **Именно поэтому v2 «не работал» — деплоенная стратегия ломала discord, а не «не пробивала».**

> ⚠️ Router-side: `badsum` требует `sysctl net.netfilter.nf_conntrack_checksum=0` на роутере — иначе conntrack пофиксит сумму и fake доедет до сервера (сломает). (из заметок; проверить на OpenWrt).

**`stun.bin` vs `fake_default_tls`:** эмпирически fake с `blob=@stun.bin` (не-TLS payload) был discord-безопасен, а один из вариантов с `fake_default_tls` — ломал. Не-TLS fake путает DPI, но не триггерит server-side reject. v1-рецепт не зря использовал stun.bin.

---

## 4. Синтаксис v1 → v2 (lua-desync) — рабочая таблица

nfqws2 понимает и старый `--dpi-desync`, но v2 гибче (цепочки, `--new`, `--filter-l7`, inline hostlist).

| v1 (`--dpi-desync-*`) | v2 (`--lua-desync=`) |
|---|---|
| `fake,multisplit` | **два** инстанса: `--lua-desync=fake:...` + `--lua-desync=multisplit:...` |
| `split2` / `disorder2` | `multisplit` / `multidisorder` |
| `--dpi-desync-split-pos=1,midsld` | `pos=1,midsld` |
| `--dpi-desync-split-seqovl=654` | `seqovl=654` |
| `--dpi-desync-repeats=8` | `repeats=8` |
| `--dpi-desync-fake-tls=/path.bin` | `blob=@/path.bin` |
| `--dpi-desync-fake-tls=0x00000000` | `blob=0x00000000` |
| (стандартный fake) | `blob=fake_default_tls` (предопределён) |
| `--dpi-desync-fake-tls-mod=rnd,dupsid` | `tls_mod=rnd,dupsid,padencap` |
| `--dpi-desync-fooling=badsum` | `badsum` |
| `--dpi-desync-fooling=badseq` | `tcp_seq=<offset>` (напр. `-10000`, `-66000`) |
| `--dpi-desync-fooling=md5sig` | `tcp_md5` |
| `--dpi-desync-ttl=3` | `ip_ttl=3` (route-dependent, хрупко) |
| `--dpi-desync-fooling=ip_autottl` | `ip_autottl=-2,3-20` (адаптивно, предпочтительнее ip_ttl) |
| (нет) | `--filter-l7=tls,quic,http`, `--payload=tls_client_hello`, `--hostlist-domains=`, `--name=`, `--new` |

**Валидные токены v2 (подтверждены тем, что nfqws2 их реально запустил):** `blob=fake_default_tls`, `blob=@file`, `blob=0x…`, `badsum`, `tcp_seq=`, `tcp_md5`, `seqovl=`, `pos=host+1|midsld|sniext+N|1`, `ip_autottl=`, `tls_mod=`, `nodrop`, `repeats=`, `wssize:wsize=1:scale=6`, `out-range=<s1`, `send:tcp_md5`, `tcp_flags_unset=ACK`.

---

## 5. Методология валидации (что дало достоверный ответ)

Проблема: цель (discord) интермиттентна. Если тестировать, когда она ОТКРЫТА — «проходит» всё (ложные победы). Решение — **контроли**:

1. **Baseline-контроль (no-desync).** Перед тестом — прямой `curl` на цель. Если `200` → цель открыта → check недостоверен для «пробива» (но достоверен для «не ломает»).
2. **Позитивный контроль (заведомо заблокированный домен).** Когда цель открыта, кросс-валидируй на стабильно заблокированном (`rutracker.org`): если стратегия даёт там throughput — она **эффективный десинк** (а не «прошла, потому что и так открыто»).
3. **Open-window = фильтр «не ломает».** Прогон по открытой цели отсеивает стратегии, которые рвут рабочее соединение.

**Итоговый критерий рабочей стратегии = пересечение трёх:**
```
(пробивает handshake цели, когда заблокирована)   ∩
(эффективный десинк на позитивном контроле)        ∩
(не ломает цель, когда открыта)
```
Так 17 кандидатов → 5 надёжных, при том что прямого «discord throughput в блоке» поймать не удалось (был открыт).

---

## 6. blockcheckw — подводные камни (стоили часов)

- **`--take N` = «стоп после N ПОДТВЕРЖДЁННЫХ на протокол», НЕ «взять топ N».** С файлом на 6997 и малым числом проходящих download → перебирает сотни → падает по `timeout` (`CHECK EXIT: 124`). **Фикс: маленький файл (~15-20) + `--take 0` (проверить все) + запас времени.**
- **`check --from-file` ждёт top-level `.strategies[]`** (плоский массив `{protocol, args, coverage}`), НЕ вложенный `.protocols[].strategies[]`. Иначе `no strategies found`.
- **Пайплайн:** `status` (классификация блока) → `scan -d` (один домен) / `universal --domain-list --sample` (много доменов, sort by coverage) → `check --from-file --take --passes` (throughput ≥32KB, ловит 16KB cap). Только `success_rate==1.0` попадает в отчёт; early-exit на первом провале.
- **Метрики в check.json:** `success_rate`, `median_speed_kbps`, `median_latency_ms`, `passes_ok/passes_total`.
- **Ранжирование:** coverage↓, затем простота↑ (меньше `--lua-desync`, меньше repeats, single-stage лучше).
- **DoH auto-fallback** встроен — ISP спуфит `:53`, blockcheckw уходит на DoH сам.
- GA-скан **почти не генерит `seqovl` >1 и не комбинирует его с badsum/badseq** — v1-семью (`seqovl=654 + fake + badsum`) надо вписывать вручную, скан её пропускает.

---

## 7. Изоляция теста (иначе двойной десинк врёт)

- Тестовая VM со **статическим IP**, **исключённым из роутерного zapret** (`router-exclude up 192.168.1.50` → nft-правила `return` до NFQUEUE в цепочках `postrouting/prerouting`). Иначе роутерный zapret искажает трафик VM → двойная обработка.
- VM бьёт **сырой ISP-путь** (мимо роутера) → то, что валидировано тут, применимо к деплою на роутер (тот же ISP DPI).
- Исключение по **source-IP** (LAN-клиент), не dest-IP. Транзакционно (up/status/down), тег для чистого отката.

---

## 8. Ловушки, которые меня подставляли

- **Само-индуцированный rate-limit ≠ IP-блок.** Сотни быстрых проб (universal-скан) → Cloudflare/ISP выдаёт `000/timeout` на всё → выглядит как «IP заблокирован намертво». После паузы (cooldown) — само проходит. **Не путать rate-limit с DPI/IP-блоком; тестировать после остывания, лёгкой нагрузкой.**
- **Интермиттентность рушит атрибуцию.** «Откатил на v1 → discord заработал» могло совпасть с естественным снятием блока. Всегда контроль (§5).
- **Пустой `check.json` ≠ «ничего не работает».** Проверь `CHECK EXIT`: `124` = timeout (не дописал), `1` = ошибка парсинга/файла, `0` = реально отработал.
- **`success_rate=1.0` в открытом окне бессмысленен** без baseline-контроля.

---

## 9. Стратегии, прошедшие валидацию (discord, эта сессия)

| Стратегия | discord (open, kB/s) | rutracker (blocked) | Заметка |
|---|---|---|---|
| `fake:blob=@stun.bin:badsum:tcp_seq=-10000:repeats=8` + `multisplit:pos=1:seqovl=654` | 1442 ✅ | ✅ | **точный v2-перевод рабочего v1** |
| `fake:blob=@stun.bin:badsum:repeats=8` + `multisplit:pos=1:seqovl=654` | 1521 ✅ | ✅ | проще, быстрее |
| `multisplit:pos=host+1` | 1429 ✅ | ✅ | **простейшая, мягкая, без fake** |
| `fake:0x0:tcp_flags_unset=ACK` + `fake:fake_default_tls:...:noack` + `multisplit:pos=sniext+1` | 1454 ✅ | ✅ | double-fake |
| `fake:fake_default_tls:tcp_md5` + `out-range=<s1` + `send:tcp_md5` | 1359 ✅ | ✅ | md5sig-fooling |

---

## 10. Чек-лист деплоя на роутер (zapret2)

1. Стратегию вешать через `--new`-секцию **только на discord-hostlist** (не глобально — сломаешь незаблокированное).
2. Проверить наличие `blob`-файла: `/opt/zapret2/files/fake/stun.bin` (едет с zapret2). Иначе `blob=fake_default_tls`.
3. Для `badsum`: `sysctl net.netfilter.nf_conntrack_checksum=0`.
4. Отключить flow offloading (hw/sw) — иначе nfqws не видит пакеты.
5. Для nfqws нужен NFQUEUE-хук в firewall (nft/iptables) на нужные порты/hostlist.
6. Приоритет выбора: сначала простой `multisplit`; fake+seqovl — если простой не берёт. Избегать фиксированного `ip_ttl` (зависит от маршрута) — брать `ip_autottl`.
7. Проверять реальной догрузкой (≥32KB), не только «сайт открылся».

---

## Общий принцип

**Эффективный пробив = десинхронизировать DPI, не повредив реальный стрим.** Всё сводится к тому, чтобы DPI увидел «не то» (fake / split / seqovl), а сервер получил корректные данные (fake отбрасывается по badsum/badseq/ttl). Плюс — измерять download, не handshake, и валидировать с контролями против интермиттентности.
