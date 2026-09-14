# Проверки MVP

Дата прогона: 2026-09-14 · Node v25.2.1 · macOS

## Автоматические тесты

### `npm test` — 7 тестов хаба + набор `$mol`

```
✔ receipt persists before delivery; exact retries survive restart and epoch rotation (38ms)
✔ concurrent duplicate submissions issue one receipt (15ms)
✔ closing races with admission without accepting marks after final batch (17ms)
✔ concurrent use of an invite issues only one credential (16ms)
✔ GATT at MTU 23 transfers long challenge, signed mark and fragmented receipt (20ms)
✔ framing rejects malformed/out-of-order packets and supports successive messages (0.2ms)
✔ HTTP console authorization, onboarding, persistence and exports (49ms)
ℹ tests 7 — pass 7 / fail 0
```

Что покрывают:

- **GATT MTU 23**: якорь длиннее 20 байт читается последовательными read, `mark` пишется фреймами `[seq,total,payload 18B]`, `receipt` приходит notifications. Лимит сообщения 4590 байт, проверка `INVALID_FRAME`/`OUT_OF_ORDER_FRAME`.
- **Сохранность до квитанции**: `HubStore.run` серийно пишет `state.json` (`fsync` + `rename`) до отдачи `receipt`. Повтор той же отметки после `epoch_rotate` и перезапуска (`new HubStore(directory).load()`) возвращает идентичную квитанцию, вторая запись не создаётся.
- **Конкурентность**: 8 параллельных `accept_mark` одной отметки и 2 параллельных `onboard` одного кода выдают одну квитанцию/один сертификат.
- **Закрытие**: гонка `accept_mark` vs `session_close` — после `closing:true` приём отклоняется `SESSION_CLOSED`, `batch` содержит `merkle_root` по `mark_hash`.
- **HTTP**: `401` без `Bearer`, `403` чужой `Origin`, `201→400` повторного онбординга, экспорт не содержит приватных ключей.

### `$mol`-тесты (`mam`)

- `protocol.test.ts` — base64url/hex roundtrip, RFC 4648 вектор `foobar`, каноникал JSON, SHA-256 `abc`, ES256 seal/open, tamper→`BAD_SIGNATURE`, encode/decode, восстановление `public_raw` из `pkcs8`, merkle root/verify (odd-duplication).
- `hub_core.test.ts` — якорь epoch 0, ротация `prev_anchor_hash`, полный цикл `invite→onboard→session_start→mark→receipt`, `DUPLICATE`, `STALE_ANCHOR`, `BAD_SIGNATURE`, `NO_CREDENTIAL`, `CREDENTIAL_EXPIRED` (сдвиг часов +200 дней), `session_close` с `final_anchor`+`batch`.
- `student.test.ts` — демо-путь `no_identity→demo_onboard→accepted` и зелёная квитанция; проверка `verify_evidence` zero-trust; `already_marked` без второго `mark`; `receipt_timeout` с чужим кредом.
- `retry.test.ts` — потерянная квитанция: первый `mark` с заглушенным `subscribe_receipt` → `receipt_timeout` но `mark` сохранён; повтор использует тот же `mark_hash`; чужая квитанция (`anchor_hash: wrong`) отклоняется.

Сборка `$mol`: `mam attendpro/student` — без ошибок, `web.js` 262 KB, `web.css` 38 B.

## Ручные прогоны

### Демо без радио (`npm run start:demo` → http://127.0.0.1:8877/student/index.html)

1. «Демо-режим: настроить без хаба» → `Демо-студент · демо` в шапке, `Радио: демо`.
2. «Отметиться» → `Слушаю эфир… → Подключаюсь… → Проверяю подпись якоря… → Подписываю отметку… → Отправлено, жду квитанцию… → ✓ Принято преподавателем (квитанция №1)`.
3. Перезагрузка страницы — личность и история восстановлены из `localStorage`, повторное «Отметиться» на той же сессии → `Вы уже отмечены на «Демо-пара…»`, второй записи нет.
4. «Сбросить данные устройства» — очищает `attendpro.identity` + `attendpro.evidence` + `attendpro.demo-hub`, следующий онбординг генерирует новый ключ.
5. Офлайн: остановить `hub/server.cjs`, перезагрузить страницу — PWA грузится из `CacheStorage` (`attendpro-v2`, `sw.js`), демо-отметка всё ещё проходит (хаб в памяти страницы).

### Хаб преподавателя (`npm start` → http://127.0.0.1:8877/)

1. Ключ из `hub/data/admin-token` → `BLE: advertising` (bleno на этом Mac рекламирует `AttendPro`, 3 характеристики зарегистрированы).
2. «Начать пару» `Алгоритмы` → `session_id` hex 8 байт, epoch 0.
3. `Invite → POST /api/onboard` — код `AB…` 6 символов, `credential_hash` совпадает с `sha256(canonical(device_cred))`, публичные ключи проверяются `seal/open`.
4. «Завершить пару» → финальный якорь `closing:true` + `batch` с `merkle_root`, экспорт `attendpro-evidence.json` содержит `anchors`, `accepted`, `device_creds`, `teacher_cred`, `final`.
5. Ротация `Новое окно отметок` каждые 5 мин (`epoch_rotate`) — предыдущий якорь становится stale.

### Android APK

- `shell/www` собран `esbuild` из `shell/bridge.js` → `CapBLE` глобал.
- `npm run android:apk` (JDK 26, SDK Platform 36, Build Tools 36) → `shell/android/app/build/outputs/apk/debug/app-debug.apk` скопирован в `dist/AttendPro-debug.apk` (4.1 MB).
- Установка `adb install -r dist/AttendPro-debug.apk` на Android 7.0+ — разрешить `BLUETOOTH_SCAN/CONNECT`, `ACCESS_FINE_LOCATION` на старых прошивках, ввести `http://<IP>:8877` + код приглашения, `Отметиться` у хаба → квитанция и появление имени в консоли.
- Debug APK допускает HTTP-онбординг в доверенной сети (публичные данные открыты); ключ устройства не передаётся.

## Границы проверки

- **Радио**: полный BLE-обмен `телефон → Mac-хаб → квитанция` требует двух физических устройств; один Mac-адаптер не заменяет пару независимых радиоустройств. Programmatic GATT-тест покрывает фрагментацию, но не эфир.
- **Масштаб**: хаб MVP обслуживает централей по очереди (bleno single-central), не рассчитан на массовый одновременный вход аудитории.
- **Платформы**: Web Bluetooth — Chrome/Edge на Android/десктопе; Safari/iPhone PWA транспорт отсутствует. iOS-проект/IPA не входит в MVP.
- **Хранение**: `hub/data/state.json` (0600) + `admin-token` — не удалять между запусками; на телефоне ключ в `localStorage` WebView (keystore не подключён, backup отключён).
- **Доверенная сеть**: HTTP-онбординг в дебаге допустим только в доверенной локальной сети.

## Как воспроизвести

```sh
npm ci
npm ci --prefix shell
npm ci --prefix hub
npm run build
npm test
npm start          # или npm run start:demo
```
