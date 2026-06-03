# Тесты

## Запуск

```bash
# Все активные тесты
python3 tests/test_integration.py
python3 tests/test_module_tester.py
```

## Структура

```
tests/
├── test_integration.py       # Сквозной tunnel + все модули (основной)
├── test_module_tester.py     # Изолированное тестирование .so модулей
├── TESTS.md
├── disabled/                 # Сломанные тесты
│   ├── test_comprehensive.py
│   └── test_reconnect.py
└── old/                      # Устаревшие (старый протокол struct-based)
    ├── test_tunnel.py
    ├── test_passthrough.py
    ├── test_copy.py
    ├── test_raw.py
    ├── test_connect_msg.py
    ├── test_chain_config.py
    └── test_no_modules_inline.py
```

## test_integration.py

Сквозной тест сервер+клиент. Запуск: `python3 tests/test_integration.py`.

- **Tunnel mode** (без модулей): HTTP-запросы + bidirectional urandom через echo-сервер.
- **Module chain mode**: все модули из `test_modules/` — каждый прогоняется через цепочку encode→decode.
  `split` пропускается (известное ограничение).

## test_module_tester.py

Изолированное тестирование `.so` модулей через `modtunnel-tester`.
Запуск: `python3 tests/test_module_tester.py`.

- `test_module_list` — список модулей
- `test_each_module` — round-trip каждого модуля (4096 bytes)
- `test_invalid_module` — проверка что несуществующий модуль падает
- `test_data_sizes` — разные размеры данных (128B — 100KB) для всех модулей

## disabled

| Файл | Причина |
|------|---------|
| `test_comprehensive.py` | `test_large_data` падает (multi-client) |
| `test_reconnect.py` | `sys.exit(1)` при импорте |

## old

Устаревшие тесты на старом протоколе (2-байтовая длина + 1-байтовый тип вместо varint).
С текущим сервером несовместимы.
