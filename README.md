# USB Research Toolkit 0.5.8 — пошаговое руководство

## Сначала: распаковка архива

Скопируйте `usb-research-toolkit-v0.5.8-time-sync.zip` в `~/Downloads`, затем в терминале Raspberry Pi выполните:

```bash
cd ~
unzip ~/Downloads/usb-research-toolkit-v0.5.8-time-sync.zip
cd ~/usb-research-toolkit-v0.5.8-time-sync
```

Если вы работаете с уже склонированным Git-репозиторием, переходите в его корень вместо пути выше. Все команды ниже запускаются из корня проекта.

USB Research Toolkit — исследовательский проект для эмуляции типовых USB-устройств на Linux/Raspberry Pi, тестирования их перечисления на **собственном изолированном хосте** и сопоставления событий Raw Gadget с захватом Wireshark/USBPcap.

> **Важно о поддержке классов.** Версия 0.5.0 расширяет рабочие сценарии классов, но не пытается обещать «любой USB-девайс без ограничений». USB HID позволяет задавать произвольные отчёты, однако каждому устройству нужен соответствующий HID report descriptor и формат report-данных. Реализованы готовые примеры клавиатуры, мыши, геймпада/джойстика и consumer control; CDC ACM с обычными class control requests и loopback для serial data; CCID bulk transport emulator с базовыми PC_to_RDR/RDR_to_PC командами и детерминированными APDU-ответами; Mass Storage BOT с backing file и основными SCSI-командами. CDC ECM/NCM, произвольные фирменные протоколы, isochronous-передачи и полноценное runtime-переключение alternate settings пока не реализованы. Composite-профили зависят от возможностей UDC и числа доступных endpoint.

Raw Gadget — низкоуровневый debug-интерфейс ядра Linux, не production backend. Контролируйте все тесты только на своём тестовом хосте: даже нормальный отказ USB-устройства возможен, а экспериментальный дескриптор может привести к зависанию или перезапуску хоста.

## Содержание

1. Что требуется
2. Сборка и автоматические тесты
3. Проверка USB Device Controller (UDC)
4. Подготовка Wireshark/USBPcap
5. Первый запуск без фаззинга
6. Каталог профилей
7. Подготовка виртуального Mass Storage-диска
8. Запуск HID, CDC ACM, MSC и composite устройств
9. Генерация вариантов
10. Запуск кампании фаззинга с live-консолью
11. Просмотр результатов и изменений профилей
12. Анализ PCAPNG и статусы корреляции
13. Побайтовый TXT/HTML отчёт всей кампании
14. Повтор конкретного случая
15. Решение частых проблем

---

## 1. Что требуется

### Raspberry Pi / Linux Gadget-side

- Raspberry Pi 4 Model B с USB-C-разъёмом, поддерживающим USB device/OTG в соответствующей конфигурации;
- Raspberry Pi OS/Debian, CMake 3.20+, C++20-компилятор, Python 3.10+;
- ядро с USB Gadget, UDC и `CONFIG_USB_RAW_GADGET`; устройство `/dev/raw-gadget` должно существовать;
- `tshark` нужен для анализа PCAPNG на Pi (необязательно для самого запуска Gadget);
- `dosfstools` (`mkfs.vfat`) — только если хотите создавать FAT-образ для виртуального диска.

Установка базовых инструментов:

```bash
sudo apt update
sudo apt install -y build-essential cmake python3 python3-venv tshark
# Необязательно, для форматирования образа Mass Storage:
sudo apt install -y dosfstools
```

### Windows host-side

- Wireshark с USBPcap;
- правильный USBPcap-интерфейс для физического USB Root Hub, к которому подключён Raspberry Pi;
- права, позволяющие захватывать USBPcap;
- тестовый компьютер, на котором разрешено наблюдать отказы USB. В этом проекте не требуется устанавливать агент на Windows.

На Raspberry Pi 4 Model B используйте USB-C data-порт платы как device-side соединение с тестовым Windows-ПК; USB-A порты Raspberry Pi — host-порты для периферии. Используйте исправный data-кабель, а питание организуйте так, чтобы плата не перезапускалась от просадки питания.

## 2. Сборка и автоматические тесты

Откройте терминал Raspberry Pi и перейдите в корень проекта (там, где лежит `CMakeLists.txt`):

```bash
cd ~/usb-research-toolkit-v0.5.8-time-sync
```

Если вы используете другой каталог, укажите его вместо `~/usb-research-toolkit-v0.5.0`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUSB_RESEARCH_BUILD_TESTS=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Проверка Python-скриптов и окружения:

```bash
python3 scripts/usb-lab.py doctor
python3 scripts/usb-gadget-campaign.py --help
python3 scripts/review-usb-campaign.py --help
python3 scripts/usb-lab.py profiles
```

Команда `doctor` проверяет инструменты, бинарники, `/dev/raw-gadget` и `/sys/class/udc/`. Тесты проекта проверяют сборку, обработку профилей, нормализацию и вспомогательные сценарии; они **не заменяют физическую проверку на реальной Pi и Windows**.

## 3. Проверь UDC и задавай его явно

Выполни:

```bash
ls -l /dev/raw-gadget
ls -l /sys/class/udc/
sudo build/usb-connect probe
```

`probe` показывает два значения: UDC driver name из uevent и имя UDC device. Не угадывайте их — используйте вывод `probe`. Для стандартной конфигурации Raspberry Pi в вашей лаборатории они могут быть одинаковыми:

```bash
export UDC_DRIVER='fe980000.usb'
export UDC_DEVICE='fe980000.usb'
printf 'driver=<%s> device=<%s>\n' "$UDC_DRIVER" "$UDC_DEVICE"
```

Если `probe` выводит другие имена, экспортируйте именно их. Важно: переменные `export` действуют только в текущем терминале; после открытия нового терминала их нужно задать снова. Чтобы избежать пустых переменных внутри `sudo`, можно передавать значения в командах напрямую.

Если `/dev/raw-gadget` отсутствует или `/sys/class/udc/` пуст, **не запускайте кампанию**. Проверьте режим peripheral/OTG, overlay DWC2 и не занят ли UDC другим gadget. Не добавляйте `dtoverlay=dwc2,dr_mode=peripheral` вслепую: сначала проверьте существующую загрузочную конфигурацию (`/boot/firmware/config.txt` или путь, применяемый вашим образом).

## 4. Подготовка Wireshark и папки захватов

Настроить SMB-шару на Pi можно так:

```bash
sudo bash scripts/setup-wireshark-share.sh
sudo testparm -s
hostname -I
ls -ld /srv/usb-captures
```

Если в `smb.conf` уже есть секция `[usb-captures]`, скрипт предупредит, что новый дубликат не добавлен. Проверьте текущую секцию вручную.

На Windows:

1. Запустите Wireshark.
2. Откройте **Capture → Options** и найдите интерфейс `USBPcapN`, соответствующий Root Hub нужного физического порта.
3. Уберите display filter, который может скрывать пакеты.
4. Начните захват **до** подключения/запуска тестового Gadget.
5. После теста остановите захват и сохраните `.pcapng` в сетевую папку Raspberry Pi, например:

```text
\\IP_RASPBERRY_PI\usb-captures\baseline-hid.pcapng
```

Замените `IP_RASPBERRY_PI` адресом из `hostname -I`. Убедитесь, что Windows действительно создала файл в `/srv/usb-captures`:

```bash
ls -lh /srv/usb-captures
```

`USBPcap` захватывает запросы на программном уровне host stack. Пустой захват может означать неверный USBPcap-интерфейс, отсутствие захвата или отсутствие запросов; это не само по себе доказательство сбоя Windows.

## 5. Первый запуск — без мутаций

До фаззинга убедитесь, что простое устройство запускается. На Windows заранее начните захват. На Pi:

```bash
cd ~/usb-research-toolkit-v0.5.8-time-sync
mkdir -p runs/baseline
sudo build/usb-connect run \
  profiles/valid/minimal-device.json \
  --backend raw-gadget \
  --udc-driver "$UDC_DRIVER" \
  --udc-device "$UDC_DEVICE" \
  --speed high \
  --trace runs/baseline/device.jsonl \
  --run-id baseline-minimal
```

Ожидается `Raw Gadget running. Press Ctrl+C to stop.`. Подождите 10–15 секунд, затем остановите процесс через `Ctrl+C`. В другом терминале можно просматривать trace во время теста:

```bash
tail -f runs/baseline/device.jsonl
```

Ищите `UDC_BOUND`, `CONTROL_REQUEST`, `CONTROL_RESPONSE_COMPLETE` и `SET_CONFIGURATION`. После теста остановите Wireshark, сохраните PCAPNG и проверьте его существование. Если базовый запуск не работает, исправьте это прежде, чем мутировать профили.

## 6. Каталог профилей

Посмотреть все встроенные профили и описание runtime-готовности:

```bash
python3 scripts/usb-lab.py profiles
```

Основные шаблоны:

| Шаблон | Что эмулирует | Примечание |
|---|---|---|
| `profiles/templates/hid-mouse.json` | HID-мышь | Нейтральные отчёты без движения |
| `profiles/templates/hid-keyboard.json` | HID Boot Keyboard | Передаёт только нулевой (не нажата ни одна клавиша) отчёт |
| `profiles/templates/hid-gamepad.json` | Общий HID gamepad | 16 кнопок, 4 оси и hat; нейтральное состояние |
| `profiles/templates/hid-joystick.json` | Общий HID joystick | Пример отчётной раскладки joystick |
| `profiles/templates/hid-consumer-control.json` | Consumer Control | Нейтральный отчёт |
| `profiles/templates/cdc-acm-serial.json` | CDC ACM serial | Class requests плюс bulk OUT→IN loopback |
| `profiles/templates/msc-bot-disk.json` | Mass Storage BOT | Требуется backing image `runs/storage/usb-lab.img` |
| `profiles/templates/composite-cdc-hid-keyboard.json` | CDC ACM + HID keyboard | Одна конфигурация, три интерфейса |
| `profiles/templates/composite-msc-hid-gamepad.json` | MSC BOT + HID gamepad | Одна конфигурация, два интерфейса |
| `profiles/templates/composite-hid-keyboard-mouse-consumer.json` | HID keyboard + mouse + consumer control | Одна конфигурация, три HID-интерфейса |
| `profiles/templates/composite-cdc-msc-hid-gamepad.json` | CDC ACM + MSC BOT + HID gamepad | Одна конфигурация, четыре интерфейса; нужен образ диска и UDC с достаточным числом endpoints |
| `profiles/templates/multi-config-keyboard-mouse.json` | Две конфигурации | Хост выбирает клавиатуру **или** мышь; не обе одновременно |
| `profiles/templates/vendor-bulk.json` | Vendor-specific bulk | Generic endpoint worker, OS-драйвер зависит от тестового профиля |
| `profiles/templates/msc-bot-descriptor-only.json` | Только MSC-дескрипторы | Не является рабочим диском; используй `msc-bot-disk.json` для BOT-исполнения |

HID-отчёт — это бинарный контракт, описывающий формат кнопок/осей/usage; не каждый коммерческий контроллер использует один стандартный report layout. Для другого HID скопируйте профиль, задайте корректный `raw_descriptors`/`interface_descriptors`, `interrupt_in_payload_hex` и endpoint. Нулевые keyboard/gamepad reports намеренно ничего не нажимают и не двигают указатель.

## 7. Создание виртуального Mass Storage-диска

MSC BOT использует файл-образ как блоковое хранилище. Создайте 64 MiB образ в пути, который указан в `profiles/templates/msc-bot-disk.json`:

```bash
cd ~/usb-research-toolkit-v0.5.8-time-sync
python3 scripts/create-msd-image.py --path runs/storage/usb-lab.img --size-mib 64 --format-vfat
```

Для `--format-vfat` нужен пакет `dosfstools` с `mkfs.vfat`/`mkfs.fat`, поддерживающим параметр `--offset` (актуальные версии dosfstools). Образ создаётся с MBR и разделом, смещённым на LBA 2048, чтобы хост видел стандартную схему removable disk. Если хотите пустой неформатированный образ:

```bash
python3 scripts/create-msd-image.py --path runs/storage/usb-lab.img --size-mib 64
```

Скрипт отказывается перезаписывать существующий образ без `--force`; этот флаг уничтожит данные в старом файле. Путь `backing_file` внутри JSON можно изменить, но он разрешается относительно текущего каталога процесса. Запускайте проект из корня репозитория либо задавайте абсолютный путь.

**Критически важно:** пока Windows держит виртуальный диск подключённым, не монтируйте и не редактируйте тот же backing image на Raspberry Pi. Это может повредить файловую систему. Используйте отдельный образ для каждой одновременной лабораторной сессии. Реализация нацелена на тестирование, а не на production storage.

## 8. Ручной запуск классов

Для всех команд ниже предполагается, что `$UDC_DRIVER` и `$UDC_DEVICE` заданы в текущем shell, как в разделе 3. Перед каждым ручным тестом начинайте захват Wireshark, после него останавливайте захват и анализируйте PCAPNG.

### HID keyboard — нейтральный отчёт

```bash
sudo build/usb-connect run profiles/templates/hid-keyboard.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/hid-keyboard/device.jsonl --run-id hid-keyboard
```

### HID gamepad / joystick

```bash
sudo build/usb-connect run profiles/templates/hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/hid-gamepad/device.jsonl --run-id hid-gamepad
```

Для джойстика замените путь на `profiles/templates/hid-joystick.json` и имя каталога trace.

### CDC ACM serial

```bash
sudo build/usb-connect run profiles/templates/cdc-acm-serial.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/cdc-acm/device.jsonl --run-id cdc-acm
```

Профиль отвечает на GET/SET_LINE_CODING, SET_CONTROL_LINE_STATE и SEND_BREAK. Bulk-данные, полученные на OUT endpoint, можно получить обратно на парном IN endpoint. Для теста данных откройте соответствующий COM-порт в терминальном приложении на тестовом Windows-ПК и отправьте текст; один только Wireshark не посылает CDC serial data.

### Mass Storage BOT

Сначала создайте образ из раздела 7, потом:

```bash
sudo build/usb-connect run profiles/templates/msc-bot-disk.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/msc-bot/device.jsonl --run-id msc-bot
```

Реализованы один LUN и типичные SCSI-команды INQUIRY, TEST UNIT READY, REQUEST SENSE, MODE SENSE, READ CAPACITY, READ/WRITE(10/12/16), START STOP UNIT, PREVENT/ALLOW REMOVAL и SYNCHRONIZE CACHE. Устройства могут запросить другие команды; тогда расширяйте SCSI-обработчик под конкретный host trace. Это не полная замена Linux `usb-storage`/`f_mass_storage` для всех вариантов протокола.

### Composite / multi-configuration

Профиль CDC+HID keyboard:

```bash
sudo build/usb-connect run profiles/templates/composite-cdc-hid-keyboard.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-cdc-hid/device.jsonl --run-id composite-cdc-hid
```

Профиль Mass Storage + gamepad требует созданного образа из раздела 7:

```bash
sudo build/usb-connect run profiles/templates/composite-msc-hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-msc-hid/device.jsonl --run-id composite-msc-hid
```

Три HID-интерфейса в одной конфигурации (клавиатура, мышь, consumer control):

```bash
sudo build/usb-connect run profiles/templates/composite-hid-keyboard-mouse-consumer.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-hid/device.jsonl --run-id composite-hid
```

Расширенный вариант CDC ACM + Mass Storage BOT + HID gamepad (нужен образ диска и больше ресурсов UDC):

```bash
sudo build/usb-connect run profiles/templates/composite-cdc-msc-hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-cdc-msc-hid/device.jsonl --run-id composite-cdc-msc-hid
```

Две альтернативные конфигурации keyboard/mouse:

```bash
sudo build/usb-connect run profiles/templates/multi-config-keyboard-mouse.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/multi-config/device.jsonl --run-id multi-config
```

Составные профили содержат несколько endpoints и потому зависят от их числа/направления, packet-size и поддержки типов endpoint конкретным UDC. Если `ENDPOINT_ENABLE_ERROR` фиксируется, посмотрите `ENDPOINT_CAPABILITIES` в trace. Runtime alternate-setting switching и isochronous I/O пока не реализованы.

## 9. Генерация профилей для проверки до реального старта

Сперва создайте план `dry-run` — он не подключает USB:

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
PLAN="runs/fuzz/dry-run-$STAMP"
python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --count 5 --seed 20261028 --mutations 1 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --out-dir "$PLAN" --dry-run
```

Посмотреть манифест и профили:

```bash
cat "$PLAN/summary.json"
less "$PLAN/manifest.json"
ls "$PLAN"/case-*.json
```

`--mutations N` — максимум N отдельных изменений поля на профиль. Уникальность профилей следует проверять отдельно: 1000 записей не гарантируют 1000 уникальных USB-конфигураций.

## 10. Малый запуск фаззинга с Live Console

Сначала убедитесь, что базовый profile стартует и Wireshark действительно фиксирует USB-запросы. Затем проведите кампанию из пяти случаев. Новые имена каталогов предотвращают затирание предыдущих результатов:

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="runs/fuzz/hid-smoke-$STAMP"
CAPTURE_DIR="/srv/usb-captures/hid-smoke-$STAMP"
sudo install -d -m 2770 -o "$USER" -g "$(id -gn)" "$CAPTURE_DIR"
echo "Результаты: $OUT"
echo "Захваты: $CAPTURE_DIR"
```

На Windows начните USBPcap захват. Затем на Pi:

```bash
sudo python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --count 5 --seed 20261028 --mutations 1 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --dwell-seconds 10 --settle-seconds 3 \
  --live-progress-interval 1 \
  --capture-dir "$CAPTURE_DIR" --out-dir "$OUT" \
  --allow-research --confirm-lab
```

Во время запуска Live Console показывает имя профиля, SHA-256, изменённые параметры, события GET_DESCRIPTOR/EP0, SET_CONFIGURATION, STALL/RESET и статус процесса по мере появления trace-событий.

- `START_FAILED` означает, что сам процесс не запустился; это не свидетельство реакции Windows.
- `RUNNING` означает, что процесс Gadget жив.
- `CONTROL_REQUEST` означает, что Raw Gadget получил управляющий запрос хоста.
- `SET_CONFIGURATION` означает, что в журнале зафиксирован ненулевой выбранный конфиг.
- `COMPLETED` означает только, что процесс проработал заданное время и был корректно завершён; это не обещает, что Windows успешно приняла устройство.

Не переходите к сотням вариантов, если почти все случаи — `START_FAILED` или trace не показывает запросов хоста. Сначала исправьте UDC/descriptor/runtime.

## 11. Результаты и изменения каждого профиля

После кампании поправьте владельца файлов (процесс обычно запускается через `sudo`):

```bash
sudo chown -R "$USER:$(id -gn)" "$OUT"
```

Сводка:

```bash
python3 -m json.tool "$OUT/summary.json" | less
```

Один объект кампании на строку:

```bash
less "$OUT/campaign.jsonl"
```

Trace и ошибки:

```bash
find "$OUT/traces" -maxdepth 1 -type f -print
cat "$OUT/traces/case-00001.stderr.log"
less "$OUT/traces/case-00001.device.jsonl"
```

Проще всего вывести изменения, статусы всех случаев и краткую статистику trace отдельным скриптом:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT"
```

Только один случай (например, `case-00018`):

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --case 18
```

Только случаи из очереди дополнительной проверки:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --only-review
python3 scripts/show-review-changes.py --campaign-dir "$OUT"
```

Сохранить структурированный JSON-отчёт:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --out "$OUT/all-changes.json"
```

Показать отличия всех `case-*.json` от исходного шаблона вручную (резервный вариант):

```bash
python3 - "$OUT" profiles/templates/hid-mouse.json <<'PY'
import json, sys
from pathlib import Path
campaign=Path(sys.argv[1]); base=json.loads(Path(sys.argv[2]).read_text())

def diff(a,b,path='$'):
    if isinstance(a,dict) and isinstance(b,dict):
        for k in sorted(set(a)|set(b)):
            p=f'{path}.{k}'
            if k not in a: print(f'  + {p}: {b[k]!r}')
            elif k not in b: print(f'  - {p}: {a[k]!r}')
            else: diff(a[k],b[k],p)
    elif isinstance(a,list) and isinstance(b,list):
        for i in range(max(len(a),len(b))):
            p=f'{path}[{i}]'
            if i>=len(a): print(f'  + {p}: {b[i]!r}')
            elif i>=len(b): print(f'  - {p}: {a[i]!r}')
            else: diff(a[i],b[i],p)
    elif a != b and path != '$.profile_name': print(f'  ~ {path}: {a!r} -> {b!r}')

for p in sorted(campaign.glob('case-*.json')):
    print(f'\n=== {p.name} ===')
    diff(base,json.loads(p.read_text()))
PY
```

Если установлен `scripts/show-all-changes.py`, он может вывести компактный отчёт по каждому случаю:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT"
```

Поле `profile_sha256` идентифицирует точный JSON, полезно для воспроизведения и сравнения.

## 12. PCAPNG анализ и статусы

После завершения кампании остановите захват Wireshark, сохраните PCAPNG и проверьте путь:

```bash
find "$CAPTURE_DIR" -maxdepth 2 -type f -print
```

Запустите анализатор после того, как файлы PCAPNG сохранены:

```bash
python3 scripts/review-usb-campaign.py \
  --campaign-dir "$OUT" --capture-dir "$CAPTURE_DIR"
python3 -m json.tool "$OUT/review-queue.json" | less
```

Для сопоставления одного случая с одним PCAPNG используйте `usb-lab compare` или отдельный вызов `compare` с фактическими путями. Если одна непрерывная PCAPNG покрывает десятки тестов, её нельзя считать независимой трассой каждого случая без разделения по времени; иначе события разных профилей могут смешаться.

Статусы сопоставления:

- `CORRELATED` — сравнимые сигнатуры совпали;
- `PARTIAL_CORRELATION` — есть совпавшие и непарные наблюдения;
- `NO_CORRELATION` — сравнимые сигнатуры не сопоставились;
- `DISCONNECT_OBSERVED` — явное событие отключения по данным источника;
- `RESET_OR_DISCONNECT_OBSERVED` — UDC сообщил неоднозначное событие reset/disconnect;
- `ERROR_OR_STALL_OBSERVED` — обнаружена ошибка/STALL/тайм-аут;
- `NO_HOST_EVIDENCE` — в нормализованном захвате нет событий;
- `POSSIBLE_DISCONNECT` — host status совместим с исчезновением устройства, но требует проверки.

Это статусы наблюдений, не диагноз Windows. `NO_HOST_EVIDENCE` может означать неправильный USBPcap interface; `NO_CORRELATION` — несовпадающий формат событий; `ERROR_OR_STALL_OBSERVED` может быть обычным ответом на некорректный дескриптор. PCAPNG сам по себе не подтверждает kernel panic/BSOD.

## 13. Повтор одного случая

Например, повторить `case 18` из завершённой кампании:

```bash
REPLAY_OUT="runs/fuzz/replay-case-18-$(date +%Y%m%d-%H%M%S)"
REPLAY_CAPTURE="/srv/usb-captures/replay-case-18-$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 2770 -o "$USER" -g "$(id -gn)" "$REPLAY_CAPTURE"
```

Начните новый USBPcap захват, затем выполните:

```bash
sudo python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --replay-from "$OUT" --replay-case 18 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --dwell-seconds 10 --settle-seconds 0 \
  --capture-dir "$REPLAY_CAPTURE" --out-dir "$REPLAY_OUT" \
  --allow-research --confirm-lab --stop-on-error
```

После теста остановите захват, сохраните PCAPNG, поправьте владельца файлов и запустите `review-usb-campaign.py` для каталога `REPLAY_OUT`. Для точного повторения сохраняйте оригинальный JSON, seed и SHA-256; не генерируйте новую мутацию вместо replay.

## 14. Частые проблемы

### В консоли `UDC driver= | UDC device=`

Переменные пустые в текущем терминале. Повторите:

```bash
export UDC_DRIVER='fe980000.usb'
export UDC_DEVICE='fe980000.usb'
printf '%s / %s\n' "$UDC_DRIVER" "$UDC_DEVICE"
```

Либо подставьте значения прямо в аргументы команды. Используйте фактические имена из `sudo build/usb-connect probe`.

### `START_FAILED` за 0.1–0.2 секунды

Посмотрите `traces/case-NNNNN.stderr.log` и `stdout.log`. Типичные причины: невалидный профиль, отсутствующий backing image для MSC, неподдерживаемые endpoint-адрес/тип/packet-size или занятый UDC. `profile_valid: true` не означает, что endpoint можно активировать на конкретном UDC. Теперь runner сразу отклоняет пустые `--udc-driver`/`--udc-device`, чтобы не выполнять бесполезную кампанию.

### `--out-dir уже существует и не пуст`

Защита от случайной перезаписи предыдущей кампании. Создайте новое имя каталога, например с датой/временем:

```bash
OUT="runs/fuzz/hid-$(date +%Y%m%d-%H%M%S)"
```

И передайте его как `--out-dir "$OUT"`.

### В trace есть `CONTROL_REQUEST`, в Wireshark ноль кадров

Проверьте USBPcap interface / Root Hub и отсутствие display filter. Не считайте пустой PCAP доказательством, что обмена USB не было.

### `/sys/class/udc/.../state` показывает `not attached`

Проверяйте его во время работы, в отдельном терминале:

```bash
watch -n 0.5 cat /sys/class/udc/fe980000.usb/state
```

После остановки Gadget `not attached` ожидаем. Дополнительно изучайте `UDC_BOUND`, `CONTROL_REQUEST`, `SET_CONFIGURATION` и физическое соединение.

### `PermissionError` для результатов, созданных `sudo`

```bash
sudo chown -R "$USER:$(id -gn)" runs/fuzz/ИМЯ_КАМПАНИИ
```

### MSC image already exists

Не добавляйте `--force`, если хотите сохранить содержимое диска. Укажите новый путь и обновите `runtime.mass_storage.backing_file` в профиле.

### Композитный профиль не запускается

Посмотрите `ENDPOINT_CAPABILITIES` и `ENDPOINT_ENABLE_ERROR` в trace. Некоторые UDC имеют фиксированную раскладку endpoint и не смогут отобразить всякий дескриптор. Попробуйте профиль с меньшим числом интерфейсов; это ограничение hardware backend, а не обязательно ошибка Windows.

---

## Источники и спецификации

- Linux Kernel documentation: [USB Raw Gadget](https://docs.kernel.org/usb/raw-gadget.html) — низкоуровневый userspace API, debugging-only характер интерфейса.
- USB-IF: [Mass Storage Bulk-Only Transport](https://www.usb.org/sites/default/files/usbmassbulk_10.pdf) — форматы CBW/CSW и требования BOT.
- USB-IF: [HID Specifications and Tools](https://usb.org/hid) — HID class и Usage Tables.
- Microsoft Learn: [HID Usages](https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/hid-usages) — классы Generic Desktop, Keyboard, Joystick и Game Pad.

VID/PID в шаблонах — учебные значения. Используйте только идентификаторы, разрешённые для вашей среды.


## Побайтовый отчёт всей кампании: профиль → Raw Gadget → Windows USBPcap

После кампании остановите захват, сохраните **один общий PCAPNG**, а затем выполните побайтовую корреляцию трёх источников:

1. **Ожидалось** — дескриптор/статический payload, скомпилированный из точного `case-NNNNN.json`.
2. **Записал Raw Gadget** — payload, который backend передал в `EP0_WRITE`/`EP_WRITE` либо прочитал через `EP0_READ`/`EP_READ` и записал в device trace. Это программная фиксация ioctl, не измерение электрической шины.
3. **Наблюдал Windows USBPcap** — данные ответа/передачи, извлечённые TShark из одного общего PCAPNG.

Генерируются `protocol-report.html`, `protocol-report.txt` и `protocol-report.json`. Помимо трёхстороннего сравнения отдельных транзакций отчёт строит инвентарь полной ожидаемой конфигурации и максимально полной конфигурации, фактически наблюдавшейся в USBPcap.

```bash
python3 scripts/report-usb-campaign.py \
  --campaign-dir runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS \
  --host-pcap /srv/usb-captures/hid-campaign-YYYYMMDD-HHMMSS/campaign.pcapng \
  --time-tolerance 0.75
```

Фактические имена каталогов и PCAPNG нужно заменить своими. По умолчанию отчёты сохраняются в каталоге кампании:

- `protocol-report.html` — показывает ожидаемое дерево дескрипторов и максимально восстановленный инвентарь ответов USBPcap, VID/PID отдельно, текстовую расшифровку и HEX обеих сторон; добавленные на стороне хоста элементы подсвечиваются зелёным, ожидаемые, но не запрошенные — красным, отличающиеся/неполные — янтарным. Отдельно остаётся трёхстороннее сравнение Expected / Raw Gadget / USBPcap;
- `protocol-report.txt` — те же данные в текстовом виде, включая таблицу `offset | expected | Raw Gadget | USBPcap | verdict`;
- `protocol-report.json` — статусы, кадры, временные окна, исходные HEX и объект `configuration_comparison` с `expected_ids`, `host_ids`, списком `entries`, декодированными полями, длинами и наблюдениями каждого дескриптора.

Откройте HTML в браузере:

```bash
xdg-open runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/protocol-report.html
```

Или посмотрите TXT прямо в терминале:

```bash
less runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/protocol-report.txt
```


В разделе **«Полная конфигурация: EXPECTED ↔ максимально восстановленная USBPcap»** отчёт использует все ответы `GET_DESCRIPTOR`, обнаруженные в окне случая. Для повторных запросов одного дескриптора сохраняются наблюдения, а для отображения выбирается наиболее полный успешный payload. Дескрипторы, которые хост не запрашивал в данном захвате, маркируются `NOT_REQUESTED` и не считаются доказанно удалёнными из устройства. Если запрос был, но payload не извлечён, состояние будет `REQUESTED_NO_PAYLOAD`. Поле `host_configuration_descriptors` содержит захваченные Configuration Descriptor и проверку длины относительно `wTotalLength`.

Важно: «максимально восстановленная» означает максимум данных, которые реально удалось извлечь из данного USBPcap, а не гарантированно исчерпывающий перечень всех дескрипторов устройства. USBPcap не может показать дескриптор, который Windows не запросила или который не попал в захват.

Скрипт берёт ожидаемые байты из **точного `case-NNNNN.json` данного запуска**, а не из исходного шаблона, поэтому учитывает фактические мутации. Он связывает PCAP кадры со случаем по `started_epoch`/`ended_epoch` из `campaign.jsonl` и времени `frame.time_epoch` из TShark. Часы Windows и Pi должны быть синхронизированы. По умолчанию задан допуск 0,75 секунды у краёв каждого временного окна. Если Windows clock опережает Pi на 2 секунды, вычтите такую разницу из timestamp хоста:

```bash
python3 scripts/report-usb-campaign.py \
  --campaign-dir runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS \
  --host-pcap /srv/usb-captures/hid-campaign-YYYYMMDD-HHMMSS/campaign.pcapng \
  --host-clock-offset-seconds 2.0
```

Это работает надёжно только при отдельном/изолированном тестовом USB-порту и корректных временных метках. В общий захват могут попасть другие устройства той же шины. Если TShark не смог извлечь байты ответа, отчёт покажет `HOST_BYTES_NOT_EXTRACTED`, а не выдаст совпадение по умолчанию. Если дескриптор не виден в PCAP, состояние будет `NOT_OBSERVED_IN_PCAP`; оно не доказывает, что хост никогда его не запрашивал — возможны неправильный интерфейс USBPcap, неполный захват или сдвиг часов.

Основные статусы:

- `EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED` — все полученные и сравнимые ответы дескрипторов совпали с профилем; ненулевая конфигурация наблюдалась и на хосте, и в trace устройства.
- `EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL` — байты совпали, но факт конфигурирования подтвердил только один источник.
- `EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE` — сравнимые байты совпали, но CONFIGURED не подтверждён.
- `HOST_DESCRIPTOR_BYTES_MISMATCH` — в ответе USBPcap есть байты или длина, отличающиеся от ожидаемого дескриптора. Отчёт показывает первое смещение и всю побайтовую таблицу.
- `HOST_RESPONSE_BYTES_UNAVAILABLE` — запрос замечен, но ответные байты не удалось извлечь.
- `HOST_TRANSFER_ERROR_OBSERVED` — TShark обнаружил ошибочный статус host transfer.
- `HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE` — хост запросил дескриптор, которого нет в ожидаемом каталоге профиля.
- `NO_HOST_EVIDENCE_FOR_CASE` — в временном окне не найден подходящий USB-трафик.
- `DEVICE_START_FAILED` — устройство не запустилось; хостовые кадры этого окна не выдаются за данные данного профиля.

Для GET_DESCRIPTOR отчёт сопоставляет exact setup tuple (`bmRequestType`, `bRequest`, `wValue`, `wIndex`, `wLength`) и временные метки, затем сравнивает expected profile → Raw Gadget trace → USBPcap. Для endpoint/control payloads он дополнительно пытается сопоставить адрес endpoint, направление, USB device address и время. Если однозначного сопоставления нет, пишет `NOT_CORRELATED`/`HOST_BYTES_NOT_CAPTURED`, а не объявляет PASS.

`Raw Gadget trace` фиксирует буфер, переданный/полученный userspace backend через ioctl, и возвращённую ioctl длину. `USBPcap` фиксирует наблюдение host USB stack/URB. Это не электрический анализатор: физические ACK/NAK/CRC не измеряются. При больших endpoint payloads trace сохраняет полностью данные до 1 MiB; более крупные передачи сохраняют только preview 256 байт и явно маркируются как truncated. Такой preview нельзя считать полным byte match. Для Mass Storage BOT динамические данные могут зависеть от backing image; если ожидаемый payload не задан непосредственно профилем, отчёт сравнивает device trace с USBPcap и помечает expected как `NOT_DEFINED_IN_PROFILE`.

### Тест отчёта без реального USB

```bash
python3 tests/test_campaign_byte_report.py scripts/report-usb-campaign.py
python3 tests/test_usb_configuration_reconstruction.py
```

Тест использует имитированный TShark, поэтому проверяет формирование отчётов и обнаружение byte mismatch, но не заменяет анализ реального захвата.

## Проверка корректности одного случая: профиль → trace → Wireshark

Одного статуса `COMPLETED` недостаточно. После сохранения отдельного PCAPNG для выбранного случая можно проверить байты дескрипторов в trace относительно точного JSON-профиля, состояние `SET_CONFIGURATION`, ожидаемые/enabled endpoints, HID IN payloads и сопоставление с наблюдениями host stack:

```bash
python3 scripts/verify-usb-case.py \
  --profile runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/case-00002.json \
  --device-trace runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/traces/case-00002.device.jsonl \
  --host-pcap /srv/usb-captures/case-00002.pcapng \
  --source windows_host \
  --out runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/verify-case-00002.json
```

`case-00002.pcapng` должен содержать захват именно этого одного теста. Если у тебя один непрерывный PCAPNG на всю кампанию, сначала раздели его по временным окнам случаев; простое сравнение общего файла с одним trace может сопоставить одинаковые запросы из разных вариантов. Без `--host-pcap` скрипт проверяет только локальный profile/trace и честно вернёт неполный вердикт.

Возможные итоговые вердикты: `PASS_OBSERVED_CORRELATED` (профиль/trace совпали, конфигурация зафиксирована, локальные проверки прошли и per-case host correlation совпала), `EXPECTED_REJECTION_POSSIBLE_NOT_CONFIGURED` (профиль не проходит strict validation и enumeration не дошло до CONFIGURED), `REVIEW_PROTOCOL_ANOMALY`, `INCOMPLETE_HOST_BYTES_NOT_VERIFIED`, `INCONCLUSIVE_SHARED_PCAP_NEEDS_PER_CASE_CAPTURE`, а также fail при несовпадении ожидаемых и trace descriptor bytes. Даже `PASS_OBSERVED_CORRELATED` означает программное подтверждение через USBPcap/host stack, а не проверку физического уровня USB; для проверки ACK/NAK/CRC требуется аппаратный USB-анализатор.

## 16. Матрица проверки классов и комбинаций интерфейсов (без мутаций)

Для задачи «какие интерфейсы пропускает фильтр» сначала используйте **матрицу без мутаций**. Обычный `usb-gadget-campaign.py` изменяет поля одного базового профиля; это полезно для fuzzing дескрипторов, но плохо подходит для чистого сравнения классов: если одновременно испортить `bLength`, `bInterfaceClass` или endpoint, отказ нельзя уверенно приписать фильтру класса.

Новая утилита `scripts/usb-interface-matrix.py` последовательно предъявляет заранее подготовленные профили без изменения их JSON. Она записывает ожидаемые интерфейсы (configuration/interface/class/subclass/protocol), Raw Gadget trace и краткий вердикт по каждому профилю. Встроенный набор включает HID keyboard/mouse/gamepad/joystick/consumer, CDC ACM, MSC BOT, HID+CDC, HID+MSC, CDC+MSC+HID, несколько HID-интерфейсов, multi-configuration и vendor-specific bulk.

Подготовьте Windows USBPcap capture **до** запуска, затем на Pi:

```bash
cd ~/usb-research-toolkit-v0.5.8-time-sync
sudo python3 scripts/usb-interface-matrix.py \
  --udc-driver fe980000.usb \
  --udc-device fe980000.usb \
  --dwell-seconds 10 \
  --settle-seconds 3 \
  --out-dir runs/interface-matrix/run-001 \
  --allow-research \
  --confirm-lab
```

Если матрица должна включать MSC, предварительно создай backing image по разделу 7. Комбинированный профиль может не стартовать, если UDC не имеет достаточного количества совместимых endpoint-ов. В этом случае смотри `traces/case-NNN.log`; это ограничение стенда, а не доказательство блокировки интерфейса фильтром.

Итоги:

```bash
cat runs/interface-matrix/run-001/interface-matrix.txt
python3 -m json.tool runs/interface-matrix/run-001/interface-matrix.json | less
```

Вердикты означают:

- `NO_HOST_CONTACT_OBSERVED` — Gadget работал, но запросы хоста не попали в trace.
- `HOST_CONTACT_NO_CONFIGURATION` — хост обращался к устройству, но `SET_CONFIGURATION` не наблюдался.
- `CONFIGURED_OBSERVED_REVIEW_HOST_CAPTURE` — хост выбрал конфигурацию; это ещё не подтверждает привязку драйверов ко всем интерфейсам.
- `CONFIGURED_WITH_ERRORS` — конфигурация наблюдалась, но в trace есть STALL/backend error.
- `DEVICE_OR_BACKEND_FAILURE` — запуск/работа Gadget завершились с ошибкой.

**Как определить, что именно пропустил фильтр:** сопоставьте для каждого case три независимых результата: (1) `interfaces_expected` из JSON/отчёта, (2) `SET_CONFIGURATION` и запросы в device trace, (3) интерфейсы и class-specific запросы в Windows USBPcap, плюс состояние устройства/драйвера в Windows Device Manager. Само `SET_CONFIGURATION` подтверждает выбор конфигурации, но не факт, что Windows успешно создала все интерфейсы или привязала к ним драйверы. Для composite устройства проверяйте каждый `bInterfaceNumber` отдельно. Зафиксируйте также VID/PID, время, порт и версию фильтра.

После чистой матрицы запускайте мутационный `usb-gadget-campaign.py` отдельно. Так вы сможете отличить фильтрацию класса/комбинации от отказа на некорректном дескрипторе.

### Границы поддержки классов

В текущем коде есть runtime-обработчики HID, CDC ACM (не весь USB CDC), MSC BOT и ограниченный CCID lab emulator; vendor-specific bulk имеет общий endpoint worker. HID позволяет задавать произвольный report descriptor и байты отчёта, но это не означает автоматическую эмуляцию каждого проприетарного HID-протокола. MSC реализует один LUN с file-backed образом. CCID реализует ограниченный тестовый bulk transport и не является полноценной смарт-картой: нет полной реализации T=0/T=1, PIN/secure messaging и криптографических операций. CDC ECM/NCM, Audio, Video, Printer, Bluetooth и произвольные фирменные протоколы не следует считать полноценно реализованными только потому, что для них можно сформировать class descriptor. Isochronous endpoints и полноценное runtime-переключение alternate settings также не поддерживаются. Сначала проверяйте поддерживаемый runtime-путь, затем добавляйте новый класс отдельным backend worker и тестами.

## 17. Targeted USB filter fuzzing (v0.5.5)

`scripts/usb-filter-fuzz.py` builds repeatable iterations from the known profile corpus (`profiles/templates`). It changes one or more controlled dimensions per iteration: VID/PID, `bDeviceClass` tuple, an interface class tuple, interface protocol, or switches to another corpus layout (which changes the number/composition of interfaces). Each exact JSON input is preserved under `inputs/`, with SHA-256 and a change log. Reports are emitted as `report.html` (visual overview), `report.txt` (compact summary), and `campaign.json` (machine-readable full record).

Generate a 40-case campaign without attaching a gadget:

```bash
python3 scripts/usb-filter-fuzz.py --count 40 --seed 20261116 --mutations 2 --out-dir runs/filter-fuzz-001
```

Run the same campaign on the isolated Raspberry Pi test bench:

```bash
sudo -E python3 scripts/usb-filter-fuzz.py --count 40 --seed 20261116 --mutations 2 \
  --run --confirm-lab --udc-driver fe980000.usb --udc-device fe980000.usb \
  --dwell-seconds 8 --settle-seconds 2 --out-dir runs/filter-fuzz-001
```

The seed makes the generated sequence repeatable. `--count` controls iterations and `--mutations` controls changes per iteration. The report shows, for every case, the submitted VID:PID, device-class tuple, complete interface class tuples, exact input filename/hash, what changed, gadget-side control-request count, SET_CONFIGURATION, STALL/error counts and a cautious verdict. The full generated JSON is the authoritative input and is preserved for replay.

**Interpretation:** `CONFIGURED_OBSERVED_REVIEW_HOST_CAPTURE` means the gadget trace observed host control traffic and SET_CONFIGURATION without the counted device-side errors. It does *not* establish Windows filter acceptance, successful driver binding, or class data-path functionality. For the actual filter verdict, correlate the case with the Windows USBPcap capture and Device Manager (or another trusted Windows-side observation). A Windows host agent is not assumed by this script. The corpus-layout switch selects a known template rather than synthesizing arbitrary endpoint descriptors; this keeps endpoint layouts grounded in tested templates. Mutating class codes independently can intentionally create semantically inconsistent profiles, so use only on an isolated lab host.

### 17. Корпусный генератор USB fuzz-кейсов (v0.5.5)

`scripts/usb-fuzz-generator.py` создаёт воспроизводимые итерации из корпуса профилей. Входом является исходный JSON-профиль; генератор сохраняет его сводку, точную мутацию и полный сформированный JSON-кандидат. Проверяются независимо поля устройства `VID/PID` и `bDeviceClass/SubClass/Protocol`, а также `bInterfaceClass/SubClass/Protocol`. Есть структурные операции добавления/удаления интерфейса.

Оффлайн-генерация (по умолчанию, без подключения USB-устройства):

```bash
python3 scripts/usb-fuzz-generator.py --iterations 100 --seed 20261116 --out-dir runs/usb-fuzz/run-001
```

Откройте `runs/usb-fuzz/run-001/fuzz-report.html`: каждая раскрываемая карточка показывает **вход → изменение → получившийся профиль → наблюдаемый результат**. Рядом создаются `fuzz-report.txt`, `fuzz-report.json` и все JSON-профили в `cases/`. Seed позволяет повторить последовательность.

Запуск совместимых мутаций на тестовом стенде (требует root и явного подтверждения):

```bash
sudo python3 scripts/usb-fuzz-generator.py --iterations 30 --seed 20261116 \\
  --execute --confirm-lab --udc-driver fe980000.usb --udc-device fe980000.usb \\
  --out-dir runs/usb-fuzz/hardware-001
```

Важно: `add-interface` и `remove-interface` генерируют структурные descriptor-кандидаты, но аппаратный запуск этих двух типов пропускается. Генератор пока не синтезирует согласованные runtime endpoint/class-worker mappings, поэтому нельзя выдавать такие кандидаты за корректно обслуживаемые интерфейсы. VID/PID и scalar class-triplet мутации допускаются к запуску. `HOST_CONFIGURED_OBSERVED` означает только наличие `SET_CONFIGURATION` в trace устройства; это не доказывает привязку Windows-драйвера к каждому интерфейсу. Для окончательного вывода сопоставляйте отчёт с USBPcap и Диспетчером устройств Windows.


### CCID smart-card lab emulator

Профиль `profiles/templates/ccid-smartcard.json` объявляет интерфейс класса `0x0B`, CCID functional descriptor (54 bytes), bulk IN/OUT и interrupt IN endpoint. Runtime отвечает на базовые `PC_to_RDR_IccPowerOn`, `IccPowerOff`, `GetSlotStatus`, `GetParameters`, `ResetParameters`, `SetParameters`, `XfrBlock`, `Escape`, `Abort` и `SetDataRateAndClock`. ATR по умолчанию `3B00`; APDU ответы детерминированы для тестирования транспорта (обычный ответ `90 00`). Это не полноценная смарт-карта, не используйте для аутентификации, PIN-кодов или реальных платёжных/идентификационных карт.

Запуск после сборки: `sudo ./build/usb-connect run profiles/templates/ccid-smartcard.json --backend raw-gadget --udc-driver fe980000.usb --udc-device fe980000.usb --trace runs/ccid/device.jsonl`. Для комбинированных устройств добавьте CCID interface и соответствующую запись `runtime.interfaces` с `class: "ccid"`, `in_endpoint` и `out_endpoint`; endpoint addresses должны быть уникальны в активной конфигурации. Interrupt endpoint объявлен в профиле, но asynchronous CCID slot-change notifications пока не реализованы.

### 18. Точный повтор уже выполненной filter-fuzz кампании (v0.5.7)

Для повтора **не запускайте генератор заново**: одинаковый seed сам по себе не гарантирует идентичность, если изменился корпус шаблонов, код генератора или версия runtime. Используйте `scripts/usb-filter-replay.py`. Он читает исходный `campaign.json`, берёт сохранённые файлы `inputs/case-*.json` (не генерирует их повторно), проверяет SHA-256 каждого входа и запускает кейсы строго в исходном порядке. Результаты пишет в отдельный каталог, оригинальная кампания не изменяется.

Сначала проверьте план без подключения USB:

```bash
python3 scripts/usb-filter-replay.py \\
  --campaign runs/filter-fuzz-001/campaign.json \\
  --out-dir runs/filter-fuzz-001-replay \\
  --udc-driver fe980000.usb --udc-device fe980000.usb --dry-run
```

Затем повторите на том же Raspberry Pi, с тем же Windows-хостом, тем же кабелем/портом и той же конфигурацией стенда:

```bash
sudo -E python3 scripts/usb-filter-replay.py \\
  --campaign runs/filter-fuzz-001/campaign.json \\
  --out-dir runs/filter-fuzz-001-replay \\
  --udc-driver fe980000.usb --udc-device fe980000.usb \\
  --confirm-lab
```

Для новых кампаний `campaign.json` содержит скорость, dwell/settle, UDC и SHA-256 бинарника `usb-connect`. Replay по умолчанию откажется работать, если хеш бинарника отличается; для осознанного сравнительного запуска с другим бинарником предусмотрен `--allow-binary-mismatch`, но такой запуск уже не является строго идентичным по ПО. Для старых v0.5.6 кампаний, где этих метаданных ещё нет, скрипт использует speed=high, dwell=8 и settle=2 секунды; если исходные значения отличались, укажите их явно через `--speed`, `--dwell-seconds`, `--settle-seconds`.

Выход: `replay.html`, `replay.txt`, `replay.json`, а также отдельные `traces/case-NNNNN.device.jsonl` и `.log`. В отчёте сохранены номер кейса, VID:PID, число интерфейсов, хеш точного входного JSON и наблюдения Raw Gadget. Для доказательства принятия фильтром по-прежнему нужны синхронные Windows USBPcap/Device Manager данные. Сам replay не может гарантировать идентичность физического Windows-хоста или состояния драйверов: для этого повторяйте на том же хосте и с теми же условиями.

### 19. Проверка и синхронизация времени с целевой ОС

Для сопоставления USBPcap на Windows и device trace на Raspberry Pi время обеих систем должно быть близким. Добавлена утилита `scripts/usb-time-sync.py`: она подключается к целевой ОС по SSH, сравнивает UTC-время с машиной, на которой запущена утилита, а по явному подтверждению может установить время целевой системы. Поддерживаются Linux и Windows с установленным/включённым OpenSSH Server. Утилита не трогает USB и сохраняет `time-sync.txt` и `time-sync.json`.

Сначала только проверь расхождение (команда ничего не меняет):

```bash
python3 scripts/usb-time-sync.py \\
  --host 192.168.1.50 --user pi --target-os linux \\
  --check --out-dir runs/time-sync/check-001
```

Синхронизация Linux-цели с локальными UTC-часами (SSH-пользователь должен иметь passwordless `sudo` для `date`):

```bash
python3 scripts/usb-time-sync.py \\
  --host 192.168.1.50 --user pi --target-os linux \\
  --sync --confirm-time-change --out-dir runs/time-sync/sync-001
```

Для Windows-цели с OpenSSH Server и PowerShell:

```bash
python3 scripts/usb-time-sync.py \\
  --host 192.168.1.60 --user labuser --target-os windows \\
  --sync --confirm-time-change --out-dir runs/time-sync/windows-sync
```

На Windows SSH-сеанс должен иметь права администратора, иначе `Set-Date` завершится ошибкой. Для Linux требуется `sudo -n date`; утилита намеренно не запрашивает и не передаёт пароль через SSH. Перед `--sync` проверь адрес и учётную запись: изменение системных часов влияет на журналы, сертификаты, планировщик и времязависимые службы. Для постоянной синхронизации предпочтительнее настроить NTP/chrony/Windows Time; эта утилита предназначена для разовой лабораторной выверки перед кампанией.

`target_minus_source_ms` показывает смещение целевой системы относительно локального источника: положительное значение означает, что часы цели идут впереди. В режиме `--check` по умолчанию PASS означает абсолютное расхождение не более 2000 мс; порог можно изменить через `--max-drift-ms`. После `--sync` утилита повторно измеряет смещение и записывает оба результата. Время устанавливается по UTC, поэтому часовой пояс отображения не меняется.

## Full USBPcap enumeration inventory (updated report)

`report-usb-campaign.py` builds a capture-wide USB enumeration inventory before
assigning traffic to fuzz cases. This inventory is independent of case timestamps and
includes descriptor requests observed before the first fuzz mutation.

For Windows USBPcap, request and completion frames are correlated by `IRP ID`, with
`URB Function` and `Control transfer stage` identifying SETUP and COMPLETE. The parser
does not depend on `usb.urb_id` or `usb.urb_type` being populated. The inventory retains
the exact 8-byte SETUP packet HEX, setup parameters, request/response frame numbers,
completion status, requested/received lengths, actual response HEX, and decoded
descriptor fields. Missing response data is never replaced with expected profile bytes.
It distinguishes missing completion, STALL, TIMEOUT, CANCELLED and generic errors.

A successful USB transfer is not proof that the descriptor is valid. The report also
flags malformed descriptor lengths and interface numbers outside `bNumInterfaces`.
Per-case Expected / Raw Gadget trace / USBPcap comparison remains separate from the
capture-wide inventory. USBPcap is a Windows host-stack capture, not an electrical
USB analyzer.

Generate the report as before:

```bash
python3 scripts/report-usb-campaign.py \
  --campaign-dir runs/fuzz/<campaign-directory> \
  --host-pcap /path/to/campaign.pcapng \
  --time-tolerance 0.75
```

The capture-wide inventory is available in `protocol-report.html`, `protocol-report.txt`
and JSON under `host_capture_inventory`. USBPcap remains a Windows host-stack capture,
not an electrical USB analyzer. A successful enumeration inventory means only that
these transactions and payloads were present in the supplied capture.
