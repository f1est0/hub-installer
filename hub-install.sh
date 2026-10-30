#!/bin/sh
# Загрузчик агента мониторинга (HubSentry). Это единственный файл, который нужно передать владельцу сервера.
#
# Он ничего не устанавливает сам: скачивает с хаба манифест и подпись, проверяет подпись вшитым ниже открытым ключом
# владельца хаба, затем скачивает установщик, агента и hub.sh и сверяет их sha256 с манифестом. Только после этого запускает
# установщик. Файл без верной подписи или с неверной контрольной суммой не запускается, даже если хаб взломан.
# В файле нет секретов: токен проекта вводится при установке.
#
#   sudo sh hub-install.sh                                     # меню с цифрами
#   sudo HUB_TOKEN=hub_xxx sh hub-install.sh --auto            # без вопросов
#   sh hub-install.sh --check | --update                       # проверка / установка обновлений (по cron)
set -u

ENV_FILE=/etc/hub-agent.env
STATE_FILE=/var/lib/hub-agent/published
saved_url="$(sed -n 's/^HUB_URL=//p' "$ENV_FILE" 2>/dev/null | head -1)"
HUB_URL="${HUB_URL:-${saved_url:-https://uptime.profium.pro}}"
case "$HUB_URL" in *ozery.profium.pro*) HUB_URL=https://uptime.profium.pro;; esac

fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "Запустите от root: sudo sh hub-install.sh"
command -v curl >/dev/null 2>&1 || fail "Нужен curl (например: apt install curl)"
command -v openssl >/dev/null 2>&1 || fail "Нужен openssl, он проверяет подпись (например: apt install openssl)"

tmp="$(mktemp -d)" || fail "Не удалось создать временную папку"
trap 'rm -rf "$tmp"' EXIT INT TERM

sha() { openssl dgst -sha256 "$1" | sed 's/^.*= //'; }
get() { curl -fsS -m 30 -o "$tmp/$1" "${HUB_URL%/}/dist/$1" 2>/dev/null; }

# Открытый ключ владельца хаба (закрытый на серверах не хранится).
cat > "$tmp/pub.pem" <<'PUBKEY_END'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvthz/uCOcqL6fAiXzFhu
eodd82uYwfQSboHq5Re/RQ4QVWJ+001LHC/IzihSMUuWB7fu9ez/fQ8haYNJFIbY
NeH6cxKF7CXC1qwwf3oVJNI4oKkVDkYy0ofz8vRIcqETkilcjom+UHYEs7vxXzba
43O067e6aUHcyLDLo9uJ4MLBv2Goyh80N1k1Od9H06IECiWICq5HAfMx5xV+cyK/
A/JJVEXp1YHFpg02xfHIIzcQG2RHTgTnnLaPqhGdXV9vvH8f/UQQUNuGe2ZNaO3r
6uikKz2YWnsAJRsQ8+OoxO8aLvb2Jx0eu/ejq0PH637umC4Iss1KgpNqK1eY+/5h
EMBGiXOss6ci01VnUipyjvo7yeJQRsnJv8lYuNecWzgshBvZa0Sj9kMiY+oir/7o
UNgIZopA3dTECPa4K9CxKQaNzepP0Fw0q9mKulb6dyDgKBJH1jQnItcTuPH5La8H
ralHTqHW3//q2JvmH9xeinPWqdUXhBS4cDm3z33gJ94VAgMBAAE=
-----END PUBLIC KEY-----
PUBKEY_END

get manifest.json && get manifest.sig || fail "Не удалось скачать данные с хаба ($HUB_URL): проверьте интернет и адрес."
openssl dgst -sha256 -verify "$tmp/pub.pem" -signature "$tmp/manifest.sig" "$tmp/manifest.json" >/dev/null 2>&1 \
  || fail "Подпись неверна: файлы с хаба не приняты. Не продолжайте и сообщите владельцу хаба."

# Срок: подписанный, но просроченный манифест не принимается (так хаб не подсунет старую версию новому серверу).
expires_at="$(sed -n 's/.*"expires":"\([0-9TZ:.-]*\)".*/\1/p' "$tmp/manifest.json")"
[ -n "$expires_at" ] || fail "В манифесте нет срока действия: файлы с хаба не приняты."
now_at="$(date -u +%Y-%m-%dT%H:%M:%S)"
[ "$now_at" != "$expires_at" ] && [ "$(printf "%s\n%s\n" "$now_at" "$expires_at" | sort | head -1)" = "$now_at" ] || fail "Срок подписи выпуска истёк ($expires_at). Сообщите владельцу хаба: нужно опубликовать новый выпуск."

# Откат: подписанный, но старый манифест не принимается.
pub_at="$(sed -n 's/.*"published":"\([0-9TZ:.-]*\)".*/\1/p' "$tmp/manifest.json")"
[ -n "$pub_at" ] || fail "Манифест повреждён (нет даты публикации)."
seen_at="$(cat "$STATE_FILE" 2>/dev/null)"
if [ -n "$seen_at" ] && [ "$pub_at" != "$seen_at" ] && [ "$(printf '%s\n%s\n' "$pub_at" "$seen_at" | sort | head -1)" = "$pub_at" ]; then
  fail "Хаб предлагает более старую версию, чем уже была ($pub_at < $seen_at): откат отклонён."
fi

for pair in installer.sh:installer hub-agent.sh:agent hub.sh:jobs; do
  file="${pair%%:*}"
  key="${pair##*:}"
  want="$(sed -n "s/.*\"$key\":\"\([0-9a-f]*\)\".*/\1/p" "$tmp/manifest.json")"
  [ "${#want}" -eq 64 ] || fail "Манифест повреждён ($key)."
  get "$file" || fail "Не удалось скачать $file с хаба."
  [ "$(sha "$tmp/$file")" = "$want" ] || fail "Контрольная сумма $file не совпала с подписанной: файл не принят."
done

mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null
printf '%s\n' "$pub_at" > "$STATE_FILE" 2>/dev/null

case "$0" in /*) self="$0";; *) self="$(pwd)/$0";; esac
HUB_URL="$HUB_URL" HUB_DIST_DIR="$tmp" HUB_BOOTSTRAP="$self" sh "$tmp/installer.sh" "$@"
