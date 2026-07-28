#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
python3 run_local.py
status=$?
if [ "$status" -ne 0 ]; then
  printf '\n실행 오류가 runtime/logs/launcher.log에 저장되었습니다.\n'
  if [ -t 0 ]; then
    printf '터미널을 닫지 않았습니다. Enter를 누르면 종료합니다... '
    read -r _answer
  fi
fi
exit "$status"

