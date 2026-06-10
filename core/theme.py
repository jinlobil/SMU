# -*- coding: utf-8 -*-
"""Runtime theme/color configuration for the SMU UI.

The legacy MainWindow still owns widget construction, but color tokens and
Color_env parsing live here so later UI modules can share one theme source.
"""

from __future__ import annotations

import logging
import os

from PyQt5.QtGui import QColor

from core.paths import COLOR_ENV_PATH

log = logging.getLogger("SophosUI")

# ======================================================
# UI Theme Tokens
# ======================================================
UI_THEME = {
    "surface": "#FFFFFF",
    "surface_soft": "#F8FBFD",
    "surface_muted": "#F3F8FC",
    "accent_soft": "#EEF5FF",
    "border": "#B7D2FB",
    "border_soft": "#D8E8FF",
    "input_border": "#CFE0FB",
    "accent": "#0863e2",
    "accent_deep": "#054fb8",
    "accent_hover": "#1F75EF",
    "accent_mid": "#2F80ED",
    "accent_light": "#EAF3FF",
    "accent_text": "#0863e2",
    "card_title_text": "#0863e2",
    "accent_text_soft": "#2B6FCB",
    "sierra": "#5F8FAF",
    "sierra_shadow": (95, 143, 175),
    "icon_glow": (8, 99, 226),
    "text": "#111827",
    "text_muted": "#6b7280",
    "text_soft": "#374151",
    "success_bg": "#ecfdf5",
    "success_text": "#047857",
    "success_border": "#bbf7d0",
    "danger_bg": "#fef2f2",
    "danger_text": "#b91c1c",
    "danger_border": "#fecaca",
    "gray_bg": "#f1f5f9",
    "gray_text": "#475569",
    "gray_border": "#e2e8f0",
}

# ======================================================
# Color / theme configuration
# - Runtime-editable color tokens used by the whole UI.
# - Later module target: core/theme.py
# ======================================================
DEFAULT_COLOR_CONFIG = {
    "UI_Background": "#FFFFFF",
    "UI_Surface": "#FFFFFF",
    "UI_Surface_Soft": "#F8FBFD",
    "UI_Surface_Muted": "#F3F8FC",
    "Card_Border": "#EEF5FF",
    "Card_Title_Text": "#0863e2",
    "Card_Divider": "#D8E8FF",
    "Sierra_Blue": "#5F8FAF",
    "Sierra_Shadow": "#5F8FAF",
    "Icon_Glow": "#0863e2",
    "Primary_Blue": "#0863e2",
    "Primary_Blue_Dark": "#054fb8",
    "Primary_Blue_Hover": "#1F75EF",
    "Primary_Blue_Mid": "#2F80ED",
    "Primary_Blue_Soft": "#EEF5FF",
    "Primary_Blue_Light": "#EAF3FF",
    "Primary_Blue_Text_Soft": "#2B6FCB",
    "Input_Border": "#CFE0FB",
    "Input_Border_Soft": "#D8E8FF",
    "Button_Primary_Stop_0": "#FDFEFF",
    "Button_Primary_Stop_1": "#6EAAF7",
    "Button_Primary_Stop_2": "#0863e2",
    "Button_Primary_Stop_3": "#054fb8",
    "Button_Primary_Hover_Stop_0": "#FFFFFF",
    "Button_Primary_Hover_Stop_1": "#8FC0FA",
    "Button_Primary_Hover_Stop_2": "#1F75EF",
    "Button_Primary_Hover_Stop_3": "#0863e2",
    "Button_Secondary_Start": "#FFFFFF",
    "Button_Secondary_Mid": "#EEF5FF",
    "Button_Secondary_End": "#DCEBFF",
    "Button_Primary_Text": "#FFFFFF",
    "Button_Secondary_Text": "#0863e2",
    "Checkbox_Text": "#0863e2",
    "Checkbox_Border": "#B7D2FB",
    "Checkbox_Checked_Start": "#2F80ED",
    "Checkbox_Checked_End": "#0863e2",
    "Table_Selection_Background": "#EEF5FF",
    "Table_Selection_Text": "#0863e2",
    "Table_Header_Background": "#F3F8FC",
    "Table_Header_Text": "#0863e2",
    "Status_Blue_Background": "#EEF5FF",
    "Status_Blue_Text": "#2B6FCB",
    "Status_Blue_Border": "#B7D2FB",
    "Status_Success_Text": "#16a34a",
    "Status_Fail_Text": "#dc2626",
    "Threat_trend_Detection": "#0863e2",
    "Threat_trend_Detection_XDR": "#EAF3FF",
    "Threat_trend_Email": "#14b8a6",
    "Threat_trend_File": "#f59e0b",
}

COLOR_ENV_COMMENTS = {
    "UI_Background": "기본 배경",
    "Card_Border": "카드 테두리",
    "Card_Title_Text": "카드 제목 글씨",
    "Sierra_Shadow": "카드 그림자 RGB 기준색",
    "Primary_Blue": "기본 브랜드 파랑",
    "Button_Primary_Stop_0": "Primary 버튼 그라데이션 시작",
    "Button_Primary_Stop_3": "Primary 버튼 그라데이션 끝",
    "Threat_trend_Detection": "그래프 Detection",
}

COLOR_ENV_ALIAS = {
    "Threat_trend_Detection": ["Threat_trand_Detection"],
    "Threat_trend_Detection_XDR": ["Threat_trand_Detection_XDR"],
    "Threat_trend_Email": ["Threat_trand_Email"],
    "Threat_trend_File": ["Threat_trand_File"],
}

THEME_COLOR_MAP = {
    "UI_Background": "app_background",
    "UI_Surface": "surface",
    "UI_Surface_Soft": "surface_soft",
    "UI_Surface_Muted": "surface_muted",
    "Card_Border": "accent_soft",
    "Card_Title_Text": "card_title_text",
    "Card_Divider": "border_soft",
    "Sierra_Blue": "sierra",
    "Primary_Blue": "accent",
    "Primary_Blue_Dark": "accent_deep",
    "Primary_Blue_Hover": "accent_hover",
    "Primary_Blue_Mid": "accent_mid",
    "Primary_Blue_Light": "accent_light",
    "Primary_Blue_Text_Soft": "accent_text_soft",
    "Input_Border": "input_border",
    "Checkbox_Border": "border",
    "Input_Border_Soft": "border_soft",
    "Button_Primary_Stop_0": "button_primary_stop_0",
    "Button_Primary_Stop_1": "button_primary_stop_1",
    "Button_Primary_Stop_2": "button_primary_stop_2",
    "Button_Primary_Stop_3": "button_primary_stop_3",
    "Button_Primary_Hover_Stop_0": "button_primary_hover_stop_0",
    "Button_Primary_Hover_Stop_1": "button_primary_hover_stop_1",
    "Button_Primary_Hover_Stop_2": "button_primary_hover_stop_2",
    "Button_Primary_Hover_Stop_3": "button_primary_hover_stop_3",
    "Button_Secondary_Start": "button_secondary_start",
    "Button_Secondary_Mid": "button_secondary_mid",
    "Button_Secondary_End": "button_secondary_end",
    "Button_Primary_Text": "button_primary_text",
    "Button_Secondary_Text": "button_secondary_text",
    "Checkbox_Text": "checkbox_text",
    "Checkbox_Checked_Start": "checkbox_checked_start",
    "Checkbox_Checked_End": "checkbox_checked_end",
    "Table_Selection_Background": "table_selection_bg",
    "Table_Selection_Text": "table_selection_text",
    "Table_Header_Background": "table_header_bg",
    "Table_Header_Text": "table_header_text",
    "Status_Blue_Background": "status_blue_bg",
    "Status_Blue_Text": "status_blue_text",
    "Status_Blue_Border": "status_blue_border",
    "Status_Success_Text": "status_success_text",
    "Status_Fail_Text": "status_fail_text",
}

COLOR_DIALOG_GROUPS = [
    ("기본 테마", [
        ("메인 강조색", "Primary_Blue"),
        ("버튼 끝 어두운 색", "Primary_Blue_Dark"),
        ("버튼 마우스오버 색", "Primary_Blue_Hover"),
        ("카드 제목 글씨", "Card_Title_Text"),
        ("카드 테두리", "Card_Border"),
        ("카드 그림자", "Sierra_Shadow"),
    ]),
    ("버튼", [
        ("기본 버튼 시작 하이라이트", "Button_Primary_Stop_0"),
        ("기본 버튼 밝은 파랑", "Button_Primary_Stop_1"),
        ("기본 버튼 중심 파랑", "Button_Primary_Stop_2"),
        ("기본 버튼 끝 진파랑", "Button_Primary_Stop_3"),
        ("마우스오버 시작 하이라이트", "Button_Primary_Hover_Stop_0"),
        ("마우스오버 밝은 파랑", "Button_Primary_Hover_Stop_1"),
        ("마우스오버 중심 파랑", "Button_Primary_Hover_Stop_2"),
        ("마우스오버 끝 파랑", "Button_Primary_Hover_Stop_3"),
        ("기본 버튼 글씨", "Button_Primary_Text"),
        ("보조 버튼 글씨", "Button_Secondary_Text"),
    ]),
    ("체크박스 / 테이블", [
        ("체크박스 글씨", "Checkbox_Text"),
        ("체크박스 테두리", "Checkbox_Border"),
        ("체크 시 시작 색", "Checkbox_Checked_Start"),
        ("체크 시 끝 색", "Checkbox_Checked_End"),
        ("테이블 선택 배경", "Table_Selection_Background"),
        ("테이블 선택 글씨", "Table_Selection_Text"),
        ("테이블 헤더 글씨", "Table_Header_Text"),
    ]),
    ("그래프", [
        ("Threat Trend - Detection - XDR", "Threat_trend_Detection"),
        ("Threat Trend - Email - XDR", "Threat_trend_Detection_XDR"),
        ("Threat Trend - Email", "Threat_trend_Email"),
        ("Threat Trend - File", "Threat_trend_File"),
    ]),
]

COLOR_SETTING_TOOLTIPS = {
    "Primary_Blue": "앱 전체에서 가장 자주 쓰이는 메인 강조색입니다.",
    "Primary_Blue_Dark": "버튼 끝부분과 깊이감을 만드는 어두운 강조색입니다.",
    "Primary_Blue_Hover": "버튼 위에 마우스를 올렸을 때 보이는 강조색입니다.",
    "Card_Title_Text": "대시보드 카드와 섹션 제목에 표시되는 글씨 색입니다.",
    "Card_Border": "카드, 미리보기 영역, 구분선 주변의 옅은 테두리 색입니다.",
    "Sierra_Shadow": "카드 그림자와 일부 아이콘 그림자에 사용하는 기준 색입니다.",
    "Button_Primary_Stop_0": "Primary 버튼 왼쪽 위의 밝은 하이라이트 색입니다.",
    "Button_Primary_Stop_1": "Primary 버튼 상단/초반부에 보이는 밝은 파랑입니다.",
    "Button_Primary_Stop_2": "Primary 버튼 중앙에 가장 많이 보이는 대표 파랑입니다.",
    "Button_Primary_Stop_3": "Primary 버튼 오른쪽 아래의 깊이감 있는 진파랑입니다.",
    "Button_Primary_Hover_Stop_0": "마우스오버 Primary 버튼 왼쪽 위 하이라이트 색입니다.",
    "Button_Primary_Hover_Stop_1": "마우스오버 Primary 버튼의 밝은 파랑 영역입니다.",
    "Button_Primary_Hover_Stop_2": "마우스오버 Primary 버튼 중앙의 대표 파랑입니다.",
    "Button_Primary_Hover_Stop_3": "마우스오버 Primary 버튼 오른쪽 아래의 진한 파랑입니다.",
    "Button_Primary_Text": "기본(Primary) 버튼 텍스트 색입니다.",
    "Button_Secondary_Text": "보조(Secondary) 버튼 텍스트 색입니다.",
    "Checkbox_Text": "체크박스 라벨 텍스트 색입니다.",
    "Checkbox_Border": "체크박스 외곽선과 보조 버튼 테두리에 쓰이는 색입니다.",
    "Checkbox_Checked_Start": "체크된 체크박스 표시의 시작 그라데이션 색입니다.",
    "Checkbox_Checked_End": "체크된 체크박스 표시의 끝 그라데이션 색입니다.",
    "Table_Selection_Background": "테이블에서 선택된 행의 배경색입니다.",
    "Table_Selection_Text": "테이블에서 선택된 행의 글씨 색입니다.",
    "Table_Header_Text": "테이블 헤더 라벨의 글씨 색입니다.",
    "Threat_trend_Detection": "Threat Trend 그래프의 Detection - XDR 선/막대 색입니다.",
    "Threat_trend_Detection_XDR": "Threat Trend 그래프의 Email - XDR 선/막대 색입니다.",
    "Threat_trend_Email": "Threat Trend 그래프의 Email 선/막대 색입니다.",
    "Threat_trend_File": "Threat Trend 그래프의 File 선/막대 색입니다.",
}


def normalize_hex_color(value, fallback):
    value = str(value or "").strip()
    if value and not value.startswith("#") and len(value) in (3, 6):
        value = f"#{value}"
    if QColor(value).isValid():
        return QColor(value).name()
    return QColor(fallback).name() if QColor(fallback).isValid() else fallback


def hex_to_rgb_tuple(value, fallback="#5F8FAF"):
    color = QColor(normalize_hex_color(value, fallback))
    return (color.red(), color.green(), color.blue())




def default_color_config():
    return dict(DEFAULT_COLOR_CONFIG)


def load_color_env(path=COLOR_ENV_PATH):
    config = default_color_config()
    raw = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    raw[key.strip()] = value.strip()
        except Exception as e:
            log.warning(f"Failed to load color env: {e}")

    for key, fallback in DEFAULT_COLOR_CONFIG.items():
        value = raw.get(key)
        if value is None:
            for alias in COLOR_ENV_ALIAS.get(key, []):
                if alias in raw:
                    value = raw[alias]
                    break
        config[key] = normalize_hex_color(value or fallback, fallback)

    return config


def save_color_env(config, path=COLOR_ENV_PATH):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# UI Color Settings\n")
        f.write("# Format: KEY=#RRGGBB\n\n")
        for key, fallback in DEFAULT_COLOR_CONFIG.items():
            comment = COLOR_ENV_COMMENTS.get(key)
            if comment:
                f.write(f"# {comment}\n")
            f.write(f"{key}={normalize_hex_color(config.get(key, fallback), fallback)}\n")


def ensure_color_env_file(path=COLOR_ENV_PATH):
    config = load_color_env(path)
    if not os.path.exists(path):
        save_color_env(config, path)
    return config


def apply_color_config_to_theme(config):
    for config_key, theme_key in THEME_COLOR_MAP.items():
        UI_THEME[theme_key] = normalize_hex_color(
            config.get(config_key, DEFAULT_COLOR_CONFIG.get(config_key, "#000000")),
            DEFAULT_COLOR_CONFIG.get(config_key, "#000000"),
        )
    UI_THEME["accent_text"] = normalize_hex_color(config.get("Primary_Blue"), DEFAULT_COLOR_CONFIG["Primary_Blue"])
    UI_THEME["sierra_shadow"] = hex_to_rgb_tuple(config.get("Sierra_Shadow"), DEFAULT_COLOR_CONFIG["Sierra_Shadow"])
    UI_THEME["icon_glow"] = hex_to_rgb_tuple(config.get("Icon_Glow"), DEFAULT_COLOR_CONFIG["Icon_Glow"])


UI_FONT_FAMILY = (
    "'Aptos', 'Inter', 'Segoe UI Variable', 'SF Pro Text', "
    "'Noto Sans CJK KR', 'Noto Sans KR', 'Apple SD Gothic Neo', "
    "'Malgun Gothic', sans-serif"
)
UI_ICON_FONT_FAMILY = "'Segoe UI Symbol', 'Aptos', 'Inter', 'Segoe UI Variable', sans-serif"

SEARCH_FIELD_W = 150
SEARCH_MODE_W = 132
SEARCH_BTN_W = 34
SEARCH_ROW_H = 40
