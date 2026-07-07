# -*- coding: utf-8 -*-
import sys
import os
import json
import time
import webbrowser
import urllib.parse
import traceback
import logging
import sqlite3
import hashlib
import base64
import secrets
import math
import html
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

import re
import xml.etree.ElementTree as ET

import requests
import pandas as pd

from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

from dateutil.relativedelta import relativedelta

import matplotlib.patheffects as path_effects

# =============================
# PyQt Core
# =============================
from PyQt5.QtCore import (
    Qt, QTimer, QThread, pyqtSignal,
    QDate, QTime, QRectF, QPointF,
    QPropertyAnimation, QEasingCurve, QEvent
)

# =============================
# PyQt Widgets
# =============================
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QTabWidget, QStackedWidget,
    QHeaderView, QMenu, QFileDialog,
    QLabel, QMessageBox, QComboBox,
    QFrame, QDateEdit, QTimeEdit, QGroupBox, QColorDialog,
    QCheckBox, QSpinBox, QScrollArea, QSplitter,
    QDialog, QTextEdit, QShortcut,
    QSizePolicy, QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QAbstractSpinBox
)

# =============================
# PyQt GUI
# =============================
from PyQt5.QtGui import (
    QKeySequence,
    QTextCursor,
    QTextCharFormat,
    QColor, QPixmap, QPainter, QPen, QPainterPath
)


from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


# ======================================================
# File layout / future module boundaries
# ======================================================
# 1) Base paths and global constants
# 2) Theme/color configuration
# 3) Core utilities: JSON, SQLite cache/index, time, validation
# 4) Identity/org resolution and report exceptions
# 5) Timeline normalization, indexing, and search
# 6) API clients and background workers
# 7) UI widgets and MainWindow tabs
#
# Keep these sections clean so they can be moved into modules later without
# changing behavior.  The current file is still single-file on purpose while
# SQLite/index behavior stabilizes.

# ======================================================
# Base paths / global constants
# - Defines all local folders, env files, DB paths, and shared UI constants.
# ======================================================
def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_base_dir()
CACHE_DIR = os.path.join(BASE_DIR, "cache")
DETECTIONS_DAY_DIR = os.path.join(CACHE_DIR, "detections")
EMAILS_DAY_DIR = os.path.join(CACHE_DIR, "emails")
LIVE_DISCOVER_DIR = os.path.join(CACHE_DIR, "live_discover")
LOG_DIR = os.path.join(BASE_DIR, "logs")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
ENV_DIR = os.path.join(BASE_DIR, "env")
ENV_PATH = os.path.join(ENV_DIR, "Sophos_env.txt")
FIREWALL_ENV_PATH = os.path.join(ENV_DIR, "Firewall_env.txt")
DLP_ENV_PATH = os.path.join(ENV_DIR, "DLP_env.txt")
MAILSCREEN_ENV_PATH = os.path.join(ENV_DIR, "Mail_Screen_env.txt")
USER_GROUP_ENV_PATH = os.path.join(ENV_DIR, "User_group_env.txt")
REPORT_EXCEPTION_LIST_PATH = os.path.join(ENV_DIR, "Report_exception_List.txt")
COLOR_ENV_PATH = os.path.join(ENV_DIR, "Color_env.txt")
COLOR_THEME_DIR = os.path.join(ENV_DIR, "themes")
DLP_DAY_DIR = os.path.join(CACHE_DIR, "dlp")
MAILSCREEN_DAY_DIR = os.path.join(CACHE_DIR, "mailscreen")
TIMELINE_INDEX_DIR = os.path.join(CACHE_DIR, "index")
APP_CACHE_DB_PATH = os.path.join(TIMELINE_INDEX_DIR, "app_cache.db")
TIMELINE_INDEX_DB_PATH = os.path.join(TIMELINE_INDEX_DIR, "timeline_index.db")
TIMELINE_RENDER_BATCH_SIZE = 250
TIMELINE_DETAIL_ROW_LIMIT = 1000
TIMELINE_KEYWORD_INDEX_VERSION = "exact_phrase_v1"


os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DETECTIONS_DAY_DIR, exist_ok=True)
os.makedirs(EMAILS_DAY_DIR, exist_ok=True)
os.makedirs(LIVE_DISCOVER_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(DLP_DAY_DIR, exist_ok=True)
os.makedirs(MAILSCREEN_DAY_DIR, exist_ok=True)
os.makedirs(TIMELINE_INDEX_DIR, exist_ok=True)
os.makedirs(ENV_DIR, exist_ok=True)
os.makedirs(COLOR_THEME_DIR, exist_ok=True)

LOG_PATH = os.path.join(LOG_DIR, f"ui_engine_{datetime.now().strftime('%Y%m%d')}.log")
# 🔥 Auto Refresh 전용 로그
AUTO_LOG_PATH = os.path.join(
    LOG_DIR,
    f"auto_refresh_{datetime.now().strftime('%Y%m%d')}.log"
)

auto_logger = logging.getLogger("SophosAuto")
auto_logger.setLevel(logging.INFO)

auto_handler = logging.FileHandler(AUTO_LOG_PATH, encoding="utf-8")
auto_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
))

auto_logger.addHandler(auto_handler)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
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
    "Threat_trend_Outbound_Mail": "#ec4899",
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
    "Threat_trend_Outbound_Mail": ["Threat_trand_Outbound_Mail"],
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
        ("Threat Trend - Inbound Mail", "Threat_trend_Email"),
        ("Threat Trend - Outbound Mail", "Threat_trend_Outbound_Mail"),
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
    "Threat_trend_Email": "Threat Trend 그래프의 Inbound Mail 선/막대 색입니다.",
    "Threat_trend_Outbound_Mail": "Threat Trend 그래프의 Outbound Mail 선/막대 색입니다.",
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




def get_detection_sensor_type(detection):
    if not isinstance(detection, dict):
        return ""

    sensor = detection.get("sensor", {})
    if isinstance(sensor, dict):
        sensor_type = str(sensor.get("type", "") or "").strip().lower()
        if sensor_type:
            return sensor_type

    for key in ("sensorType", "sensor_type", "type", "source"):
        value = str(detection.get(key, "") or "").strip().lower()
        if value in {"endpoint", "email"}:
            return value

    dd = detection.get("detectionDescription", {})
    if isinstance(dd, dict):
        reason = str(dd.get("createdReasonId", "") or "").strip()
        if reason in XDR_EMAIL_RULES:
            return "email"

    return ""
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


# ======================================================
# Core storage / JSON cache fallback
# - Reads the original JSON/JSONL cache files.
# - SQLite loaders below fall back here if DB/index access fails.
# - Later module target: core/storage/json_cache.py
# ======================================================

def load_detections_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            DETECTIONS_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.json"
        )

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        results.extend(data)
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded detections from {start_date} ~ {end_date} : {len(results)}")
    return results


def load_emails_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            EMAILS_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.json"
        )

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        results.extend(data)
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded emails from {start_date} ~ {end_date} : {len(results)}")
    return results

def get_selected_range_days(days: int):
    end = datetime.now()
    start = end - timedelta(days=days)

    return (
        start.strftime("%Y-%m-%d"),
        end.strftime("%Y-%m-%d"),
    )


# ======================================================
# Utils
# ======================================================
def parse_multiline_domains(text: str):
    results = []
    seen = set()

    for line in str(text or "").splitlines():
        domain = line.strip()
        if not domain:
            continue
        if domain in seen:
            continue
        seen.add(domain)
        results.append(domain)

    return results

DLP_AI_DEST_KW = [
    "openai", "chatgpt", "oaiusercontent", "claude", "claudeusercontent",
    "gemini", "copilot", "perplexity", "ppl-ai-file-upload", "midjourney",
    "magnific", "klingai", "zeta-ai", "aspose.ai", "genspark",
    "aicreation", "gamma.app", "vizcom", "firefly", "sensei.adobe",
    "vyro.ai", "chaton.ai", "flowith.io", "linnk.ai", "upscale.media",
    "miricanvas", "clovanote", "deevid.ai", "nano-banana.ai", "napkin.ai",
    "picaapi.com", "meshy.ai", "topazlabs", "photoroom",
    "picsart", "krea.ai", "use.ai", "clova-x.naver.com", "polarishare",
    "livewiki", "freepik", "chat-orchestrator-prod", "aistudio.google.com", "aigc",
]

DLP_CONVERTER_DEST_KW = [
    "ilovepdf.com", "iloveimg.com", "convertio.me", "cloudconvert.com",
    "smallpdf", "freeconvert.com", "pdfaid.com", "ezgif.com",
    "allinpdf.com", "pdf24.org", "pdfguru.com", "thebestpdf.com",
    "onlinedoctranslator.com", "tinypng.com", "tinyjpg.com", "imagetostl.com",
    "runconvert.com", "transloadit.com", "pdfhouse.com",
]

DLP_MESSENGER_DEST_KW = [
    "slack.com", "slack-edge.com", "chat.google.com", "talk.naver.com",
    "channel.io", "intercomcdn.com", "intercomcdn.eu", "zendesk.com",
    "instagram.com", "whatsapp", "skype.com", "chat.linkareer.com",
]

DLP_CLOUD_DEST_KW = [
    "dropbox", "onedrive", "sharepoint", "box.com", "notion", "confluence",
    "wetransfer", "mega", "icloud", "pcloud", "cloudflarestorage.com",
    "blob.core.windows.net", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "s3.amazonaws.com", "amazonaws-s3", "s3-accelerate.amazonaws.com",
    "sandollcloud.com", "mybox.naver.com", "ncloud.com", "hancomdocs.com",
    "graph.microsoft.com", "officeapps.live.com", "teams.microsoft.com",
    "my.microsoftpersonalcontent.com", "objects-origin.githubusercontent.com",
    "supabase.co", "cloudfront.net", "aliyuncs.com", "ktcloud.com",
]

DLP_DESIGN_DEST_KW = [
    "figma.com", "canva.com", "miro.com", "lucid.app", "adobe.io",
    "shutterstock.com", "sandollcloud.com", "bizhows.com", "mangoboard",
    "freepik", "photoroom", "picsart", "krea.ai", "topazlabs",
]

DLP_SOCIAL_DEST_KW = [
    "upload.youtube.com", "upload.x.com", "tiktokcdn", "facebook.com",
    "threads.com", "pinterest.com", "x.com", "instagram.com",
    "upload.facebook.com", "vupload-edge.facebook.com", "u.pinimg.com",
]

DLP_COMMERCE_DEST_KW = [
    "seller", "vendorcentral.amazon", "sellercentral.amazon", "partner.",
    "partners.", "lotteon", "cjonstyle", "temu.com", "wconcept",
    "wadiz", "coupang", "navercorp.com", "shopee", "alibaba",
    "made-in-china", "baemin", "coupangeats", "29cm", "giftishow",
    "shopping.naver.com", "ssg", "kurly", "welstorymall", "kcp.co.kr",
]

DLP_HR_DEST_KW = [
    "saramin.co.kr", "greetinghr.com", "recruiter.co.kr", "recruit.",
    "ninehire", "albamon.com", "jobkorea.co.kr", "mokahr.com",
    "incruit.com", "jobda.im", "careernote.io", "specter.co.kr",
    "sterlingdirect.com", "ashbyhq",
]

DLP_MARKETING_DEST_KW = [
    "gfa.naver.com", "ad-creative.gfa.naver.com", "ads.naver.com",
    "doubleclick.net", "groobee.io", "dable.io", "stackadapt.com",
    "tiktok.com", "onaudience.com", "ipredictive.com", "mediamixer.co.kr",
    "adpnut.com", "adnmore.co.kr", "mtgroup.kr", "doyouad.com",
    "sauceflex.com", "quantummetric.com", "dataflare.net",
]

DLP_BUSINESS_DEST_KW = [
    "opensurvey.io", "bsgglobal.net", "licensingworkspace.com", "hancomdocs.com",
    "bizhows.com", "pokemonkorea.co.kr", "fss.or.kr", "energy.or.kr",
    "rnd.or.kr", "worldjob.or.kr", "axa.co.kr", "meritzfire.com",
    "samsungfire.com", "kbinsure.co.kr", "easypay.co.kr", "ezwel.com",
    "pay.naver.com", "payoneer.com", "typeform", "atlassian.net",
    "notability.com", "githubusercontent.com", "captcha.com", "google.com",
]


def _strip_dlp_origin_suffix(value: str) -> str:
    return re.sub(r"\s*\(\s*origin\s*:\s*[^)]*\)\s*$", "", str(value or ""), flags=re.IGNORECASE).strip()


def _extract_report_hostname(value: str):
    s = _strip_dlp_origin_suffix(value).strip().strip('"\'')
    if not s:
        return ""

    if s.startswith("\\"):
        parts = [p for p in s.split("\\") if p]
        return parts[0].lower() if parts else "internal-file-server"

    if s.startswith("/") or re.match(r"^[a-z]:[\\/]", s, flags=re.IGNORECASE):
        return "local-file-path"

    if " " in s:
        s = s.split()[0]

    s = s.rstrip(".,;)")

    try:
        from urllib.parse import urlparse

        parsed = urlparse(s if "://" in s else f"//{s}")
        if parsed.hostname:
            return parsed.hostname.lower().strip("[]")
    except Exception:
        pass

    if "/" in s:
        s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    if ":" in s and s.count(":") == 1:
        s = s.split(":", 1)[0]

    return s.lower().strip("[]")


def _collapse_report_hostname(hostname: str) -> str:
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return ""

    if host == "local-file-path":
        return "로컬 경로"

    if host.startswith("www."):
        host = host[4:]

    if re.fullmatch(r"api\d+(?:-cf)?\.ilovepdf\.com", host) or host.endswith(".ilovepdf.com"):
        return "ilovepdf.com"
    if re.fullmatch(r"api\d+\.iloveimg\.com", host) or host.endswith(".iloveimg.com"):
        return "iloveimg.com"
    if re.fullmatch(r"s\d+[-a-z]*\.convertio\.me", host) or host.endswith(".convertio.me"):
        return "convertio.me"
    if host.endswith(".freeconvert.com"):
        return "freeconvert.com"
    if host.endswith(".cloudconvert.com"):
        return "cloudconvert.com"
    if host.endswith(".transloadit.com"):
        return "transloadit.com"
    if host.startswith("filetools") and host.endswith(".pdf24.org"):
        return "pdf24.org"
    if host.endswith(".oaiusercontent.com"):
        return "oaiusercontent.com"
    if host.endswith(".claudeusercontent.com"):
        return "claudeusercontent.com"
    if host.endswith(".cloudflarestorage.com"):
        return "cloudflarestorage.com"
    if host.endswith(".blob.core.windows.net"):
        return "blob.core.windows.net"
    if host.endswith(".sharepoint.com"):
        return "sharepoint.com"
    if host.endswith(".storage.googleapis.com") or host == "storage.googleapis.com":
        return "storage.googleapis.com"
    if (
        host == "s3.amazonaws.com"
        or host.startswith("s3.") and host.endswith("amazonaws.com")
        or host.startswith("s3-") and host.endswith("amazonaws.com")
        or ".s3" in host and host.endswith("amazonaws.com")
    ):
        return "amazonaws-s3"
    if host.endswith(".mail.naver.com"):
        return "mail.naver.com"
    if host.endswith(".tiktokcdn.com") or "tiktokcdn" in host:
        return "tiktokcdn.com"

    return host


def normalize_report_destination(value):
    s = str(value or "").strip()
    if not s or s.lower() == "none":
        return "None"

    if s.startswith("\\"):
        return "내부 파일서버"
    if s.startswith("/") or re.match(r"^[a-z]:[\\/]", s, flags=re.IGNORECASE):
        return "로컬 경로"

    hostname = _extract_report_hostname(s)
    collapsed = _collapse_report_hostname(hostname)
    return collapsed or s.lower()


def classify_dlp_destination(target_name="", target_type="", dest_detail=""):
    target = str(target_name or "").strip().lower()
    ttype = str(target_type or "").strip().lower()
    raw_detail = str(dest_detail or "").strip().lower()
    normalized_detail = normalize_report_destination(dest_detail)
    normalized_l = str(normalized_detail or "").lower()
    haystack = " ".join([target, ttype, raw_detail, normalized_l])

    if normalized_detail == "내부 파일서버" or raw_detail.startswith("\\"):
        return "내부 파일서버"
    if normalized_detail == "로컬 경로" or raw_detail.startswith("/"):
        return "로컬/앱 임시파일"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", normalized_l):
        return "IP 직접 접속"

    if any(k in haystack for k in DLP_AI_DEST_KW):
        return "AI/생성형AI"
    if any(k in haystack for k in DLP_CONVERTER_DEST_KW):
        return "문서/PDF/이미지 변환"
    if ttype == "e-mail" or "mail" in normalized_l or ".mail." in raw_detail:
        return "메일/대용량 첨부"
    if target in {"kakaotalk", "nateon messenger", "naver line", "wechat", "viber", "messages", "whatsapp.root.dll"}:
        return "메신저/고객상담"
    if any(k in haystack for k in DLP_MESSENGER_DEST_KW):
        return "메신저/고객상담"
    if any(k in haystack for k in DLP_SOCIAL_DEST_KW):
        return "소셜/미디어 업로드"
    if any(k in haystack for k in DLP_DESIGN_DEST_KW):
        return "디자인/협업 SaaS"
    if ttype == "cloud services / file sharing" or target in {"airdrop outgoing", "filezilla", "google drive file stream"}:
        return "클라우드/오브젝트 스토리지"
    if any(k in haystack for k in DLP_CLOUD_DEST_KW):
        return "클라우드/오브젝트 스토리지"
    if any(k in haystack for k in DLP_HR_DEST_KW):
        return "채용/HR"
    if any(k in haystack for k in DLP_MARKETING_DEST_KW):
        return "광고/마케팅/분석"
    if any(k in haystack for k in DLP_COMMERCE_DEST_KW):
        return "쇼핑몰/판매자/파트너 포털"
    if any(k in haystack for k in DLP_BUSINESS_DEST_KW):
        return "업무/공공/금융 포털"

    return "웹 브라우저/기타"

def validate_domain_list(domain_list: list):
    invalid_domains = []

    for domain in domain_list:
        value = str(domain).strip()

        if not value:
            invalid_domains.append(domain)
            continue

        if " " in value:
            invalid_domains.append(domain)
            continue

        if "." not in value:
            invalid_domains.append(domain)
            continue

        if value.startswith(".") or value.endswith("."):
            invalid_domains.append(domain)
            continue

        parts = value.split(".")
        valid = True

        for part in parts:
            if not part:
                valid = False
                break

            for ch in part:
                if not (ch.isalnum() or ch == "-"):
                    valid = False
                    break

            if not valid:
                break

        if not valid:
            invalid_domains.append(domain)

    if invalid_domains:
        return False, invalid_domains

    return True, []


def load_json(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_jsonl(path):
    results = []

    if not os.path.exists(path):
        return results

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    row = json.loads(line)
                    if isinstance(row, dict):
                        results.append(row)
                except Exception as e:
                    log.warning(f"Failed to parse jsonl line in {path}: {e}")

    except Exception as e:
        log.warning(f"Failed to load jsonl file {path}: {e}")

    return results


def save_jsonl(path, rows):
    tmp = path + ".tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        for row in rows:
            if not isinstance(row, dict):
                continue
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    os.replace(tmp, path)


# ======================================================
# Core storage / SQLite app cache and indexed query tables
# - JSON refresh remains the source of truth.
# - app_cache_records stores raw rows for compatibility.
# - detection_events/email_events/dlp_events are indexed read models used by tabs, exports, and reports.
# - Later module target: core/storage/sqlite_cache.py
# ======================================================
APP_CACHE_SOURCES = {
    "detections": {"dir": DETECTIONS_DAY_DIR, "ext": ".json", "format": "json"},
    "emails": {"dir": EMAILS_DAY_DIR, "ext": ".json", "format": "json"},
    "dlp": {"dir": DLP_DAY_DIR, "ext": ".jsonl", "format": "jsonl"},
    "mailscreen": {
        "dir": MAILSCREEN_DAY_DIR,
        "ext": ".json",
        "format": "mailscreen",
        "filename_template": "mailscreen_mail_{date}.json",
        "date_regex": r"mailscreen_mail_(\d{4}-\d{2}-\d{2})\.json$",
    },
}

APP_CACHE_SINGLE_FILES = {
    "endpoints": os.path.join(CACHE_DIR, "endpoints.json"),
    "orgs": os.path.join(CACHE_DIR, "user_groups.json"),
    "users": os.path.join(CACHE_DIR, "users.json"),
}


def iter_date_strings(start_date: str, end_date: str):
    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    while current <= end:
        yield current.strftime("%Y-%m-%d")
        current += timedelta(days=1)


def app_cache_connect():
    os.makedirs(TIMELINE_INDEX_DIR, exist_ok=True)
    conn = sqlite3.connect(APP_CACHE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    init_app_cache_db(conn)
    return conn


def init_app_cache_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_cache_files (
            path TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            cache_date TEXT,
            mtime REAL NOT NULL,
            size INTEGER NOT NULL,
            rows INTEGER NOT NULL DEFAULT 0,
            indexed_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_cache_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            cache_date TEXT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_cache_records_source_date ON app_cache_records(source, cache_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_cache_records_file ON app_cache_records(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_cache_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detection_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            sensor_type TEXT,
            rule TEXT,
            hostname TEXT,
            mailbox TEXT,
            sender_ip TEXT,
            subject TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_date_sensor ON detection_events(event_date_kst, sensor_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_rule ON detection_events(rule)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_file ON detection_events(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            sender TEXT,
            recipients TEXT,
            subject TEXT,
            reason TEXT,
            client_ip TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_events_date ON email_events(event_date_kst)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_events_file ON email_events(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dlp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            machine_name TEXT,
            client_name TEXT,
            event_id TEXT,
            event_label TEXT,
            filename TEXT,
            destination TEXT,
            filehash TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_date ON dlp_events(event_date_kst)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_machine ON dlp_events(machine_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_file ON dlp_events(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mailscreen_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            seq TEXT,
            sender TEXT,
            sender_user_id TEXT,
            sender_email TEXT,
            sender_name TEXT,
            sender_detail TEXT,
            dept TEXT,
            receiver TEXT,
            subject TEXT,
            send_result TEXT,
            mail_process TEXT,
            policy TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    for column_name in ("sender_email", "sender_name"):
        try:
            conn.execute(f"ALTER TABLE mailscreen_events ADD COLUMN {column_name} TEXT")
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_date ON mailscreen_events(event_date_kst)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_sender_user_id ON mailscreen_events(sender_user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_sender_email ON mailscreen_events(sender_email)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sensitive_files_index (
            dedupe_key TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            categories TEXT NOT NULL,
            keywords TEXT NOT NULL,
            event_time TEXT,
            display_filename TEXT,
            user TEXT,
            user_id TEXT,
            dept TEXT,
            source_file TEXT,
            row_index INTEGER,
            search_text TEXT,
            record_json TEXT NOT NULL,
            indexed_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_files_source_category_time ON sensitive_files_index(source, category, event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_files_category_time ON sensitive_files_index(category, event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_files_time ON sensitive_files_index(event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_files_search ON sensitive_files_index(search_text)")
    for column_sql in ("source_file TEXT", "row_index INTEGER"):
        try:
            conn.execute(f"ALTER TABLE sensitive_files_index ADD COLUMN {column_sql}")
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_files_source_file ON sensitive_files_index(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sensitive_sites_index (
            dedupe_key TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            categories TEXT NOT NULL,
            keywords TEXT NOT NULL,
            event_time TEXT,
            site TEXT,
            url TEXT,
            user TEXT,
            user_id TEXT,
            dept TEXT,
            source_file TEXT,
            row_index INTEGER,
            search_text TEXT,
            record_json TEXT NOT NULL,
            indexed_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_sites_source_category_time ON sensitive_sites_index(source, category, event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_sites_category_time ON sensitive_sites_index(category, event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_sites_time ON sensitive_sites_index(event_time DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_sites_search ON sensitive_sites_index(search_text)")
    for column_sql in ("source_file TEXT", "row_index INTEGER"):
        try:
            conn.execute(f"ALTER TABLE sensitive_sites_index ADD COLUMN {column_sql}")
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_sites_source_file ON sensitive_sites_index(source_file)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_sender_name ON mailscreen_events(sender_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_sender ON mailscreen_events(sender)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mailscreen_events_file ON mailscreen_events(source_file)")


def load_cache_file_rows(path, file_format):
    if file_format == "jsonl":
        return load_jsonl(path)
    data = load_json(path)
    if file_format == "mailscreen" and isinstance(data, dict):
        items = data.get("items", [])
        return items if isinstance(items, list) else []
    return data if isinstance(data, list) else []


def dt_to_kst_date_text(dt, fallback_date=""):
    if not dt:
        return fallback_date or ""
    try:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return fallback_date or ""


def detection_index_values(row, source, path, idx, cache_date, raw_json):
    event_dt = iso_to_kst_dt(row.get("time")) if isinstance(row, dict) else None
    event_date = dt_to_kst_date_text(event_dt, cache_date)
    sensor_type = get_detection_sensor_type(row)
    dd = row.get("detectionDescription", {}) if isinstance(row, dict) else {}
    rule = ""
    if isinstance(dd, dict):
        rule = str(dd.get("createdReasonId", "") or "").strip()
    if not rule and isinstance(row, dict):
        rule = str(row.get("detectionRule", "") or "").strip()
    raw = row.get("rawData", {}) if isinstance(row, dict) and isinstance(row.get("rawData"), dict) else {}
    hostname = str(raw.get("meta_hostname", "") or "").strip()
    mailbox = ""
    sender_ip = ""
    subject = ""
    if sensor_type == "email":
        try:
            xdr = extract_xdr_email_fields(row)
            mailbox = str(xdr.get("mailbox", "") or "").strip()
            sender_ip = str(xdr.get("sender_ip", "") or "").strip()
            subject = str(xdr.get("subject", "") or "").strip()
        except Exception:
            pass
    return (
        path,
        idx,
        cache_date,
        row.get("time") if isinstance(row, dict) else "",
        event_date,
        sensor_type,
        rule,
        hostname,
        mailbox,
        sender_ip,
        subject,
        raw_json,
    )


def email_index_values(row, source, path, idx, cache_date, raw_json):
    event_time = row.get("receivedAt") if isinstance(row, dict) else ""
    event_date = dt_to_kst_date_text(iso_to_kst_dt(event_time), cache_date)
    from_addr = ""
    recipients = ""
    if isinstance(row, dict):
        try:
            from_addr = email_addr(row.get("from"))
            to_list = [email_addr(x) for x in (row.get("to", []) or []) if isinstance(x, dict)]
            cc_list = [email_addr(x) for x in (row.get("cc", []) or []) if isinstance(x, dict)]
            recipients = join_list(to_list + cc_list)
        except Exception:
            pass
    return (
        path,
        idx,
        cache_date,
        event_time,
        event_date,
        from_addr,
        recipients,
        str(row.get("subject", "") or "") if isinstance(row, dict) else "",
        str(row.get("reason", "") or "") if isinstance(row, dict) else "",
        str(row.get("clientIp", "") or "") if isinstance(row, dict) else "",
        raw_json,
    )


def dlp_index_values(row, source, path, idx, cache_date, raw_json):
    event_time = str(row.get("eventtimelocal", "") or "") if isinstance(row, dict) else ""
    event_dt = dlp_time_to_dt(event_time)
    event_date = dt_to_kst_date_text(event_dt, cache_date)
    event_id = str(row.get("event_id", "") or "") if isinstance(row, dict) else ""
    return (
        path,
        idx,
        cache_date,
        event_time,
        event_date,
        str(row.get("machine_name", "") or "") if isinstance(row, dict) else "",
        str(row.get("client_name", "") or "") if isinstance(row, dict) else "",
        event_id,
        format_dlp_event_id(event_id),
        str(row.get("filename", "") or "") if isinstance(row, dict) else "",
        str(row.get("destination", "") or "") if isinstance(row, dict) else "",
        str(row.get("filehash", "") or "") if isinstance(row, dict) else "",
        raw_json,
    )


MAILSCREEN_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MAILSCREEN_BLANK_VALUES = {"", "none", "null", "nan", "미분류", "&nbsp;"}


def mailscreen_identity_text(value):
    text = html.unescape(str(value or "")).strip()
    text = re.sub(r"\s+", " ", text)
    return "" if text.lower() in MAILSCREEN_BLANK_VALUES else text


def mailscreen_extract_email(*values):
    for value in values:
        text = mailscreen_identity_text(value)
        if not text:
            continue
        m = MAILSCREEN_EMAIL_RE.search(text)
        if m:
            return m.group(0).strip()
    return ""


def resolve_mailscreen_sender_identity(row):
    if not isinstance(row, dict):
        return {
            "email": "",
            "user_id": "None",
            "user_name": "None",
            "dept_name": "미분류",
            "dept_code": "",
        }

    sender = mailscreen_identity_text(row.get("sender"))
    sender_detail = mailscreen_identity_text(row.get("sender_detail"))
    dept = mailscreen_identity_text(row.get("dept"))
    email_addr_text = mailscreen_extract_email(sender, sender_detail)
    local_user_id = email_addr_text.split("@", 1)[0].strip() if email_addr_text else ""
    display_sender = "" if "@" in sender else sender

    identity = {}
    if email_addr_text:
        identity = resolve_identity_by_mailbox(email_addr_text)

    directory_info = get_directory_user_info(email_addr_text, local_user_id, display_sender)
    if not email_addr_text and directory_info:
        email_addr_text = str(directory_info.get("email", "") or "").strip()
        local_user_id = str(directory_info.get("user_id", "") or "").strip()

    user_id = str(identity.get("user_id", "") or "").strip()
    if user_id in {"", "None"}:
        user_id = str(directory_info.get("user_id", "") or "").strip() or local_user_id
    if not user_id:
        user_id = "None"

    user_name = str(identity.get("user_name", "") or "").strip()
    if user_name in {"", "None"}:
        user_name = str(directory_info.get("name", "") or "").strip() or display_sender
    if not user_name and sender and "@" in sender:
        user_name = local_user_id
    if not user_name:
        user_name = "None"

    dept_name = dept
    dept_code = ""
    if not dept_name:
        dept_name = str(identity.get("dept_name", "") or "").strip()
        dept_code = str(identity.get("dept_code", "") or "").strip()
    if (not dept_name or dept_name == "미분류") and directory_info:
        dept_name = str(directory_info.get("dept_name", "") or "").strip() or dept_name
        dept_code = str(directory_info.get("dept_code", "") or "").strip() or dept_code
    if (not dept_name or dept_name == "미분류") and (display_sender or local_user_id):
        org_dept, org_code = get_org_info_by_user(display_sender or user_name, local_user_id)
        dept_name = org_dept or dept_name
        dept_code = org_code or dept_code
    if not dept_name:
        dept_name = "미분류"

    return {
        "email": email_addr_text,
        "user_id": user_id,
        "user_name": user_name,
        "dept_name": dept_name,
        "dept_code": dept_code,
    }


def enrich_mailscreen_sender_fields(row):
    if not isinstance(row, dict):
        return row

    enriched = dict(row)
    identity = resolve_mailscreen_sender_identity(enriched)
    sender_email = mailscreen_identity_text(identity.get("email"))
    sender_name = mailscreen_identity_text(identity.get("user_name"))
    sender_dept = mailscreen_identity_text(identity.get("dept_name"))

    if not sender_email:
        sender_email = mailscreen_extract_email(enriched.get("sender"), enriched.get("sender_detail"))
    if not sender_name or sender_name == "None":
        raw_sender = mailscreen_identity_text(enriched.get("sender"))
        sender_name = "" if "@" in raw_sender else raw_sender
    if not sender_dept or sender_dept == "None":
        sender_dept = mailscreen_identity_text(enriched.get("dept"))

    enriched["sender_email"] = sender_email or "None"
    enriched["sender_name"] = sender_name or "None"
    enriched["sender_user_id"] = identity.get("user_id", "None") or "None"
    enriched["sender_dept"] = sender_dept or "None"
    enriched["sender"] = enriched["sender_email"] if enriched["sender_email"] != "None" else mailscreen_identity_text(enriched.get("sender")) or "None"
    enriched["dept"] = enriched["sender_dept"]
    return enriched


def mailscreen_index_values(row, source, path, idx, cache_date, raw_json):
    row = enrich_mailscreen_sender_fields(row)
    event_time = str(row.get("date", "") or "") if isinstance(row, dict) else ""
    event_dt = timeline_parse_dt(event_time)
    event_date = dt_to_kst_date_text(event_dt, cache_date)
    identity = resolve_mailscreen_sender_identity(row)
    return (
        path,
        idx,
        cache_date,
        event_time,
        event_date,
        str(row.get("seq", "") or "") if isinstance(row, dict) else "",
        mailscreen_identity_text(row.get("sender")) if isinstance(row, dict) else "",
        identity.get("user_id", "None"),
        mailscreen_identity_text(row.get("sender_email")) if isinstance(row, dict) else "",
        mailscreen_identity_text(row.get("sender_name")) if isinstance(row, dict) else "",
        mailscreen_identity_text(row.get("sender_detail")) if isinstance(row, dict) else "",
        identity.get("dept_name", "미분류"),
        mailscreen_identity_text(row.get("receiver")) if isinstance(row, dict) else "",
        str(row.get("subject", "") or "") if isinstance(row, dict) else "",
        str(row.get("send_result", "") or "") if isinstance(row, dict) else "",
        str(row.get("mail_process", "") or "") if isinstance(row, dict) else "",
        str(row.get("policy", "") or "") if isinstance(row, dict) else "",
        raw_json,
    )


APP_CACHE_INDEX_INSERTS = {
    "detections": (
        "DELETE FROM detection_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO detection_events
            (source_file, row_index, cache_date, event_time, event_date_kst, sensor_type, rule, hostname, mailbox, sender_ip, subject, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        detection_index_values,
    ),
    "emails": (
        "DELETE FROM email_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO email_events
            (source_file, row_index, cache_date, event_time, event_date_kst, sender, recipients, subject, reason, client_ip, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        email_index_values,
    ),
    "dlp": (
        "DELETE FROM dlp_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO dlp_events
            (source_file, row_index, cache_date, event_time, event_date_kst, machine_name, client_name, event_id, event_label, filename, destination, filehash, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        dlp_index_values,
    ),
    "mailscreen": (
        "DELETE FROM mailscreen_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO mailscreen_events
            (source_file, row_index, cache_date, event_time, event_date_kst, seq, sender, sender_user_id, sender_email, sender_name, sender_detail, dept, receiver, subject, send_result, mail_process, policy, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        mailscreen_index_values,
    ),
}


def sync_app_cache_file(conn, source, path, cache_date=None, file_format="json"):
    stat = os.stat(path)
    rows = load_cache_file_rows(path, file_format)
    if not isinstance(rows, list):
        rows = []

    conn.execute("DELETE FROM app_cache_records WHERE source_file = ?", (path,))
    index_spec = APP_CACHE_INDEX_INSERTS.get(source)
    if index_spec:
        conn.execute(index_spec[0], (path,))

    payload = []
    index_payload = []
    for idx, row in enumerate(rows):
        if not isinstance(row, (dict, list)):
            continue
        if source == "mailscreen" and isinstance(row, dict):
            row = enrich_mailscreen_sender_fields(row)
        raw_json = json.dumps(row, ensure_ascii=False)
        payload.append((source, cache_date, path, idx, raw_json))
        if index_spec and isinstance(row, dict):
            try:
                index_payload.append(index_spec[2](row, source, path, idx, cache_date, raw_json))
            except Exception as e:
                log.warning(f"SQLite index row build failed source={source} path={path} row={idx}: {e}")
    if payload:
        conn.executemany(
            """
            INSERT OR REPLACE INTO app_cache_records
                (source, cache_date, source_file, row_index, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            payload,
        )
    if index_payload:
        conn.executemany(index_spec[1], index_payload)
    conn.execute(
        """
        INSERT OR REPLACE INTO app_cache_files
            (path, source, cache_date, mtime, size, rows, indexed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            path,
            source,
            cache_date,
            float(stat.st_mtime),
            int(stat.st_size),
            len(payload),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    return len(payload)


def app_cache_file_current(conn, path):
    if not os.path.exists(path):
        return True
    stat = os.stat(path)
    row = conn.execute(
        "SELECT mtime, size FROM app_cache_files WHERE path = ?",
        (path,),
    ).fetchone()
    if not row:
        return False
    return float(row[0] or 0) == float(stat.st_mtime) and int(row[1] or 0) == int(stat.st_size)


def app_cache_file_row_count(conn, path):
    row = conn.execute(
        "SELECT rows FROM app_cache_files WHERE path = ?",
        (path,),
    ).fetchone()
    if not row:
        return None
    try:
        return int(row[0] or 0)
    except Exception:
        return None


def app_cache_index_current(conn, source, path):
    if not app_cache_file_current(conn, path):
        return False
    cached_rows = app_cache_file_row_count(conn, path)
    if cached_rows == 0:
        return True
    table_map = {
        "detections": "detection_events",
        "emails": "email_events",
        "dlp": "dlp_events",
        "mailscreen": "mailscreen_events",
    }
    table = table_map.get(source)
    if not table:
        return True
    try:
        if source == "mailscreen":
            return conn.execute(
                "SELECT 1 FROM mailscreen_events WHERE source_file = ? AND sender_email IS NOT NULL LIMIT 1",
                (path,),
            ).fetchone() is not None
        return conn.execute(f"SELECT 1 FROM {table} WHERE source_file = ? LIMIT 1", (path,)).fetchone() is not None
    except sqlite3.Error:
        return False


def sync_app_cache_range(source, start_date, end_date, progress_cb=None):
    cfg = APP_CACHE_SOURCES[source]
    stats = {"indexed": 0, "skipped": 0, "rows": 0, "files": 0, "source": source}
    with app_cache_connect() as conn:
        changed_paths = []
        for cache_date in iter_date_strings(start_date, end_date):
            filename = cfg.get("filename_template", "{date}{ext}").format(date=cache_date, ext=cfg["ext"])
            path = os.path.join(cfg["dir"], filename)
            if not os.path.exists(path):
                continue
            stats["files"] += 1
            if app_cache_index_current(conn, source, path):
                stats["skipped"] += 1
                continue
            if progress_cb:
                progress_cb(f"SQLite 데이터 반영중 - {source} {cache_date}")
            stats["rows"] += sync_app_cache_file(conn, source, path, cache_date, cfg["format"])
            changed_paths.append(path)
            stats["indexed"] += 1
        if changed_paths:
            log.info(
                "App cache range changed source=%s changed=%d sensitive_rebuild=%s",
                source,
                len(changed_paths),
                source in ("dlp", "mailscreen"),
            )
            if source in ("dlp", "mailscreen"):
                stats.update(
                    rebuild_sensitive_files_index(
                        conn,
                        changed_paths=changed_paths,
                        removed_paths=[],
                        progress_cb=progress_cb,
                    )
                )
            if source == "dlp":
                stats.update(
                    rebuild_sensitive_sites_index(
                        conn,
                        changed_paths=changed_paths,
                        removed_paths=[],
                        progress_cb=progress_cb,
                    )
                )
        conn.commit()
    return stats


def sync_app_cache_all(progress_cb=None):
    totals = {"data_rows": 0, "data_files": 0, "data_indexed": 0, "data_skipped": 0}
    with app_cache_connect() as conn:
        changed_paths = []
        removed_paths = []
        for source, cfg in APP_CACHE_SOURCES.items():
            for path in iter_json_files(cfg["dir"], cfg["ext"]):
                cache_date = os.path.splitext(os.path.basename(path))[0]
                date_regex = cfg.get("date_regex")
                if date_regex:
                    m = re.search(date_regex, os.path.basename(path))
                    cache_date = m.group(1) if m else cache_date
                totals["data_files"] += 1
                if app_cache_index_current(conn, source, path):
                    totals["data_skipped"] += 1
                    continue
                if progress_cb:
                    progress_cb(f"SQLite 데이터 반영중 - {source} {cache_date}")
                totals["data_rows"] += sync_app_cache_file(conn, source, path, cache_date, cfg["format"])
                changed_paths.append(path)
                totals["data_indexed"] += 1
        for source, path in APP_CACHE_SINGLE_FILES.items():
            if not os.path.exists(path):
                continue
            totals["data_files"] += 1
            if app_cache_file_current(conn, path):
                totals["data_skipped"] += 1
                continue
            if progress_cb:
                progress_cb(f"SQLite 데이터 반영중 - {source}")
            totals["data_rows"] += sync_app_cache_file(conn, source, path, None, "json")
            changed_paths.append(path)
            totals["data_indexed"] += 1
        existing_paths = set()
        for source, cfg in APP_CACHE_SOURCES.items():
            existing_paths.update(iter_json_files(cfg["dir"], cfg["ext"]))
        existing_paths.update(path for path in APP_CACHE_SINGLE_FILES.values() if os.path.exists(path))
        stale_rows = conn.execute("SELECT path FROM app_cache_files").fetchall()
        removed = 0
        for (path,) in stale_rows:
            if path not in existing_paths:
                conn.execute("DELETE FROM app_cache_records WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM detection_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM email_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM dlp_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM mailscreen_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM app_cache_files WHERE path = ?", (path,))
                removed_paths.append(path)
                removed += 1
        totals["data_removed"] = removed
        log.info(
            "App cache sync changed=%d removed=%d changed_dlp=%d removed_dlp=%d",
            len(changed_paths),
            len(removed_paths),
            sum(1 for path in changed_paths if str(path).endswith(".jsonl") and f"{os.sep}dlp{os.sep}" in str(path)),
            sum(1 for path in removed_paths if str(path).endswith(".jsonl") and f"{os.sep}dlp{os.sep}" in str(path)),
        )
        totals.update(rebuild_sensitive_files_index(conn, changed_paths=changed_paths, removed_paths=removed_paths, progress_cb=progress_cb))
        totals.update(rebuild_sensitive_sites_index(conn, changed_paths=changed_paths, removed_paths=removed_paths, progress_cb=progress_cb))
        conn.commit()
        totals["data_total_rows"] = conn.execute("SELECT COUNT(*) FROM app_cache_records").fetchone()[0]
        totals["data_total_files"] = conn.execute("SELECT COUNT(*) FROM app_cache_files").fetchone()[0]
    totals["app_db_path"] = APP_CACHE_DB_PATH
    return totals


def load_app_cache_records(source, start_date=None, end_date=None):
    if start_date is not None and end_date is not None:
        sync_app_cache_range(source, start_date, end_date)

    with app_cache_connect() as conn:
        if start_date is not None and end_date is not None:
            rows = conn.execute(
                """
                SELECT raw_json FROM app_cache_records
                WHERE source = ? AND cache_date BETWEEN ? AND ?
                ORDER BY cache_date ASC, source_file ASC, row_index ASC
                """,
                (source, start_date, end_date),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT raw_json FROM app_cache_records
                WHERE source = ?
                ORDER BY source_file ASC, row_index ASC
                """,
                (source,),
            ).fetchall()
    results = []
    for (raw_json,) in rows:
        try:
            value = json.loads(raw_json)
            if isinstance(value, dict):
                results.append(value)
        except Exception as e:
            log.warning(f"SQLite cache row parse failed source={source}: {e}")
    return results


def load_app_cache_single(source, path, json_fallback=True):
    try:
        if os.path.exists(path):
            with app_cache_connect() as conn:
                if not app_cache_file_current(conn, path):
                    sync_app_cache_file(conn, source, path, None, "json")
                    conn.commit()
        rows = load_app_cache_records(source)
        if rows or not json_fallback:
            log.info(f"Loaded {source} from SQLite cache : {len(rows)}")
            return rows
    except Exception as e:
        log.warning(f"SQLite {source} load failed, fallback to JSON: {e}")
    return load_json(path)


def load_indexed_raw_rows(table, start_date, end_date, extra_where="", params=()):
    with app_cache_connect() as conn:
        sql = f"""
            SELECT raw_json FROM {table}
            WHERE COALESCE(NULLIF(event_date_kst, ''), cache_date) BETWEEN ? AND ?
            {extra_where}
            ORDER BY COALESCE(NULLIF(event_time, ''), cache_date) ASC, source_file ASC, row_index ASC
        """
        rows = conn.execute(sql, (start_date, end_date, *params)).fetchall()
    results = []
    for (raw_json,) in rows:
        try:
            value = json.loads(raw_json)
            if isinstance(value, dict):
                results.append(value)
        except Exception as e:
            log.warning(f"SQLite indexed row parse failed table={table}: {e}")
    return results


def load_indexed_detections_by_range(start_date, end_date, sensor_type=None, xdr_email_only=False):
    sync_app_cache_range("detections", start_date, end_date)
    extra = ""
    params = []
    if sensor_type:
        extra += " AND sensor_type = ?"
        params.append(sensor_type)
    if xdr_email_only:
        placeholders = ",".join(["?"] * len(XDR_EMAIL_RULES))
        extra += f" AND rule IN ({placeholders})"
        params.extend(sorted(XDR_EMAIL_RULES))
    return load_indexed_raw_rows("detection_events", start_date, end_date, extra, tuple(params))


def load_endpoint_detections_by_range(start_date, end_date):
    return load_indexed_detections_by_range(start_date, end_date, sensor_type="endpoint")


def load_xdr_email_detections_by_range(start_date, end_date):
    return load_indexed_detections_by_range(start_date, end_date, sensor_type="email", xdr_email_only=True)


def load_detections_by_range(start_date: str, end_date: str):
    try:
        rows = load_indexed_detections_by_range(start_date, end_date)
        log.info(f"Loaded detections from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite detections index load failed, fallback to JSON: {e}")
        return load_detections_by_range_json(start_date, end_date)


def load_emails_by_range(start_date: str, end_date: str):
    try:
        sync_app_cache_range("emails", start_date, end_date)
        rows = load_indexed_raw_rows("email_events", start_date, end_date)
        log.info(f"Loaded emails from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite emails index load failed, fallback to JSON: {e}")
        return load_emails_by_range_json(start_date, end_date)


def load_dlp_by_range(start_date: str, end_date: str):
    try:
        sync_app_cache_range("dlp", start_date, end_date)
        rows = load_indexed_raw_rows("dlp_events", start_date, end_date)
        log.info(f"Loaded DLP from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite DLP index load failed, fallback to JSON: {e}")
        return load_dlp_by_range_json(start_date, end_date)


def load_dlp_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            DLP_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.jsonl"
        )

        if os.path.exists(file_path):
            try:
                results.extend(load_jsonl(file_path))
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded DLP from {start_date} ~ {end_date} : {len(results)}")
    return results


def load_dlp_all_indexed_cache():
    rows = load_app_cache_records("dlp")
    log.info(f"Loaded DLP from SQLite index all cache : {len(rows)}")
    return rows


def load_mailscreen_all_indexed_cache():
    rows = load_app_cache_records("mailscreen")
    log.info(f"Loaded MailScreen from SQLite index all cache : {len(rows)}")
    return rows


def load_mailscreen_by_range(start_date: str, end_date: str):
    try:
        sync_app_cache_range("mailscreen", start_date, end_date)
        rows = load_indexed_raw_rows("mailscreen_events", start_date, end_date)
        log.info(f"Loaded MailScreen from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite MailScreen index load failed, fallback to JSON: {e}")

    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        date_str = current.strftime("%Y-%m-%d")
        file_path = os.path.join(MAILSCREEN_DAY_DIR, f"mailscreen_mail_{date_str}.json")
        if os.path.exists(file_path):
            try:
                payload = load_json(file_path)
                if isinstance(payload, dict):
                    items = payload.get("items", [])
                    if isinstance(items, list):
                        results.extend([enrich_mailscreen_sender_fields(item) for item in items if isinstance(item, dict)])
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")
        current += timedelta(days=1)

    log.info(f"Loaded MailScreen from {start_date} ~ {end_date} : {len(results)}")
    return results


# ======================================================
# Core utilities / DLP display helpers
# - Small formatting helpers shared by File tab, Timeline, export, and report.
# - Later module target: modules/dlp/formatters.py
# ======================================================
def format_dlp_event_id(value):
    event_id = str(value or "None")
    mapping = {
        "Content Threat Detected": "탐지됨",
        "Content Threat Blocked": "차단",
    }
    return mapping.get(event_id.strip(), event_id)


SENSITIVE_FILE_CATEGORY_SPECS = [
    ("이직 / 취업", [
        "이력서", "resume", "curriculum vitae", "자기소개서", "자소서",
        "포트폴리오", "portfolio", "경력기술서", "입사지원", "지원서",
        "면접", "채용", "잡코리아", "사람인", "원티드", "wanted",
        "linkedin", "링크드인", "cover letter",
    ]),
    ("결혼 / 웨딩 / 연애", [
        "결혼", "웨딩", "wedding", "상견례", "청첩장", "예식", "예식장",
        "스드메", "드레스", "혼수", "신혼", "신혼여행", "허니문",
        "혼인", "예물", "예단", "커플사진", "가족사진", "웨딩사진",
        "연애", "남친", "여친", "남자친구", "여자친구", "연인",
        "소개팅", "프로포즈", "커플", "커플링", "데이트사진", "오빠",
    ]),
    ("개인 증빙 / 금융", [
        "신분증", "주민등록증", "운전면허증", "여권", "가족관계증명서",
        "주민등록등본", "주민등록초본", "인감증명서", "통장사본",
        "계좌번호", "입금계좌", "입금내역", "거래내역", "잔액증명서",
        "원천징수", "소득금액", "급여명세서", "연말정산", "건강보험",
        "국민연금", "재직증명", "전세계약서", "월세계약서", "임대차계약서",
    ]),
    ("발주 / 주문 / 거래 문서", [
        "발주서", "주문서", "거래명세서", "출고양식", "수기발주",
        "공동구매", "매출내역", "invoice",
    ]),
    ("비용 / 영수증 / 정산", [
        "영수증", "결제증빙", "비용정산", "법카", "접대비", "회식비", "receipt",
    ]),
    ("계약 / 법무 / 사업자 증빙", [
        "계약서", "계약일반조건", "사업자등록증", "채권", "변제계획서",
    ]),
    ("제품 / 디자인 / 마케팅 자료", [
        "상세페이지", "썸네일", "렌더링", "로고", "누끼", "데켓",
        "택플로우", "TACTFLOW", "인플루언서", "시딩",
        "유튜브", "마케팅", "쇼츠", "숏츠", "론칭", "콜라보",
    ]),
    ("메신저 수신 파일", [
        "카카오톡 받은 파일", "kakaotalk", "kakaotalk download",
        "네이트온 받은 파일", "nateon", "wechat", "viber", "whatsapp",
        "telegram desktop", "messages/attachments", "xwechat_files",
        "viberdownloads", "discord",
    ]),
    ("개인 사진 / 영상", [
        "개인사진", "가족사진", "웨딩사진", "증명사진", "프로필사진",
        "셀카", "셀피", "selfie", "여행사진", "앨범", "본식사진",
        "스냅사진", "여권사진", "반명함",
    ]),
]


SENSITIVE_FILE_CATEGORY_REGEX_SPECS = []


def sensitive_row_text(row):
    field_text = " ".join(str(row.get(k, "") or "") for k in (
        "filename", "destination", "destination_type", "item_details",
        "destinationDetails", "machine_name", "client_name", "event_id",
    ))
    return f"{field_text} {json.dumps(row, ensure_ascii=False, default=str)}".lower()


def classify_sensitive_text(text, category_specs=SENSITIVE_FILE_CATEGORY_SPECS):
    text = str(text or "").lower()
    matched_categories = []
    matched_keywords = []
    for category, keywords in category_specs:
        hits = [kw for kw in keywords if kw.lower() in text]
        if hits:
            matched_categories.append(category)
            matched_keywords.extend(hits)
    for category, patterns in SENSITIVE_FILE_CATEGORY_REGEX_SPECS:
        hits = []
        for pattern, label in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(label)
        if hits:
            matched_categories.append(category)
            matched_keywords.extend(hits)
    if not matched_categories:
        return None
    return {
        "category": matched_categories[0],
        "categories": matched_categories,
        "keywords": sorted(set(matched_keywords), key=lambda x: x.lower()),
    }


def classify_sensitive_row(row, category_specs=SENSITIVE_FILE_CATEGORY_SPECS):
    return classify_sensitive_text(sensitive_row_text(row), category_specs)


def display_sensitive_file_name(path_text):
    text = str(path_text or "None").strip()
    if not text or text == "None":
        return "None"
    normalized = text.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] or text


def resolve_sensitive_user_name(machine_name, client_name):
    identity = resolve_identity_by_hostname(machine_name)
    user_name = str(identity.get("user_name", "") or "").strip()
    if user_name and user_name != "None":
        return user_name
    directory_info = get_directory_user_info(client_name)
    directory_name = str(directory_info.get("name", "") or "").strip()
    if directory_name:
        return directory_name
    org_name = get_org_user_name_by_user_id(client_name)
    if org_name:
        return org_name
    return str(client_name or "None")


def make_sensitive_record(row, category_specs=SENSITIVE_FILE_CATEGORY_SPECS):
    classified = classify_sensitive_row(row, category_specs)
    if not classified:
        return None
    machine_name = str(row.get("machine_name", "None") or "None")
    client_name = str(row.get("client_name", "None") or "None")
    dept_name, _ = get_dept_by_hostname(machine_name)
    filename = str(row.get("filename", "None") or "None")
    destination = str(row.get("destination", "None") or "None")
    destination_detail = str(row.get("item_details") or row.get("destinationDetails") or "None")
    return {
        "row": row,
        "source": "DLP",
        "category": classified["category"],
        "categories": classified["categories"],
        "keywords": classified["keywords"],
        "event_time": str(row.get("eventtimelocal", "") or ""),
        "event": format_dlp_event_id(row.get("event_id", "None")),
        "machine": machine_name,
        "dept": dept_name,
        "user": resolve_sensitive_user_name(machine_name, client_name),
        "user_id": client_name,
        "filename": filename,
        "display_filename": display_sensitive_file_name(filename),
        "destination": destination,
        "destination_type": str(row.get("destination_type", "None") or "None"),
        "destination_detail": destination_detail,
        "filehash": str(row.get("filehash", "None") or "None"),
    }


def sensitive_record_search_text(record):
    return " ".join(str(record.get(k, "") or "") for k in (
        "source", "category", "keywords", "event_time", "event", "machine",
        "dept", "user", "user_id", "filename", "display_filename",
        "destination", "destination_type", "destination_detail", "filehash",
        "mail_subject", "mail_sender", "mail_receiver", "mail_policy", "mail_attach_raw",
    )).lower()


MAILSCREEN_ATTACHMENT_EXTENSIONS = (
    "docx", "doc", "xlsx", "xls", "pptx", "ppt", "jpeg", "jpg",
    "pdf", "txt", "csv", "png", "heic", "gif", "bmp", "zip", "7z", "rar",
    "alz", "egg", "ai", "psd", "mp4", "mov", "avi", "eml", "msg",
)


def clean_mailscreen_attachment_name(value):
    text = str(value or "").strip()
    if not text or text == "None":
        return ""
    text = re.sub(r"\s*\(\s*\d+\s+more\s*\)\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*\(\s*[\d,.]+\s*(?:B|K|KB|M|MB|G|GB|T|TB)\s*\)\s*$", "", text, flags=re.IGNORECASE)
    return text.strip(" ,;|")


def extract_mailscreen_attachment_names(row):
    attach_text = str(row.get("attach", "") or "").strip() if isinstance(row, dict) else ""
    if not attach_text or attach_text == "None":
        return []

    ext_pattern = "|".join(re.escape(ext) for ext in MAILSCREEN_ATTACHMENT_EXTENSIONS)
    pattern = re.compile(
        rf"([^,;|\n]+?\.(?:{ext_pattern}))(?:\s*\([^)]*\))*",
        re.IGNORECASE,
    )
    names = []
    for match in pattern.finditer(attach_text):
        name = clean_mailscreen_attachment_name(match.group(1))
        if name and name not in names:
            names.append(name)

    if names:
        return names

    fallback = clean_mailscreen_attachment_name(attach_text)
    return [fallback] if fallback else []


def make_sensitive_mailscreen_record(row, attachment_name, category_specs=SENSITIVE_FILE_CATEGORY_SPECS):
    if not isinstance(row, dict):
        return None
    row = enrich_mailscreen_sender_fields(row)
    filename = clean_mailscreen_attachment_name(attachment_name)
    if not filename:
        return None

    subject = str(row.get("subject", "") or "")
    classified = classify_sensitive_text(f"{filename} {subject}", category_specs)
    if not classified:
        return None

    sender_email = mailscreen_identity_text(row.get("sender_email")) or mailscreen_identity_text(row.get("sender"))
    sender_name = mailscreen_identity_text(row.get("sender_name")) or sender_email or "None"
    user_id = mailscreen_identity_text(row.get("sender_user_id")) or sender_email or "None"
    dept_name = mailscreen_identity_text(row.get("sender_dept")) or mailscreen_identity_text(row.get("dept")) or "미분류"
    receiver = mailscreen_identity_text(row.get("receiver_detail")) or mailscreen_identity_text(row.get("receiver")) or "None"
    mail_process = str(row.get("mail_process", "") or "None")
    send_result = str(row.get("send_result", "") or "None")
    event = f"{mail_process}/{send_result}" if mail_process != "None" and send_result != "None" else (send_result or mail_process)

    return {
        "row": row,
        "source": "Outbound Mail",
        "category": classified["category"],
        "categories": classified["categories"],
        "keywords": classified["keywords"],
        "event_time": str(row.get("date", "") or ""),
        "event": event,
        "machine": "None",
        "dept": dept_name,
        "user": sender_name,
        "user_id": user_id,
        "filename": filename,
        "display_filename": display_sensitive_file_name(filename),
        "destination": receiver,
        "destination_type": "Outbound Mail Attachment",
        "destination_detail": str(row.get("subject", "") or "None"),
        "filehash": "None",
        "mail_subject": str(row.get("subject", "") or "None"),
        "mail_sender": sender_email or "None",
        "mail_receiver": receiver,
        "mail_size": str(row.get("size", "") or "None"),
        "mail_policy": str(row.get("policy", "") or "None"),
        "mail_process": mail_process,
        "mail_send_result": send_result,
        "mail_attach_raw": str(row.get("attach", "") or "None"),
    }


def build_sensitive_file_records(rows, category_specs=SENSITIVE_FILE_CATEGORY_SPECS, mailscreen_rows=None):
    records = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        record = make_sensitive_record(row, category_specs)
        if record:
            records.append(record)

    for row in mailscreen_rows or []:
        if not isinstance(row, dict):
            continue
        for attachment_name in extract_mailscreen_attachment_names(row):
            record = make_sensitive_mailscreen_record(row, attachment_name, category_specs)
            if record:
                records.append(record)

    latest_by_file_owner = {}
    for record in records:
        dedupe_key = (
            str(record.get("source", "")).strip().lower(),
            str(record.get("display_filename", "")).strip().lower(),
            str(record.get("dept", "")).strip().lower(),
            str(record.get("user", "")).strip().lower(),
        )
        current = latest_by_file_owner.get(dedupe_key)
        if current is None or str(record.get("event_time", "")) > str(current.get("event_time", "")):
            latest_by_file_owner[dedupe_key] = record

    records = list(latest_by_file_owner.values())
    records.sort(key=lambda r: (r["category"], r["display_filename"].lower()))
    records.sort(key=lambda r: r["event_time"], reverse=True)
    for record in records:
        record["search_text"] = sensitive_record_search_text(record)
    return records


SENSITIVE_FILES_INDEX_VERSION = "sensitive_files_v3"
SENSITIVE_FILES_PAGE_LIMIT = 500


def sensitive_files_index_sources(include_dlp=True, include_outbound=True):
    sources = []
    if include_dlp:
        sources.append("DLP")
    if include_outbound:
        sources.append("Outbound Mail")
    return sources


def sensitive_files_dedupe_key(record):
    return "|".join([
        str(record.get("source", "")).strip().lower(),
        str(record.get("display_filename", "")).strip().lower(),
        str(record.get("dept", "")).strip().lower(),
        str(record.get("user", "")).strip().lower(),
    ])


def normalize_cache_source_file_path(path):
    text = str(path or "").strip()
    return re.sub(r"/+", "/", text.replace("\\", "/")).rstrip("/").lower()


def cache_source_file_basename(path):
    normalized = normalize_cache_source_file_path(path)
    return normalized.rsplit("/", 1)[-1] if normalized else ""


def source_file_matches_targets(source_file, target_paths):
    if not target_paths:
        return True
    source_norm = normalize_cache_source_file_path(source_file)
    source_base = cache_source_file_basename(source_file)
    for target in target_paths:
        target_norm = normalize_cache_source_file_path(target)
        target_base = cache_source_file_basename(target)
        if not target_norm:
            continue
        if source_norm == target_norm:
            return True
        if source_base and target_base and source_base == target_base:
            return True
        if source_norm.endswith("/" + target_norm) or target_norm.endswith("/" + source_norm):
            return True
    return False


def parse_sensitive_raw_rows(rows, source):
    results = []
    for source_file, row_index, raw_json in rows:
        try:
            row = json.loads(raw_json)
            if isinstance(row, dict):
                row["__source_file"] = source_file
                row["__row_index"] = row_index
                results.append(row)
        except Exception as e:
            log.warning(f"Sensitive index raw parse failed source={source}: {e}")
    return results


def load_app_cache_raw_rows_from_conn(conn, source, source_files=None):
    params = [source]
    where_sql = "source = ?"
    source_file_values = list(source_files or [])
    if source_file_values:
        placeholders = ",".join("?" for _ in source_file_values)
        where_sql += f" AND source_file IN ({placeholders})"
        params.extend(source_file_values)
    rows = conn.execute(
        f"""
        SELECT source_file, row_index, raw_json
        FROM app_cache_records
        WHERE {where_sql}
        ORDER BY cache_date ASC, source_file ASC, row_index ASC
        """,
        params,
    ).fetchall()
    if rows or not source_file_values:
        return parse_sensitive_raw_rows(rows, source)

    # Some existing cache DBs can contain equivalent source_file values with
    # different path forms (absolute vs relative, slash direction, etc.).  When
    # exact IN matching returns nothing for an incremental rebuild, fall back to
    # a normalized path comparison so changed DLP files are not skipped.
    fuzzy_rows = [
        row for row in conn.execute(
            """
            SELECT source_file, row_index, raw_json
            FROM app_cache_records
            WHERE source = ?
            ORDER BY cache_date ASC, source_file ASC, row_index ASC
            """,
            (source,),
        ).fetchall()
        if source_file_matches_targets(row[0], source_file_values)
    ]
    if fuzzy_rows:
        log.warning(
            "Sensitive index fuzzy app_cache_records path match source=%s requested=%d rows=%d sample=%s",
            source,
            len(source_file_values),
            len(fuzzy_rows),
            "; ".join(str(path) for path in source_file_values[:3]),
        )
        return parse_sensitive_raw_rows(fuzzy_rows, source)

    indexed_table = {
        "detections": "detection_events",
        "emails": "email_events",
        "dlp": "dlp_events",
        "mailscreen": "mailscreen_events",
    }.get(source)
    if indexed_table:
        indexed_rows = [
            row for row in conn.execute(
                f"""
                SELECT source_file, row_index, raw_json
                FROM {indexed_table}
                ORDER BY source_file ASC, row_index ASC
                """
            ).fetchall()
            if source_file_matches_targets(row[0], source_file_values)
        ]
        if indexed_rows:
            log.warning(
                "Sensitive index fallback indexed table match source=%s table=%s requested=%d rows=%d sample=%s",
                source,
                indexed_table,
                len(source_file_values),
                len(indexed_rows),
                "; ".join(str(path) for path in source_file_values[:3]),
            )
            return parse_sensitive_raw_rows(indexed_rows, source)

    log.warning(
        "Sensitive index no raw rows for changed paths source=%s requested=%d sample=%s",
        source,
        len(source_file_values),
        "; ".join(str(path) for path in source_file_values[:5]),
    )
    return []


def sensitive_index_meta_version(conn, key):
    row = conn.execute("SELECT value FROM app_cache_meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else ""


def should_full_rebuild_sensitive_index(conn, version_key, expected_version, changed_paths, removed_paths):
    if changed_paths is None and removed_paths is None:
        return True
    return sensitive_index_meta_version(conn, version_key) != expected_version


def delete_sensitive_index_paths(conn, table_name, changed_paths=None, removed_paths=None):
    paths = sorted(set((changed_paths or []) + (removed_paths or [])))
    if not paths:
        return 0
    placeholders = ",".join("?" for _ in paths)
    cur = conn.execute(f"DELETE FROM {table_name} WHERE source_file IN ({placeholders})", paths)
    deleted = cur.rowcount if cur.rowcount is not None else 0
    if deleted:
        return deleted
    matched_paths = [
        row[0] for row in conn.execute(f"SELECT DISTINCT source_file FROM {table_name}").fetchall()
        if source_file_matches_targets(row[0], paths)
    ]
    if not matched_paths:
        return 0
    placeholders = ",".join("?" for _ in matched_paths)
    cur = conn.execute(f"DELETE FROM {table_name} WHERE source_file IN ({placeholders})", matched_paths)
    deleted = cur.rowcount if cur.rowcount is not None else 0
    log.warning(
        "Sensitive index fuzzy delete table=%s requested=%d matched_paths=%d deleted=%d sample=%s",
        table_name,
        len(paths),
        len(matched_paths),
        deleted,
        "; ".join(str(path) for path in paths[:3]),
    )
    return deleted


def insert_sensitive_files_payload(conn, payload, replace_existing=True):
    if not payload:
        return 0
    if replace_existing:
        conn.executemany(
            """
            INSERT OR REPLACE INTO sensitive_files_index
                (dedupe_key, source, category, categories, keywords, event_time,
                 display_filename, user, user_id, dept, source_file, row_index, search_text, record_json, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payload,
        )
        return len(payload)

    inserted = 0
    for item in payload:
        dedupe_key = item[0]
        event_time = item[5]
        existing = conn.execute(
            "SELECT event_time FROM sensitive_files_index WHERE dedupe_key = ?",
            (dedupe_key,),
        ).fetchone()
        if existing and str(existing[0] or "") > str(event_time or ""):
            continue
        conn.execute(
            """
            INSERT OR REPLACE INTO sensitive_files_index
                (dedupe_key, source, category, categories, keywords, event_time,
                 display_filename, user, user_id, dept, source_file, row_index, search_text, record_json, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            item,
        )
        inserted += 1
    return inserted


def rebuild_sensitive_files_index(conn, changed_paths=None, removed_paths=None, progress_cb=None):
    start_ts = time.perf_counter()
    full_rebuild = should_full_rebuild_sensitive_index(
        conn,
        "sensitive_files_index_version",
        SENSITIVE_FILES_INDEX_VERSION,
        changed_paths,
        removed_paths,
    )
    target_paths = None if full_rebuild else list(changed_paths or [])
    if progress_cb:
        progress_cb("Sensitive Files 인덱스 생성중" if full_rebuild else "Sensitive Files 증분 인덱스 생성중")
    log.info(
        "Sensitive Files index start mode=%s changed=%d removed=%d",
        "full" if full_rebuild else "incremental",
        len(changed_paths or []),
        len(removed_paths or []),
    )

    if full_rebuild:
        dlp_rows = load_app_cache_raw_rows_from_conn(conn, "dlp")
        mailscreen_rows = load_app_cache_raw_rows_from_conn(conn, "mailscreen")
    else:
        delete_count = delete_sensitive_index_paths(conn, "sensitive_files_index", changed_paths, removed_paths)
        if not target_paths:
            conn.execute(
                "INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)",
                ("sensitive_files_index_version", SENSITIVE_FILES_INDEX_VERSION),
            )
            log.info("Sensitive Files index no changed files deleted=%d elapsed=%.2fs", delete_count, time.perf_counter() - start_ts)
            return {
                "sensitive_index_rows": conn.execute("SELECT COUNT(*) FROM sensitive_files_index").fetchone()[0],
                "sensitive_index_dlp_rows": 0,
                "sensitive_index_mailscreen_rows": 0,
                "sensitive_indexed_at": sensitive_index_meta_version(conn, "sensitive_files_indexed_at"),
            }
        dlp_rows = load_app_cache_raw_rows_from_conn(conn, "dlp", target_paths)
        mailscreen_rows = load_app_cache_raw_rows_from_conn(conn, "mailscreen", target_paths)
        log.info("Sensitive Files index deleted changed/removed rows=%d", delete_count)

    records = build_sensitive_file_records(dlp_rows, mailscreen_rows=mailscreen_rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = []
    for record in records:
        record["search_text"] = record.get("search_text") or sensitive_record_search_text(record)
        row = record.get("row") if isinstance(record.get("row"), dict) else {}
        payload.append((
            sensitive_files_dedupe_key(record),
            str(record.get("source", "") or ""),
            str(record.get("category", "") or ""),
            json.dumps(record.get("categories", []) or [], ensure_ascii=False),
            json.dumps(record.get("keywords", []) or [], ensure_ascii=False),
            str(record.get("event_time", "") or ""),
            str(record.get("display_filename", "") or ""),
            str(record.get("user", "") or ""),
            str(record.get("user_id", "") or ""),
            str(record.get("dept", "") or ""),
            str(row.get("__source_file", "") or ""),
            int(row.get("__row_index", -1) if str(row.get("__row_index", "")).strip() else -1),
            str(record.get("search_text", "") or "").lower(),
            json.dumps(record, ensure_ascii=False, default=str),
            now,
        ))

    if full_rebuild:
        conn.execute("DELETE FROM sensitive_files_index")
    inserted = insert_sensitive_files_payload(conn, payload, replace_existing=full_rebuild)
    conn.execute(
        "INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)",
        ("sensitive_files_index_version", SENSITIVE_FILES_INDEX_VERSION),
    )
    conn.execute(
        "INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)",
        ("sensitive_files_indexed_at", now),
    )
    total_rows = conn.execute("SELECT COUNT(*) FROM sensitive_files_index").fetchone()[0]
    log.info(
        "Sensitive Files index done mode=%s dlp_rows=%d mailscreen_rows=%d records=%d inserted=%d total=%d elapsed=%.2fs",
        "full" if full_rebuild else "incremental",
        len(dlp_rows),
        len(mailscreen_rows),
        len(records),
        inserted,
        total_rows,
        time.perf_counter() - start_ts,
    )
    return {
        "sensitive_index_rows": total_rows,
        "sensitive_index_dlp_rows": len(dlp_rows),
        "sensitive_index_mailscreen_rows": len(mailscreen_rows),
        "sensitive_indexed_at": now,
    }

def sensitive_files_index_ready(conn):
    row = conn.execute(
        "SELECT value FROM app_cache_meta WHERE key = ?",
        ("sensitive_files_index_version",),
    ).fetchone()
    return bool(row and row[0] == SENSITIVE_FILES_INDEX_VERSION)


def sensitive_files_where_clause(category="전체", keyword="", sources=None):
    clauses = []
    params = []
    source_values = list(sources or [])
    if source_values:
        placeholders = ",".join("?" for _ in source_values)
        clauses.append(f"source IN ({placeholders})")
        params.extend(source_values)
    else:
        clauses.append("1 = 0")

    if category and category != "전체":
        clauses.append("category = ?")
        params.append(category)

    keyword = str(keyword or "").strip().lower()
    if keyword:
        clauses.append("search_text LIKE ?")
        params.append(f"%{keyword}%")

    return " AND ".join(clauses), params


def sensitive_record_from_index_json(raw_json):
    try:
        record = json.loads(raw_json)
        if isinstance(record, dict):
            record["search_text"] = record.get("search_text") or sensitive_record_search_text(record)
            return record
    except Exception as e:
        log.warning(f"Sensitive Files index record parse failed: {e}")
    return None


def query_sensitive_files_index(
    category="전체",
    keyword="",
    sources=None,
    limit=SENSITIVE_FILES_PAGE_LIMIT,
    offset=0,
):
    with app_cache_connect() as conn:
        if not sensitive_files_index_ready(conn):
            return {
                "records": [],
                "total": 0,
                "category_counts": {},
                "index_ready": False,
                "message": "Sensitive Files 인덱스가 없습니다. Config에서 Data Index를 먼저 실행하세요.",
            }

        if sources is None:
            sources = ["DLP", "Outbound Mail"]
        where_sql, params = sensitive_files_where_clause(category, keyword, sources)
        total = conn.execute(
            f"SELECT COUNT(*) FROM sensitive_files_index WHERE {where_sql}",
            params,
        ).fetchone()[0]

        count_where_sql, count_params = sensitive_files_where_clause("전체", keyword, sources)
        count_rows = conn.execute(
            f"""
            SELECT category, COUNT(*)
            FROM sensitive_files_index
            WHERE {count_where_sql}
            GROUP BY category
            """,
            count_params,
        ).fetchall()
        category_counts = {str(category): int(count) for category, count in count_rows}

        rows = conn.execute(
            f"""
            SELECT record_json
            FROM sensitive_files_index
            WHERE {where_sql}
            ORDER BY event_time DESC, display_filename ASC
            LIMIT ? OFFSET ?
            """,
            params + [int(limit), int(offset)],
        ).fetchall()

    records = []
    for (raw_json,) in rows:
        record = sensitive_record_from_index_json(raw_json)
        if record:
            records.append(record)

    return {
        "records": records,
        "total": int(total),
        "category_counts": category_counts,
        "index_ready": True,
        "limit": int(limit),
        "offset": int(offset),
    }


SENSITIVE_SITE_CATEGORY_SPECS = [
    ("AI 사이트", [
        "chat.openai.com", "chatgpt.com", "openai.com", "platform.openai.com",
        "api.openai.com", "auth.openai.com", "help.openai.com", "status.openai.com",
        "cdn.openai.com", "oaiusercontent.com",
        "chatgpt-async-webps-prod-eastus.oaiusercontent.com", "claude.ai",
        "console.anthropic.com", "anthropic.com", "api.anthropic.com",
        "docs.anthropic.com", "gemini.google.com", "aistudio.google.com",
        "makersuite.google.com", "notebooklm.google.com", "bard.google.com",
        "ai.google", "labs.google", "deepmind.google", "vertexai.google.com",
        "colab.research.google.com", "firebase.studio", "idx.google.com",
        "copilot.microsoft.com", "copilot.cloud.microsoft", "m365.cloud.microsoft",
        "copilotstudio.microsoft.com", "copilot.github.com", "perplexity.ai",
        "poe.com", "wrtn.ai", "deepseek.com", "chat.deepseek.com",
        "api.deepseek.com", "grok.com", "x.ai", "grok.x.com", "meta.ai",
        "ai.meta.com", "llama.meta.com", "character.ai", "janitorai.com",
        "spicychat.ai", "crushon.ai", "candy.ai", "chai-research.com",
        "chai.ml", "replika.com", "you.com", "phind.com", "komo.ai",
        "andisearch.com", "iask.ai", "consensus.app", "elicit.com",
        "scite.ai", "cursor.com", "windsurf.com", "codeium.com", "tabnine.com",
        "lovable.dev", "bolt.new", "v0.dev", "sourcegraph.com", "cody.dev",
        "continue.dev", "cline.bot", "devin.ai", "cognition.ai", "amazonq.aws",
        "manus.im", "n8n.io", "make.com", "flowiseai.com", "langflow.org",
        "dify.ai", "midjourney.com", "nijijourney.com", "leonardo.ai",
        "ideogram.ai", "krea.ai", "dreamstudio.ai", "stability.ai", "clipdrop.co",
        "firefly.adobe.com", "playgroundai.com", "getimg.ai", "nightcafe.studio",
        "civitai.com", "runwayml.com", "runway.com", "pika.art", "suno.com",
        "udio.com", "elevenlabs.io", "heygen.com", "synthesia.io", "descript.com",
        "kapwing.com", "veed.io", "luma.ai", "haiper.ai", "chatpdf.com",
        "humata.ai", "askyourpdf.com", "scispace.com", "typeset.io", "jenni.ai",
        "quillbot.com", "grammarly.com", "wordtune.com", "paperpal.com", "copy.ai",
        "jasper.ai", "writesonic.com", "chatsonic.com", "rytr.me", "anyword.com",
        "notion.ai", "gamma.app", "tome.app", "beautiful.ai", "presentations.ai",
        "plusdocs.com", "pitch.com", "slidesgo.com", "slidesai.io", "decktopus.com",
        "otter.ai", "fireflies.ai", "fathom.video", "tldv.io", "read.ai",
        "krisp.ai", "supernormal.com", "deepl.com", "papago.naver.com",
        "translate.google.com", "clova-x.naver.com", "clova.ai", "hyperclova.naver.com",
        "cue.search.naver.com", "daglo.ai", "lilys.ai", "askup.ai", "upstage.ai",
        "solar.upstage.ai", "polarisoffice.com", "khanmigo.ai", "socratic.org",
        "quizlet.com", "duolingo.com", "dataiku.com", "databricks.com",
        "snowflake.com", "thoughtspot.com", "akkio.com", "polymersearch.com",
    ]),
    ("여행 / 숙박", [
        "yanolja.com", "goodchoice.kr", "yeogi.com", "ddnayo.com", "tidesquare.com",
        "tourvis.com", "myrealtrip.com", "triple.guide", "interpark.com",
        "travel.interpark.com", "nol-universe.com", "agoda.com", "booking.com",
        "hotels.com", "expedia.com", "trip.com", "ctrip.com", "trivago.com",
        "kayak.com", "priceline.com", "travelocity.com", "orbitz.com",
        "hotelcombined.com", "hotelscombined.com", "skyscanner.co.kr", "airbnb.com",
        "vrbo.com", "hostelworld.com", "lottehotel.com", "shillahotels.com",
        "josunhotel.com", "parnas.co.kr", "walkerhill.com", "hanwharesort.co.kr",
        "sonohotelsresorts.com", "kensington.co.kr", "resom.co.kr", "elysian.co.kr",
        "konjiamresort.co.kr", "phoenixhnr.co.kr", "high1.com", "marriott.com",
        "hilton.com", "hyatt.com", "ihg.com", "accor.com", "all.accor.com",
        "wyndhamhotels.com", "choicehotels.com", "bestwestern.com", "radissonhotels.com",
        "fourseasons.com", "mandarinoriental.com", "shangri-la.com", "aman.com",
        "kempinski.com",
    ]),
    ("개인 메일 / 웹메일", [
        "gmail.com", "mail.google.com", "googlemail.com", "mail.naver.com",
        "mail.daum.net", "hanmail.net", "mail.hanmail.net", "mail.kakao.com",
        "outlook.live.com", "outlook.com", "hotmail.com", "live.com", "mail.live.com",
        "mail.yahoo.com", "yahoo.com", "ymail.com", "rocketmail.com", "icloud.com",
        "mail.icloud.com", "me.com", "mac.com", "proton.me", "mail.proton.me",
        "protonmail.com", "pm.me", "tuta.com", "mail.tuta.com", "tutanota.com",
        "tutanota.de", "tutamail.com", "tuta.io", "keemail.me", "mail.zoho.com",
        "zohomail.com", "mail.aol.com", "aol.com", "gmx.com", "gmx.net",
        "mail.gmx.com", "mail.gmx.net", "mail.com", "mail.yandex.com",
        "mail.yandex.ru", "mail.qq.com", "foxmail.com", "mail.163.com",
        "mail.126.com", "mail.yeah.net", "mail.sina.com", "mail.sina.com.cn",
        "fastmail.com", "app.fastmail.com", "fastmail.fm", "mailfence.com",
        "hushmail.com", "startmail.com", "runbox.com", "posteo.de", "mailbox.org",
        "hey.com", "mail.nate.com", "empas.com", "korea.com", "dreamwiz.com",
        "chol.com", "hanafos.com", "paran.com", "unitel.co.kr", "kornet.net",
        "hitel.net",
    ]),
    ("클라우드 / 파일공유", [
        "drive.google.com", "docs.google.com", "sheets.google.com", "slides.google.com",
        "forms.google.com", "photos.google.com", "storage.googleapis.com",
        "storage.cloud.google.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
        "my.sharepoint.com", "onedrive.com", "office.live.com", "officeapps.live.com",
        "dropbox.com", "dropboxusercontent.com", "dl.dropboxusercontent.com",
        "dropboxstatic.com", "db.tt", "box.com", "app.box.com", "boxcloud.com",
        "boxcdn.net", "drive.icloud.com", "icloud-content.com", "mybox.naver.com",
        "cloud.naver.com", "drive.kakao.com", "sendy.co.kr", "wetransfer.com",
        "we.tl", "mega.nz", "mega.io", "mega.co.nz", "mediafire.com",
        "download.mediafire.com", "pcloud.com", "my.pcloud.com", "e.pcloud.link",
        "u.pcloud.link", "sync.com", "cp.sync.com", "tresorit.com", "web.tresorit.com",
        "tresorit.io", "internxt.com", "drive.internxt.com", "drive.proton.me",
        "protondrive.com", "nordlocker.com", "web.nordlocker.com", "icedrive.net",
        "drive.icedrive.net", "koofr.eu", "app.koofr.net", "jumpshare.com",
        "hightail.com", "spaces.hightail.com", "filemail.com", "send-anywhere.com",
        "fromsmash.com", "transfernow.net", "transferxl.com", "swisstransfer.com",
        "wormhole.app", "file.io", "gofile.io", "pixeldrain.com", "catbox.moe",
        "litterbox.catbox.moe", "krakenfiles.com", "bayfiles.com", "letsupload.io",
        "userscloud.com", "uppit.com", "zippyshare.com", "4shared.com",
        "4shared-china.com", "disk.yandex.com", "disk.yandex.ru", "yadi.sk",
        "pan.baidu.com", "yun.baidu.com", "weiyun.com", "pan.qq.com",
        "aliyundrive.com", "alipan.com", "cloud.163.com",
    ]),
    ("원격접속 / 파일전송 도구", [
        "teamviewer.com", "anydesk.com", "remotedesktop.google.com",
        "rustdesk.com", "parsec.app", "splashtop.com", "logmein.com", "gotomypc.com",
        "realvnc.com", "vnc.com", "tightvnc.com", "ultravnc.com", "dwservice.net",
        "assist.zoho.com", "awe-sun.com", "supremocontrol.com",
        "getscreen.me", "meshcentral.com", "radmin.com", "mremoteng.org", "putty.org",
        "winscp.net", "filezilla-project.org", "termius.com", "tailscale.com",
        "zerotier.com", "ngrok.com", "cloudflared.com", "remote.it",
    ]),
    ("금융 / 가상자산", [
        "kbstar.com", "obank.kbstar.com", "shinhan.com", "bank.shinhan.com",
        "wooribank.com", "spib.wooribank.com", "hana.com", "kebhana.com",
        "ibk.co.kr", "nonghyup.com", "nhbank.com", "sc.co.kr", "standardchartered.co.kr",
        "citi.com", "citibank.co.kr", "kakaobank.com", "kbanknow.com", "tossbank.com",
        "toss.im", "pay.naver.com", "kakaopay.com", "samsungcard.com",
        "hyundaicard.com", "lottecard.co.kr", "bccard.com", "wooricard.com",
        "hanacard.co.kr", "kbcard.com", "shinhansec.com", "miraeasset.com",
        "samsungpop.com", "kiwoom.com", "nhqv.com", "kbsec.com", "koreainvestment.com",
        "upbit.com", "bithumb.com", "coinone.co.kr", "korbit.co.kr", "gopax.co.kr",
        "binance.com", "coinbase.com", "kraken.com", "crypto.com", "bybit.com",
        "okx.com", "bitget.com", "kucoin.com", "gate.io", "mexc.com",
        "metamask.io", "phantom.app", "trustwallet.com", "ledger.com", "trezor.io",
    ]),
    ("쇼핑 / 중고거래 / 개인거래", [
        "coupang.com", "gmarket.co.kr", "auction.co.kr", "11st.co.kr", "ssg.com",
        "emart.ssg.com", "lotteon.com", "shopping.naver.com", "smartstore.naver.com",
        "brand.naver.com", "kream.co.kr", "musinsa.com", "ably.co.kr", "zigzag.kr",
        "29cm.co.kr", "wconcept.co.kr", "kurly.com", "ohou.se", "todayhouse.com",
        "interpark.com", "wemakeprice.com", "tmon.co.kr", "aliexpress.com",
        "amazon.com", "ebay.com", "qoo10.com", "taobao.com", "tmall.com",
        "1688.com", "jd.com", "daangn.com", "karrotmarket.com", "bunjang.co.kr",
        "joongna.com", "hellomarket.com", "junggonara.co.kr",
    ]),
    ("채용 / 이직", [
        "saramin.co.kr", "jobkorea.co.kr", "wanted.co.kr", "linkedin.com",
        "rememberapp.co.kr", "career.co.kr", "incruit.com", "jobplanet.co.kr",
        "blind.com", "teamblind.com", "rocketpunch.com", "jumpit.co.kr",
        "programmers.co.kr", "jasoseol.com", "linkareer.com", "superookie.com",
        "catch.co.kr", "job.incruit.com", "albamon.com", "alba.co.kr", "work.go.kr",
        "job.alio.go.kr", "job.seoul.go.kr", "seouljobnow.co.kr", "rallit.com",
        "zighang.com", "jobflex.com", "jobda.im", "ninehire.com", "greetinghr.com",
        "apply.workable.com", "wantedlab.com", "jobs.lever.co", "greenhouse.io",
        "boards.greenhouse.io", "wellfound.com", "angel.co", "stackoverflowjobs.com",
        "remoteok.com", "weworkremotely.com", "remotive.com", "flexjobs.com",
        "indeed.com", "glassdoor.com", "monster.com", "ziprecruiter.com", "dice.com",
        "seek.com.au", "jobsdb.com", "efinancialcareers.com",
    ]),
    ("문서 변환 / PDF 도구", [
        "ilovepdf.com", "smallpdf.com", "pdf24.org", "convertio.co",
        "cloudconvert.com", "freeconvert.com", "remove.bg", "canva.com",
        "figma.com", "photopea.com", "tinywow.com",
    ]),
    ("SNS / 커뮤니티", [
        "instagram.com", "facebook.com", "threads.net", "x.com", "twitter.com",
        "tiktok.com", "youtube.com", "reddit.com", "discord.com", "telegram.org",
        "t.me", "medium.com", "tumblr.com", "pinterest.com", "snapchat.com",
        "mastodon.social", "bsky.app", "linktr.ee", "beacons.ai", "open.kakao.com",
        "pf.kakao.com", "talk.naver.com", "band.us", "line.me", "openchat.line.me",
        "dcinside.com", "gall.dcinside.com", "theqoo.net", "instiz.net",
        "fmkorea.com", "ruliweb.com", "clien.net", "ppomppu.co.kr", "82cook.com",
        "mlbpark.donga.com", "humoruniv.com", "todayhumor.co.kr", "inven.co.kr",
        "arca.live", "etoland.co.kr", "slrclub.com", "bobaedream.co.kr",
        "quasarzone.com", "coolenjoy.net", "dogdrip.net", "ilbe.com",
        "cafe.naver.com", "blog.naver.com", "section.blog.naver.com", "m.blog.naver.com",
        "cafe.daum.net", "brunch.co.kr", "everytime.kr",
    ]),
]

SENSITIVE_SITES_INDEX_VERSION = "sensitive_sites_v5"
SENSITIVE_SITES_PAGE_LIMIT = 500


def normalize_site_host(value):
    host = _extract_report_hostname(value)
    host = host.lower().strip().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def sensitive_site_known_domains(category_specs=SENSITIVE_SITE_CATEGORY_SPECS):
    domains = []
    seen = set()
    for _, patterns in category_specs:
        for pattern in patterns:
            domain = normalize_site_host(pattern)
            if domain and domain not in seen:
                domains.append(domain)
                seen.add(domain)
    return domains


def extract_url_candidates_from_text(text, category_specs=SENSITIVE_SITE_CATEGORY_SPECS):
    text = html.unescape(str(text or ""))
    candidates = []
    seen = set()

    def add_candidate(value):
        candidate = str(value or "").strip().rstrip(".,;")
        host = normalize_site_host(candidate)
        if not host or host in seen:
            return
        candidates.append(candidate)
        seen.add(host)

    for match in re.finditer(r"https?://[^\s<>'\")]+|www\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s<>'\")]+)?", text, re.IGNORECASE):
        add_candidate(match.group(0))

    for match in MAILSCREEN_EMAIL_RE.finditer(text):
        email_domain = match.group(0).rsplit("@", 1)[-1]
        add_candidate(email_domain)

    lower_text = text.lower()
    for domain in sensitive_site_known_domains(category_specs):
        pattern = rf"(?<![a-z0-9.-]){re.escape(domain.lower())}(?![a-z0-9.-])"
        if re.search(pattern, lower_text):
            add_candidate(domain)

    return candidates


def classify_sensitive_site(host, url="", category_specs=SENSITIVE_SITE_CATEGORY_SPECS):
    normalized_host = normalize_site_host(host) or normalize_site_host(url)
    matched_categories = []
    matched_keywords = []
    for category, patterns in category_specs:
        hits = []
        seen_needles = set()
        for pattern in patterns:
            needle = normalize_site_host(pattern)
            if not needle or needle in seen_needles:
                continue
            if normalized_host == needle or normalized_host.endswith("." + needle):
                hits.append(needle)
                seen_needles.add(needle)
        if hits:
            matched_categories.append(category)
            matched_keywords.extend(hits)
    if not matched_categories:
        return None
    return {
        "category": matched_categories[0],
        "categories": matched_categories,
        "keywords": sorted(set(matched_keywords), key=lambda x: x.lower()),
    }


def sensitive_site_search_text(record):
    return " ".join(str(record.get(k, "") or "") for k in (
        "source", "category", "keywords", "event_time", "event", "site", "url",
        "dept", "user", "user_id", "machine", "destination", "subject", "sender",
        "receiver", "policy",
    )).lower()


def make_sensitive_site_dlp_record(row, category_specs=SENSITIVE_SITE_CATEGORY_SPECS):
    if not isinstance(row, dict):
        return None
    destination = str(row.get("destination", "") or "")
    detail = str(row.get("item_details") or row.get("destinationDetails") or "")
    site_candidates = [detail, destination]
    selected_url = ""
    selected_host = ""
    classified = None
    for candidate in site_candidates:
        host = normalize_site_host(candidate)
        if not host or host in {"local-file-path", "internal-file-server"}:
            continue
        classified = classify_sensitive_site(host, candidate, category_specs)
        if classified:
            selected_host = host
            selected_url = candidate
            break
    if not classified:
        return None
    machine_name = str(row.get("machine_name", "None") or "None")
    client_name = str(row.get("client_name", "None") or "None")
    dept_name, _ = get_dept_by_hostname(machine_name)
    return {
        "row": row,
        "source": "DLP",
        "category": classified["category"],
        "categories": classified["categories"],
        "keywords": classified["keywords"],
        "event_time": str(row.get("eventtimelocal", "") or ""),
        "event": format_dlp_event_id(row.get("event_id", "None")),
        "site": selected_host,
        "url": selected_url or selected_host,
        "destination": destination or "None",
        "detail": detail or "None",
        "machine": machine_name,
        "dept": dept_name,
        "user": resolve_sensitive_user_name(machine_name, client_name),
        "user_id": client_name,
        "filename": str(row.get("filename", "None") or "None"),
        "filehash": str(row.get("filehash", "None") or "None"),
    }


def make_sensitive_site_mailscreen_records(row, category_specs=SENSITIVE_SITE_CATEGORY_SPECS):
    if not isinstance(row, dict):
        return []
    row = enrich_mailscreen_sender_fields(row)
    subject = str(row.get("subject", "") or "")
    scan_text = " ".join(str(row.get(k, "") or "") for k in (
        "subject", "receiver", "sender", "attach",
    ))
    candidates = extract_url_candidates_from_text(scan_text, category_specs)
    if not candidates:
        return []
    sender_email = mailscreen_identity_text(row.get("sender_email")) or mailscreen_identity_text(row.get("sender"))
    sender_name = mailscreen_identity_text(row.get("sender_name")) or sender_email or "None"
    user_id = mailscreen_identity_text(row.get("sender_user_id")) or sender_email or "None"
    dept_name = mailscreen_identity_text(row.get("sender_dept")) or mailscreen_identity_text(row.get("dept")) or "미분류"
    receiver = mailscreen_identity_text(row.get("receiver_detail")) or mailscreen_identity_text(row.get("receiver")) or "None"
    records = []
    for candidate in candidates:
        host = normalize_site_host(candidate)
        if not host:
            continue
        classified = classify_sensitive_site(host, candidate, category_specs)
        if not classified:
            continue
        mail_process = str(row.get("mail_process", "") or "None")
        send_result = str(row.get("send_result", "") or "None")
        event = f"{mail_process}/{send_result}" if mail_process != "None" and send_result != "None" else (send_result or mail_process)
        records.append({
            "row": row,
            "source": "Outbound Mail",
            "category": classified["category"],
            "categories": classified["categories"],
            "keywords": classified["keywords"],
            "event_time": str(row.get("date", "") or ""),
            "event": event,
            "site": host,
            "url": candidate,
            "destination": receiver,
            "detail": subject or "None",
            "machine": "None",
            "dept": dept_name,
            "user": sender_name,
            "user_id": user_id,
            "subject": subject or "None",
            "sender": sender_email or "None",
            "receiver": receiver,
            "policy": str(row.get("policy", "") or "None"),
            "mail_process": mail_process,
            "mail_send_result": send_result,
        })
    return records


def build_sensitive_site_records(dlp_rows=None, mailscreen_rows=None):
    records = []
    for row in dlp_rows or []:
        record = make_sensitive_site_dlp_record(row)
        if record:
            records.append(record)

    latest = {}
    for record in records:
        dedupe_key = sensitive_sites_dedupe_key(record)
        current = latest.get(dedupe_key)
        if current is None or str(record.get("event_time", "")) > str(current.get("event_time", "")):
            latest[dedupe_key] = record
    records = list(latest.values())
    records.sort(key=lambda r: (r.get("event_time", ""), r.get("site", "")), reverse=True)
    for record in records:
        record["search_text"] = sensitive_site_search_text(record)
    return records


def sensitive_site_debug_text(value, limit=140):
    text = html.unescape(str(value or "")).replace("\n", " ").replace("\r", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text if len(text) <= limit else text[:limit] + "..."


def log_sensitive_sites_build_debug(stage, dlp_rows, records, sample_limit=10):
    try:
        sorted_rows = sorted(
            list(dlp_rows or []),
            key=lambda row: str(row.get("eventtimelocal", "") or "") if isinstance(row, dict) else "",
            reverse=True,
        )
        log.info(
            "Sensitive Sites debug stage=%s dlp_rows=%d records=%d latest_dlp=%s latest_record=%s",
            stage,
            len(sorted_rows),
            len(records or []),
            str(sorted_rows[0].get("eventtimelocal", "") or "") if sorted_rows else "",
            max((str(record.get("event_time", "") or "") for record in records or []), default=""),
        )
        for idx, row in enumerate(sorted_rows[:sample_limit], start=1):
            destination = str(row.get("destination", "") or "")
            detail = str(row.get("item_details") or row.get("destinationDetails") or "")
            candidate_info = []
            matched_info = []
            for label, candidate in (("detail", detail), ("destination", destination)):
                host = normalize_site_host(candidate)
                classified = classify_sensitive_site(host, candidate) if host else None
                candidate_info.append(f"{label}:{host or '-'}")
                if classified:
                    matched_info.append(f"{label}:{host}:{','.join(classified.get('categories', []) or [])}")
            log.info(
                "Sensitive Sites debug dlp_sample#%d time=%s machine=%s user=%s dest=%s detail=%s candidates=%s matched=%s source_file=%s row_index=%s",
                idx,
                str(row.get("eventtimelocal", "") or ""),
                str(row.get("machine_name", "") or ""),
                str(row.get("client_name", "") or ""),
                sensitive_site_debug_text(destination),
                sensitive_site_debug_text(detail),
                ";".join(candidate_info),
                ";".join(matched_info) or "NO_MATCH",
                str(row.get("__source_file", "") or ""),
                str(row.get("__row_index", "") or ""),
            )
        for idx, record in enumerate(sorted(records or [], key=lambda r: str(r.get("event_time", "") or ""), reverse=True)[:sample_limit], start=1):
            log.info(
                "Sensitive Sites debug record_sample#%d time=%s site=%s category=%s user=%s dept=%s source_file=%s row_index=%s",
                idx,
                str(record.get("event_time", "") or ""),
                str(record.get("site", "") or ""),
                str(record.get("category", "") or ""),
                str(record.get("user", "") or ""),
                str(record.get("dept", "") or ""),
                str((record.get("row") or {}).get("__source_file", "") if isinstance(record.get("row"), dict) else ""),
                str((record.get("row") or {}).get("__row_index", "") if isinstance(record.get("row"), dict) else ""),
            )
    except Exception as e:
        log.warning("Sensitive Sites debug logging failed stage=%s: %s", stage, e)


def sensitive_sites_index_sources(include_dlp=True, include_outbound=False):
    sources = []
    if include_dlp:
        sources.append("DLP")
    return sources


def sensitive_sites_dedupe_key(record):
    return "|".join([
        str(record.get("source", "")).strip().lower(),
        str(record.get("site", "")).strip().lower(),
        str(record.get("dept", "")).strip().lower(),
        str(record.get("user", "")).strip().lower(),
    ])


def insert_sensitive_sites_payload(conn, payload, replace_existing=True):
    if not payload:
        return 0
    if replace_existing:
        conn.executemany(
            """
            INSERT OR REPLACE INTO sensitive_sites_index
                (dedupe_key, source, category, categories, keywords, event_time,
                 site, url, user, user_id, dept, source_file, row_index, search_text, record_json, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            payload,
        )
        return len(payload)

    inserted = 0
    for item in payload:
        dedupe_key = item[0]
        event_time = item[5]
        existing = conn.execute(
            "SELECT event_time FROM sensitive_sites_index WHERE dedupe_key = ?",
            (dedupe_key,),
        ).fetchone()
        if existing and str(existing[0] or "") > str(event_time or ""):
            continue
        conn.execute(
            """
            INSERT OR REPLACE INTO sensitive_sites_index
                (dedupe_key, source, category, categories, keywords, event_time,
                 site, url, user, user_id, dept, source_file, row_index, search_text, record_json, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            item,
        )
        inserted += 1
    return inserted


def rebuild_sensitive_sites_index(conn, changed_paths=None, removed_paths=None, progress_cb=None):
    start_ts = time.perf_counter()
    full_rebuild = should_full_rebuild_sensitive_index(
        conn,
        "sensitive_sites_index_version",
        SENSITIVE_SITES_INDEX_VERSION,
        changed_paths,
        removed_paths,
    )
    target_paths = None if full_rebuild else list(changed_paths or [])
    if progress_cb:
        progress_cb("Sensitive Sites 인덱스 생성중" if full_rebuild else "Sensitive Sites 증분 인덱스 생성중")
    log.info(
        "Sensitive Sites index start mode=%s changed=%d removed=%d",
        "full" if full_rebuild else "incremental",
        len(changed_paths or []),
        len(removed_paths or []),
    )

    if full_rebuild:
        dlp_rows = load_app_cache_raw_rows_from_conn(conn, "dlp")
        mailscreen_rows = []
    else:
        delete_count = delete_sensitive_index_paths(conn, "sensitive_sites_index", changed_paths, removed_paths)
        if not target_paths:
            conn.execute(
                "INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)",
                ("sensitive_sites_index_version", SENSITIVE_SITES_INDEX_VERSION),
            )
            log.info("Sensitive Sites index no changed files deleted=%d elapsed=%.2fs", delete_count, time.perf_counter() - start_ts)
            return {
                "sensitive_sites_index_rows": conn.execute("SELECT COUNT(*) FROM sensitive_sites_index").fetchone()[0],
                "sensitive_sites_indexed_at": sensitive_index_meta_version(conn, "sensitive_sites_indexed_at"),
            }
        dlp_rows = load_app_cache_raw_rows_from_conn(conn, "dlp", target_paths)
        mailscreen_rows = []
        log.info("Sensitive Sites index deleted changed/removed rows=%d", delete_count)

    records = build_sensitive_site_records(dlp_rows, mailscreen_rows)
    log_sensitive_sites_build_debug("full" if full_rebuild else "incremental", dlp_rows, records)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = []
    for record in records:
        record["search_text"] = record.get("search_text") or sensitive_site_search_text(record)
        row = record.get("row") if isinstance(record.get("row"), dict) else {}
        payload.append((
            sensitive_sites_dedupe_key(record), str(record.get("source", "") or ""),
            str(record.get("category", "") or ""), json.dumps(record.get("categories", []) or [], ensure_ascii=False),
            json.dumps(record.get("keywords", []) or [], ensure_ascii=False), str(record.get("event_time", "") or ""),
            str(record.get("site", "") or ""), str(record.get("url", "") or ""),
            str(record.get("user", "") or ""), str(record.get("user_id", "") or ""),
            str(record.get("dept", "") or ""), str(row.get("__source_file", "") or ""),
            int(row.get("__row_index", -1) if str(row.get("__row_index", "")).strip() else -1),
            str(record.get("search_text", "") or "").lower(),
            json.dumps(record, ensure_ascii=False, default=str), now,
        ))
    if full_rebuild:
        conn.execute("DELETE FROM sensitive_sites_index")
    inserted = insert_sensitive_sites_payload(conn, payload, replace_existing=full_rebuild)
    conn.execute("INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)", ("sensitive_sites_index_version", SENSITIVE_SITES_INDEX_VERSION))
    conn.execute("INSERT OR REPLACE INTO app_cache_meta(key, value) VALUES (?, ?)", ("sensitive_sites_indexed_at", now))
    total_rows = conn.execute("SELECT COUNT(*) FROM sensitive_sites_index").fetchone()[0]
    max_event_time = conn.execute("SELECT MAX(event_time) FROM sensitive_sites_index").fetchone()[0]
    log.info(
        "Sensitive Sites index table max_event_time=%s total=%d",
        max_event_time,
        total_rows,
    )
    log.info(
        "Sensitive Sites index done mode=%s dlp_rows=%d mailscreen_rows=%d records=%d inserted=%d total=%d elapsed=%.2fs",
        "full" if full_rebuild else "incremental",
        len(dlp_rows),
        len(mailscreen_rows),
        len(records),
        inserted,
        total_rows,
        time.perf_counter() - start_ts,
    )
    return {
        "sensitive_sites_index_rows": total_rows,
        "sensitive_sites_indexed_at": now,
    }

def sensitive_sites_index_ready(conn):
    row = conn.execute(
        "SELECT value FROM app_cache_meta WHERE key = ?",
        ("sensitive_sites_index_version",),
    ).fetchone()
    return bool(row and row[0] == SENSITIVE_SITES_INDEX_VERSION)


def sensitive_sites_where_clause(category="전체", keyword="", sources=None):
    clauses = []
    params = []
    source_values = list(sources or [])
    if source_values:
        clauses.append(f"source IN ({','.join('?' for _ in source_values)})")
        params.extend(source_values)
    else:
        clauses.append("1 = 0")
    if category and category != "전체":
        clauses.append("category = ?")
        params.append(category)
    keyword = str(keyword or "").strip().lower()
    if keyword:
        clauses.append("search_text LIKE ?")
        params.append(f"%{keyword}%")
    return " AND ".join(clauses), params


def query_sensitive_sites_index(category="전체", keyword="", sources=None, limit=SENSITIVE_SITES_PAGE_LIMIT, offset=0):
    with app_cache_connect() as conn:
        if not sensitive_sites_index_ready(conn):
            return {
                "records": [], "total": 0, "category_counts": {}, "index_ready": False,
                "message": "Sensitive Sites 인덱스가 없습니다. Config에서 Data Index를 먼저 실행하세요.",
            }
        if sources is None:
            sources = ["DLP"]
        where_sql, params = sensitive_sites_where_clause(category, keyword, sources)
        total = conn.execute(f"SELECT COUNT(*) FROM sensitive_sites_index WHERE {where_sql}", params).fetchone()[0]
        count_where_sql, count_params = sensitive_sites_where_clause("전체", keyword, sources)
        count_rows = conn.execute(
            f"SELECT category, COUNT(*) FROM sensitive_sites_index WHERE {count_where_sql} GROUP BY category",
            count_params,
        ).fetchall()
        category_counts = {str(category): int(count) for category, count in count_rows}
        rows = conn.execute(
            f"""
            SELECT record_json
            FROM sensitive_sites_index
            WHERE {where_sql}
            ORDER BY event_time DESC, site ASC
            LIMIT ? OFFSET ?
            """,
            params + [int(limit), int(offset)],
        ).fetchall()
    records = []
    for (raw_json,) in rows:
        try:
            record = json.loads(raw_json)
            if isinstance(record, dict):
                records.append(record)
        except Exception as e:
            log.warning(f"Sensitive Sites index record parse failed: {e}")
    log.info(
        "Sensitive Sites query category=%s keyword=%r sources=%s total=%d returned=%d offset=%d first_time=%s first_site=%s",
        category,
        keyword,
        sources,
        int(total),
        len(records),
        int(offset),
        str(records[0].get("event_time", "") or "") if records else "",
        str(records[0].get("site", "") or "") if records else "",
    )
    return {
        "records": records, "total": int(total), "category_counts": category_counts,
        "index_ready": True, "limit": int(limit), "offset": int(offset),
    }

# ======================================================
# Core utilities / file, session, time, and validation helpers
# - Generic helpers that are not tied to a single UI tab.
# - Later module targets: core/path.py, core/time.py, core/validator.py
# ======================================================
def get_unique_path(path):
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    idx = 1

    while True:
        new_path = f"{base}_({idx}){ext}"
        if not os.path.exists(new_path):
            return new_path
        idx += 1

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def get_dir_size_bytes(path):
    total = 0

    if not os.path.exists(path):
        return total

    for root, dirs, files in os.walk(path):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                total += os.path.getsize(file_path)
            except Exception:
                pass

    return total


def format_size_text(size_bytes):
    try:
        size = float(size_bytes)

        if size < 1024:
            return f"{int(size)} B"
        elif size < 1024 ** 2:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 ** 3:
            return f"{size / (1024 ** 2):.1f} MB"
        else:
            return f"{size / (1024 ** 3):.2f} GB"
    except Exception:
        return "0 B"

def live_discover_session_path(session_id: str):
    return os.path.join(LIVE_DISCOVER_DIR, f"{session_id}.json")


def create_live_discover_session(
    endpoint_name: str,
    program_name: str,
    rows: list,
    query_mode: str = "Live",
    query_type: str = "Process",
    display_columns: list = None
):
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    if display_columns is None:
        display_columns = ["name", "path", "pid"]

    data = {
        "session_id": session_id,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "endpoint_name": endpoint_name,
        "program_name": program_name,
        "query_mode": query_mode,
        "query_type": query_type,
        "display_columns": display_columns,
        "result_count": len(rows),
        "rows": rows,
    }

    save_json(live_discover_session_path(session_id), data)
    return data


def load_live_discover_sessions():
    sessions = []

    if not os.path.exists(LIVE_DISCOVER_DIR):
        return sessions

    for name in os.listdir(LIVE_DISCOVER_DIR):
        if not name.lower().endswith(".json"):
            continue

        path = os.path.join(LIVE_DISCOVER_DIR, name)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                sessions.append(data)

        except Exception as e:
            log.warning(f"[LIVE DISCOVER] failed to load session file: {path} / {e}")

    sessions.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return sessions


def delete_live_discover_session(session_id: str):
    path = live_discover_session_path(session_id)

    if os.path.exists(path):
        os.remove(path)

def kst_time(iso):
    if not iso:
        return "None"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(iso)

def iso_to_kst_dt(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        kst_dt = dt.astimezone(timezone(timedelta(hours=9)))
        return kst_dt.replace(tzinfo=None)
    except Exception:
        return None

def dlp_time_to_dt(value):
    if not value:
        return None

    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def combine_date_time(date_edit, time_edit):
    d = date_edit.date().toPyDate()
    t = time_edit.time().toPyTime()
    return datetime.combine(d, t)


def kst_date_range_to_utc_iso(start_date: str, end_date: str):
    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(
        hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone(timedelta(hours=9))
    )
    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, microsecond=0, tzinfo=timezone(timedelta(hours=9))
    )
    return (
        start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        end_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


def unix_ms_to_kst(unix_ms):
    try:
        sec = int(unix_ms) // 1000
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "None"

def bytes_to_mb_text(value):
    try:
        size_bytes = float(value)
        size_mb = size_bytes / (1024 * 1024)
        return f"{size_mb:.2f} MB"
    except Exception:
        return str(value)

def join_list(values):
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join([str(x) for x in values])
    return str(values)

XDR_EMAIL_RULES = {
    "XDR-sophos-email-maliciousurl",
    "XDR-sophos-email-virus",
    "XDR-sophos-email-impersonation",
}

def parse_multiline_ips(text: str):
    results = []
    seen = set()

    for line in str(text or "").splitlines():
        ip = line.strip()
        if not ip:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        results.append(ip)

    return results

def load_firewall_env_values(path: str):
    values = {}

    if not os.path.exists(path):
        return values

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if "=" in line:
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip()

    except Exception as e:
        log.warning(f"Firewall_env.txt read failed: {e}")

    return values


def get_firewall_target_configs(path: str, selected_firewalls: list = None):
    values = load_firewall_env_values(path)

    # 화면 표시명 / env key prefix
    # Cloud는 기존 호환 때문에 prefix 없이 FW_HOST 사용
    firewall_defs = [
        {
            "name": "Cloud",
            "prefix": "",
            "host_key": "FW_HOST",
            "port_key": "FW_PORT",
            "username_key": "FW_USERNAME",
            "password_key": "FW_PASSWORD",
            "verify_ssl_key": "FW_VERIFY_SSL",
        },
        {
            "name": "Seoul",
            "prefix": "SEOUL",
            "host_key": "FW_SEOUL_HOST",
            "port_key": "FW_SEOUL_PORT",
            "username_key": "FW_SEOUL_USERNAME",
            "password_key": "FW_SEOUL_PASSWORD",
            "verify_ssl_key": "FW_SEOUL_VERIFY_SSL",
        },
        {
            "name": "Icheon",
            "prefix": "ICHEON",
            "host_key": "FW_ICHEON_HOST",
            "port_key": "FW_ICHEON_PORT",
            "username_key": "FW_ICHEON_USERNAME",
            "password_key": "FW_ICHEON_PASSWORD",
            "verify_ssl_key": "FW_ICHEON_VERIFY_SSL",
        },
        {
            "name": "Anseong",
            "prefix": "ANSEONG",
            "host_key": "FW_ANSEONG_HOST",
            "port_key": "FW_ANSEONG_PORT",
            "username_key": "FW_ANSEONG_USERNAME",
            "password_key": "FW_ANSEONG_PASSWORD",
            "verify_ssl_key": "FW_ANSEONG_VERIFY_SSL",
        },
    ]

    selected_set = None
    if selected_firewalls:
        selected_set = {str(x).strip() for x in selected_firewalls if str(x).strip()}

    results = []

    for fw in firewall_defs:
        name = fw["name"]

        if selected_set is not None and name not in selected_set:
            continue

        host = str(values.get(fw["host_key"], "")).strip()
        port = str(values.get(fw["port_key"], "")).strip()
        username = str(values.get(fw["username_key"], "")).strip()
        password = str(values.get(fw["password_key"], "")).strip()
        verify_ssl_raw = str(values.get(fw["verify_ssl_key"], "false")).strip().lower()

        results.append({
            "name": name,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "verify_ssl": verify_ssl_raw == "true",
            "iphost_description": str(values.get("FW_IPHOST_DESCRIPTION", "")).strip(),
            "iphost_group": str(values.get("FW_IPHOST_GROUP", "")).strip(),
            "fqdnhost_group": str(values.get("FW_FQDNHOST_GROUP", "")).strip(),
        })

    return results


def validate_firewall_env_file(path: str, mode: str = "IP", selected_firewalls: list = None):
    if not os.path.exists(path):
        return False, f"환경파일이 없습니다: {path}"

    mode = str(mode or "IP").strip().upper()
    values = load_firewall_env_values(path)

    if mode == "DOMAIN":
        common_required = [
            "FW_FQDNHOST_GROUP",
        ]
    else:
        common_required = [
            "FW_IPHOST_DESCRIPTION",
            "FW_IPHOST_GROUP",
        ]

    missing_keys = []
    empty_keys = []

    for key in common_required:
        if key not in values:
            missing_keys.append(key)
        elif not str(values.get(key, "")).strip():
            empty_keys.append(key)

    if missing_keys:
        return False, "Firewall_env.txt 공통 필수 항목 누락: " + ", ".join(missing_keys)

    if empty_keys:
        return False, "Firewall_env.txt 공통 필수 항목 값 비어 있음: " + ", ".join(empty_keys)

    firewall_configs = get_firewall_target_configs(path, selected_firewalls=selected_firewalls)

    if not firewall_configs:
        return False, "선택된 방화벽이 없습니다."

    invalid_messages = []

    for fw in firewall_configs:
        name = fw.get("name", "Unknown")

        if not fw.get("host"):
            invalid_messages.append(f"{name}: HOST 값 비어 있음")

        if not fw.get("port"):
            invalid_messages.append(f"{name}: PORT 값 비어 있음")

        if not fw.get("username"):
            invalid_messages.append(f"{name}: USERNAME 값 비어 있음")

        if not fw.get("password"):
            invalid_messages.append(f"{name}: PASSWORD 값 비어 있음")

    if invalid_messages:
        return False, "Firewall_env.txt 방화벽 설정 오류:\n\n" + "\n".join(invalid_messages)

    return True, ""

def validate_ipv4_list(ip_list: list):
    invalid_ips = []

    for ip in ip_list:
        parts = str(ip).strip().split(".")
        if len(parts) != 4:
            invalid_ips.append(ip)
            continue

        valid = True
        for part in parts:
            if not part.isdigit():
                valid = False
                break

            num = int(part)
            if num < 0 or num > 255:
                valid = False
                break

        if not valid:
            invalid_ips.append(ip)

    if invalid_ips:
        return False, invalid_ips

    return True, []

def parse_firewall_group_members(xml_text: str, group_type: str = "IP"):
    """
    Sophos Firewall XML API Group 조회 응답에서 그룹 멤버 객체명을 최대한 유연하게 추출.
    실제 응답 구조가 버전별로 조금 다를 수 있어서 Raw Response도 같이 보관한다.
    """
    xml_text = str(xml_text or "").strip()

    result = {
        "group_type": group_type,
        "group_name": "",
        "members": [],
        "status_code": "",
        "status_message": "",
        "raw": xml_text,
    }

    if not xml_text:
        return result

    parsed_status = parse_firewall_api_response(xml_text)
    result["status_code"] = str(parsed_status.get("code", ""))
    result["status_message"] = str(parsed_status.get("message", ""))

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return result

    group_type = str(group_type or "IP").upper()

    if group_type == "DOMAIN":
        group_tags = {"FQDNHostGroup"}
        member_tags = {
            "FQDNHost",
            "Host",
            "Member",
            "HostName",
            "Name",
        }
        skip_group_name_tag = "FQDNHostGroup"
    else:
        group_tags = {"IPHostGroup"}
        member_tags = {
            "IPHost",
            "Host",
            "Member",
            "HostName",
            "Name",
        }
        skip_group_name_tag = "IPHostGroup"

    group_nodes = []

    for node in root.iter():
        tag = str(node.tag or "").split("}")[-1]
        if tag in group_tags:
            group_nodes.append(node)

    if not group_nodes:
        return result

    group_node = group_nodes[0]

    # 그룹명 추출
    for child in group_node.iter():
        tag = str(child.tag or "").split("}")[-1]
        text = str(child.text or "").strip()
        if tag == "Name" and text:
            result["group_name"] = text
            break

    members = []
    seen = set()

    for node in group_node.iter():
        tag = str(node.tag or "").split("}")[-1]
        text = str(node.text or "").strip()

        if not text:
            continue

        # 첫 번째 Name은 그룹명일 가능성이 높으므로 제외
        if tag == "Name" and text == result.get("group_name"):
            continue

        # Description / Status 류 제외
        if tag in {"Description", "Status", "Filter"}:
            continue

        # 멤버 후보 태그만 수집
        if tag not in member_tags:
            continue

        # 방화벽 객체명 기준: AIDR_ 로 생성한 객체 우선
        # 단, 실제 운영에서 수동 객체도 볼 수 있게 AIDR_가 아니어도 수집은 허용
        if text in seen:
            continue

        seen.add(text)

        value = text
        if text.startswith("AIDR_"):
            value = text.replace("AIDR_", "", 1)

        members.append({
            "object_name": text,
            "value": value,
        })

    result["members"] = members
    return result

def parse_firewall_api_response(xml_text: str):
    xml_text = str(xml_text or "").strip()

    if not xml_text:
        return {
            "code": "",
            "message": "",
        }

    try:
        root = ET.fromstring(xml_text)

        # 핵심: Response 바로 아래가 아니라 하위 전체에서 Status 찾기
        status = root.find(".//Status")

        if status is None:
            return {
                "code": "",
                "message": xml_text,
            }

        code = str(status.attrib.get("code", "")).strip()
        message = str(status.text or "").strip()

        return {
            "code": code,
            "message": message,
        }

    except Exception:
        m_code = re.search(r'code="([^"]+)"', xml_text)
        code = m_code.group(1).strip() if m_code else ""

        m_msg = re.search(r'<Status[^>]*>(.*?)</Status>', xml_text, re.DOTALL)
        message = m_msg.group(1).strip() if m_msg else xml_text

        return {
            "code": code,
            "message": message,
        }

def safe_json_loads(value, default=None):
    if default is None:
        default = {}

    if isinstance(value, dict):
        return value

    if not value:
        return default

    try:
        return json.loads(value)
    except Exception:
        return default

def shorten_path_text(text, max_len=46):
    s = str(text or "").strip()
    if not s:
        return "-"

    s = s.replace("\\", "/")
    parts = [p for p in s.split("/") if p]

    if not parts:
        return "-"

    filename = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else ""

    # 1차: .../folder/file.ext
    if parent:
        candidate = f".../{parent}/{filename}"
        if len(candidate) <= max_len:
            return candidate

    # 2차: .../file.ext
    candidate = f".../{filename}"
    if len(candidate) <= max_len:
        return candidate

    # 3차: 파일명 자체를 최대한 살리되, 확장자는 유지
    name, ext = os.path.splitext(filename)

    if ext:
        remain = max_len - len(".../") - len(ext)
        if remain > 1:
            return f".../{name[:remain]}{ext}"

    remain = max_len - len(".../")
    if remain > 1:
        return f".../{filename[:remain]}"

    return f".../{filename}"

def join_or_none(values):
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join([str(x) for x in values if str(x).strip()]) or "None"
    return str(values) if str(values).strip() else "None"


def extract_xdr_email_fields(d):
    rule = "None"
    dd = d.get("detectionDescription", {})
    if isinstance(dd, dict):
        rule = dd.get("createdReasonId", "None") or "None"
    if rule == "None":
        rule = d.get("detectionRule", "None") or "None"

    raw_data = d.get("rawData", {})
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw = safe_json_loads(raw_data.get("raw"), {})
    if not isinstance(raw, dict):
        raw = {}

    from_addr = raw.get("mailFrom") or raw.get("from") or "None"

    mailbox = "None"
    if raw.get("mailboxAddress"):
        mailbox = raw.get("mailboxAddress")
    elif raw.get("envelopeRecipients"):
        mailbox = join_or_none(raw.get("envelopeRecipients"))

    to_value = "None"
    if raw.get("to"):
        to_value = join_or_none(raw.get("to"))
    elif raw.get("mailboxAddress"):
        to_value = raw.get("mailboxAddress")
    elif raw.get("envelopeRecipients"):
        to_value = join_or_none(raw.get("envelopeRecipients"))

    subject = raw.get("subject") or "None"
    sender_ip = raw.get("clientIp") or "None"

    ioc = "None"
    ioc_sha = "None"
    detail = "None"

    if rule == "XDR-sophos-email-maliciousurl":
        url_data = raw.get("highRiskUrlData", {})
        urls = url_data.get("urls", []) if isinstance(url_data, dict) else []
        if urls and isinstance(urls[0], dict):
            ioc = urls[0].get("url") or "None"
            detail = urls[0].get("urlCategory") or "None"

    elif rule == "XDR-sophos-email-virus":
        attachments = raw.get("attachments", [])
        if attachments and isinstance(attachments[0], dict):
            att = attachments[0]
            ioc = att.get("name") or "None"
            ioc_sha = att.get("checksum") or "None"
            detail = att.get("intelixThreatVerdict") or "None"

    elif rule == "XDR-sophos-email-impersonation":
        impersonation = raw.get("impersonationData", {})
        if isinstance(impersonation, dict):
            ioc = impersonation.get("categoryDetails") or "None"
            category = impersonation.get("category") or "None"
            is_imp = impersonation.get("isImpersonation")
            if is_imp is None:
                detail = category
            else:
                detail = f"{category} / isImpersonation={is_imp}"

    return {
        "time": kst_time(d.get("time")),
        "rule": rule,
        "mailbox": str(mailbox),
        "from": str(from_addr),
        "to": str(to_value),
        "subject": str(subject),
        "sender_ip": str(sender_ip),
        "ioc": str(ioc),
        "ioc_sha": str(ioc_sha),
        "detail": str(detail),
        "raw": d,
    }

def get_display_file_and_sha(raw):
    if not isinstance(raw, dict):
        return "None", "None"

    # 1) ioc_event_files 우선
    files = raw.get("ioc_event_files", [])
    f0 = files[0] if isinstance(files, list) and files and isinstance(files[0], dict) else {}

    file_name = f0.get("file_name")
    file_sha = f0.get("sha256")

    if file_name:
        return file_name, (file_sha or "None")

    # 2) 일반 프로세스/파일명 fallback
    display_name = (
        raw.get("process_name")
        or raw.get("meta_process_name")
        or raw.get("target_process_name")
        or raw.get("name")
        or raw.get("file_name")
        or raw.get("original_filename")
        or "None"
    )

    display_sha = (
        raw.get("process_sha256")
        or raw.get("meta_sha256")
        or raw.get("target_process_sha256")
        or raw.get("sha256")
        or "None"
    )

    return display_name, display_sha

def email_addr(obj):
    if not isinstance(obj, dict):
        return "None"
    return f"{obj.get('localAddress','')}@{obj.get('domainAddress','')}".strip("@")


def day_key_from_iso(iso_str):
    """ISO time -> 'YYYY-MM-DD' (KST 기준으로 자르기)"""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        kst = dt.astimezone(timezone(timedelta(hours=9)))
        return kst.strftime("%Y-%m-%d")
    except Exception:
        return None


def save_day_json(base_dir, day_key, items):
    """cache/{type}/{YYYY-MM-DD}.json 로 overwrite 저장"""
    if not day_key:
        return
    path = os.path.join(base_dir, f"{day_key}.json")
    save_json(path, items)



# ======================================================
# Identity / organization mapping
# - Normalizes user names, user IDs, hostnames, mailbox aliases, and exception rules.
# - Builds lookup maps used by Detection, Email-XDR, File/DLP, reports, exports, and Timeline.
# - Later module target: core/identity.py or modules/directory/identity.py.
# ======================================================

def normalize_name_key(value):
    return re.sub(r"\s+", "", str(value or "")).strip().lower()

def normalize_org_match_name(value):
    s = str(value or "").strip()

    if "\\" in s:
        left, right = s.split("\\", 1)
        if right.strip().lower() in {"locknlock", "lnl", "local"}:
            s = left.strip()
        else:
            s = right.strip()

    s = re.sub(r"(?i)_mac$", "", s).strip()
    return s

def is_shared_pc_name(value):
    s = str(value or "").strip()
    return bool(re.match(r"(?i)^asset-\d+$", s))

def load_report_exception_map():
    result = {}

    if not os.path.exists(REPORT_EXCEPTION_LIST_PATH):
        return result

    try:
        with open(REPORT_EXCEPTION_LIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = normalize_name_key(key)
                value = str(value or "").strip()

                if key and value:
                    result[key] = value
    except Exception as e:
        log.warning(f"Failed to load report exception list: {e}")

    return result


def save_report_exception_text(raw_text: str):
    lines = []

    for line in str(raw_text or "").splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        lines.append(line)

    tmp_path = REPORT_EXCEPTION_LIST_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        if lines:
            f.write("\n")

    os.replace(tmp_path, REPORT_EXCEPTION_LIST_PATH)

def build_org_user_index():
    result = {}

    for org in ORGS:
        if not isinstance(org, dict):
            continue

        dept_code = str(org.get("deptCode", "") or "").strip()
        raw_dept_name = str(org.get("deptName", "") or "").strip()
        dept_name = DEPT_MAP.get(dept_code, raw_dept_name) or "미분류"

        users = org.get("users", [])
        if not isinstance(users, list):
            continue

        for u in users:
            if isinstance(u, dict):
                org_user_name = str(u.get("name", "") or "").strip()
                org_user_id = str(u.get("id", "") or u.get("userId", "") or "").strip()
            else:
                org_user_name = str(u or "").strip()
                org_user_id = ""

            if org_user_name:
                result[normalize_name_key(org_user_name)] = {
                    "dept_name": dept_name,
                    "dept_code": dept_code,
                }

            if org_user_id:
                result[normalize_name_key(org_user_id)] = {
                    "dept_name": dept_name,
                    "dept_code": dept_code,
                }

    return result


def build_hostname_user_map():
    result = {}

    for e in ENDPOINTS:
        if not isinstance(e, dict):
            continue

        hostname = str(e.get("hostname", "") or "").strip()
        if not hostname:
            continue

        person = e.get("associatedPerson", {})
        if not isinstance(person, dict):
            person = {}

        raw_name = str(person.get("name", "") or "").strip()
        via_login = str(person.get("viaLogin", "") or "").strip()
        user_id = via_login.split("\\")[-1] if "\\" in via_login else via_login
        user_name = normalize_org_match_name(raw_name)

        if is_shared_pc_name(user_name) or is_shared_pc_name(hostname):
            user_name = "공용PC"

        result[normalize_name_key(hostname)] = {
            "hostname": hostname,
            "user_name": user_name,
            "user_id": user_id,
        }

    return result


def get_directory_user_dept(user):
    if not isinstance(user, dict):
        return "미분류", ""

    source = user.get("source", {}) if isinstance(user.get("source"), dict) else {}
    source_type = str(source.get("type", "") or "").strip()
    if source_type and source_type != "activeDirectory":
        return "미분류", ""

    groups = user.get("groups", {}) if isinstance(user.get("groups"), dict) else {}
    items = groups.get("items", [])
    if not isinstance(items, list):
        return "미분류", ""

    for group in reversed(items):
        if not isinstance(group, dict):
            continue
        dept_code = str(group.get("displayName", "") or "").strip()
        if not dept_code.isdigit():
            continue
        return DEPT_MAP.get(dept_code, dept_code) or "미분류", dept_code

    return "미분류", ""


def build_directory_user_index():
    result = {}

    for user in USERS:
        if not isinstance(user, dict):
            continue

        source = user.get("source", {}) if isinstance(user.get("source"), dict) else {}
        source_type = str(source.get("type", "") or "").strip()
        if source_type and source_type != "activeDirectory":
            continue

        dept_name, dept_code = get_directory_user_dept(user)

        entry = {
            "name": str(user.get("name", "") or "").strip(),
            "user_id": str(user.get("exchangeLogin", "") or "").strip(),
            "email": str(user.get("email", "") or "").strip(),
            "dept_name": dept_name,
            "dept_code": dept_code,
        }

        keys = []
        if entry["name"]:
            keys.append(entry["name"])
        if entry["user_id"]:
            keys.append(entry["user_id"])
        if entry["email"]:
            keys.append(entry["email"])
            if "@" in entry["email"]:
                keys.append(entry["email"].split("@", 1)[0])

        for key in keys:
            norm_key = normalize_name_key(key)
            if norm_key:
                result[norm_key] = entry

    return result


def get_directory_user_info(*values):
    for value in values:
        key = normalize_name_key(value)
        if not key:
            continue
        info = DIRECTORY_USER_INDEX.get(key)
        if info:
            return info
    return {}


def build_hostname_dept_map():
    result = {}

    for host_key, info in HOSTNAME_USER_MAP.items():
        hostname = str(info.get("hostname", "") or "").strip()
        user_name = str(info.get("user_name", "") or "").strip()
        user_id = str(info.get("user_id", "") or "").strip()

        dept_name = "미분류"
        dept_code = ""

        if user_name:
            org_info = USER_ORG_INDEX.get(normalize_name_key(user_name))
            if not org_info and user_id:
                org_info = USER_ORG_INDEX.get(normalize_name_key(user_id))

            if org_info:
                dept_name = str(org_info.get("dept_name", "미분류") or "미분류")
                dept_code = str(org_info.get("dept_code", "") or "")

        if dept_name == "미분류" and user_id:
            directory_info = get_directory_user_info(user_id)
            if directory_info:
                dept_name = str(directory_info.get("dept_name", "미분류") or "미분류")
                dept_code = str(directory_info.get("dept_code", "") or "")

        # Report_exception_List 는 일반 분류가 끝난 뒤 마지막에 덮어쓴다.
        exc_dept = get_report_exception_dept(user_name, user_id, hostname)
        if exc_dept:
            dept_name = exc_dept
            dept_code = ""

        result[host_key] = {
            "dept_name": dept_name,
            "dept_code": dept_code,
        }

    return result

def resolve_identity_by_hostname(hostname: str):
    host = str(hostname or "").strip()
    if not host:
        return {
            "hostname": "None",
            "user_name": "None",
            "user_id": "",
            "dept_name": "미분류",
            "dept_code": "",
        }

    user_name, user_id, _ = get_endpoint_user_by_machine_name(host)

    if not user_name:
        user_name = "None"

    dept_name, dept_code = get_dept_by_hostname(host)

    return {
        "hostname": host,
        "user_name": str(user_name or "None"),
        "user_id": str(user_id or ""),
        "dept_name": str(dept_name or "미분류"),
        "dept_code": str(dept_code or ""),
    }

def get_org_user_name_by_user_id(user_id: str):
    user_id_key = normalize_name_key(user_id)
    if not user_id_key:
        return ""

    for org in ORGS:
        if not isinstance(org, dict):
            continue

        users = org.get("users", [])
        if not isinstance(users, list):
            continue

        for u in users:
            if not isinstance(u, dict):
                continue

            org_user_id = str(u.get("id", "") or u.get("userId", "") or "").strip()
            if org_user_id and normalize_name_key(org_user_id) == user_id_key:
                return str(u.get("name", "") or "").strip()

    return ""


def resolve_identity_by_mailbox(mailbox_addr: str):
    mailbox_addr = str(mailbox_addr or "").strip()
    mailbox_lower = mailbox_addr.lower()

    if not mailbox_lower or "@" not in mailbox_lower:
        return {
            "mailbox": mailbox_addr or "None",
            "mailbox_user": "",
            "hostname": "None",
            "user_id": "None",
            "user_name": "None",
            "dept_name": "미분류",
            "dept_code": "",
        }

    mailbox_user = mailbox_lower.split("@", 1)[0].strip()

    matched_hostname = "None"
    matched_user_id = "None"
    matched_user_name = "None"

    for ep in ENDPOINTS:
        if not isinstance(ep, dict):
            continue

        ap = ep.get("associatedPerson") or {}
        via_login = str(ap.get("viaLogin") or "").strip()
        if not via_login:
            continue

        login_user = via_login.split("\\")[-1].strip().lower()
        if not login_user:
            continue

        if login_user == mailbox_user:
            matched_hostname = str(ep.get("hostname") or "None")
            matched_user_id = via_login.split("\\")[-1].strip() or "None"
            matched_user_name = str(ap.get("name") or "None")
            break

    dept_name = "미분류"
    dept_code = ""

    if matched_hostname != "None":
        dept_name, dept_code = get_dept_by_hostname(matched_hostname)
    elif mailbox_user:
        # Endpoint 매칭이 안 되면 mailbox local-part를 User ID로 보고 User API 맵을 먼저 시도한다.
        matched_user_id = mailbox_user
        directory_info = get_directory_user_info(mailbox_addr, mailbox_user)
        if directory_info:
            matched_user_name = str(directory_info.get("name", "") or "None")
            matched_user_id = str(directory_info.get("user_id", "") or mailbox_user)
            dept_name = str(directory_info.get("dept_name", "미분류") or "미분류")
            dept_code = str(directory_info.get("dept_code", "") or "")
        else:
            org_user_name = get_org_user_name_by_user_id(mailbox_user)
            if org_user_name:
                matched_user_name = org_user_name
            dept_name, dept_code = get_org_info_by_user(org_user_name, mailbox_user, mailbox_user)

    # Report_exception_List 는 Endpoint/User API/조직도 분류가 끝난 뒤 마지막에 덮어쓴다.
    exc_dept = get_report_exception_dept(matched_user_name, matched_user_id, mailbox_user, mailbox_addr)
    if exc_dept:
        dept_name = exc_dept
        dept_code = ""

    return {
        "mailbox": mailbox_addr or "None",
        "mailbox_user": mailbox_user,
        "hostname": matched_hostname,
        "user_id": matched_user_id,
        "user_name": matched_user_name,
        "dept_name": dept_name or "미분류",
        "dept_code": dept_code or "",
    }

def get_dept_by_hostname(hostname: str):
    key = normalize_name_key(hostname)
    if not key:
        return "미분류", ""

    info = HOSTNAME_DEPT_MAP.get(key, {})
    return (
        str(info.get("dept_name", "미분류") or "미분류"),
        str(info.get("dept_code", "") or ""),
    )

def reload_all_data():
    global ENDPOINTS, ORGS, USERS, REPORT_EXCEPTION_MAP
    global USER_ORG_INDEX, DIRECTORY_USER_INDEX, HOSTNAME_USER_MAP, HOSTNAME_DEPT_MAP

    ENDPOINTS = load_app_cache_single("endpoints", os.path.join(CACHE_DIR, "endpoints.json"))
    ORGS = load_app_cache_single("orgs", os.path.join(CACHE_DIR, "user_groups.json"))
    USERS = load_app_cache_single("users", os.path.join(CACHE_DIR, "users.json"))
    REPORT_EXCEPTION_MAP = load_report_exception_map()

    USER_ORG_INDEX = build_org_user_index()
    DIRECTORY_USER_INDEX = build_directory_user_index()
    HOSTNAME_USER_MAP = build_hostname_user_map()
    HOSTNAME_DEPT_MAP = build_hostname_dept_map()

    log.info(
        f"[ORG MAP] endpoints={len(ENDPOINTS)} orgs={len(ORGS)} users={len(USERS)} "
        f"user_index={len(USER_ORG_INDEX)} directory_user_index={len(DIRECTORY_USER_INDEX)} "
        f"hostname_index={len(HOSTNAME_DEPT_MAP)}"
    )



def get_endpoint_user_by_machine_name(machine_name):
    target = normalize_name_key(machine_name)
    if not target:
        return "", "", ""

    for e in ENDPOINTS:
        if not isinstance(e, dict):
            continue

        hostname = str(e.get("hostname", "") or "").strip()
        if normalize_name_key(hostname) != target:
            continue

        person = e.get("associatedPerson", {})
        if not isinstance(person, dict):
            person = {}

        raw_name = str(person.get("name", "") or "").strip()
        via_login = str(person.get("viaLogin", "") or "").strip()
        user_id = via_login.split("\\")[-1] if "\\" in via_login else via_login

        user_name = normalize_org_match_name(raw_name)

        # Asset-xxxx 형태는 공용PC로 처리
        if is_shared_pc_name(user_name) or is_shared_pc_name(hostname):
            return "공용PC", user_id, "shared_pc"

        return user_name, user_id, "normal"

    return "", "", "not_found"


def get_org_info_by_user(user_name, user_id="", hostname=""):
    user_name_key = normalize_name_key(user_name)
    user_id_key = normalize_name_key(user_id)

    dept_name = "미분류"
    dept_code = ""

    for org in ORGS:
        if not isinstance(org, dict):
            continue

        org_dept_code = str(org.get("deptCode", "") or "").strip()
        raw_dept_name = str(org.get("deptName", "") or "").strip()
        org_dept_name = DEPT_MAP.get(org_dept_code, raw_dept_name) or "미분류"

        users = org.get("users", [])
        if not isinstance(users, list):
            continue

        matched = False
        for u in users:
            if isinstance(u, dict):
                org_user_name = str(u.get("name", "") or "").strip()
                org_user_id = str(u.get("id", "") or u.get("userId", "") or "").strip()
            else:
                org_user_name = str(u or "").strip()
                org_user_id = ""

            if user_name_key and normalize_name_key(org_user_name) == user_name_key:
                matched = True
                break

            if user_id_key and org_user_id and normalize_name_key(org_user_id) == user_id_key:
                matched = True
                break

        if matched:
            dept_name = org_dept_name
            dept_code = org_dept_code
            break

    if dept_name == "미분류" and user_id:
        directory_info = get_directory_user_info(user_id)
        if directory_info:
            dept_name = str(directory_info.get("dept_name", "미분류") or "미분류")
            dept_code = str(directory_info.get("dept_code", "") or "")

    # Report_exception_List 는 일반 분류가 끝난 뒤 마지막에 덮어쓴다.
    exc_dept = get_report_exception_dept(user_name, user_id, hostname)
    if exc_dept:
        return exc_dept, ""

    return dept_name, dept_code

def get_report_exception_dept(*values):
    for value in values:
        key = normalize_name_key(value)
        if not key:
            continue

        dept = str(REPORT_EXCEPTION_MAP.get(key, "") or "").strip()
        if dept:
            return dept

    return ""



# ======================================================
# Timeline / identity context, normalization, search index
# - Expands a user search term into related hostnames/mailboxes/user IDs.
# - Normalizes Detection, Email-XDR, Email, and DLP rows into timeline events.
# - Builds/query token indexes for fast timeline search.
# - Later module target: modules/timeline/
# ======================================================
def timeline_add_alias(ctx, category, value):
    value = str(value or "").strip()
    if not value or value in {"None", "미분류"}:
        return

    ctx.setdefault(category, set()).add(value)
    if category == "dept_names":
        return

    ctx.setdefault("all_values", set()).add(value)

    key = normalize_name_key(value)
    if key:
        ctx.setdefault("all_keys", set()).add(key)

    if "@" in value:
        local = value.split("@", 1)[0].strip()
        if local:
            ctx.setdefault("email_locals", set()).add(local)
            ctx.setdefault("all_values", set()).add(local)
            local_key = normalize_name_key(local)
            if local_key:
                ctx.setdefault("all_keys", set()).add(local_key)


def timeline_add_directory_info(ctx, info):
    if not isinstance(info, dict) or not info:
        return False

    timeline_add_alias(ctx, "names", info.get("name"))
    timeline_add_alias(ctx, "user_ids", info.get("user_id"))
    timeline_add_alias(ctx, "emails", info.get("email"))
    timeline_add_alias(ctx, "dept_names", info.get("dept_name"))
    return True


def timeline_add_endpoint_info(ctx, info):
    if not isinstance(info, dict) or not info:
        return False

    timeline_add_alias(ctx, "hostnames", info.get("hostname"))
    timeline_add_alias(ctx, "names", info.get("user_name"))
    timeline_add_alias(ctx, "user_ids", info.get("user_id"))
    return True


def build_timeline_identity_context(keyword):
    keyword = str(keyword or "").strip()
    ctx = {
        "input": keyword,
        "input_lower": keyword.lower(),
        "names": set(),
        "user_ids": set(),
        "emails": set(),
        "email_locals": set(),
        "hostnames": set(),
        "dept_names": set(),
        "all_values": set(),
        "all_keys": set(),
    }

    timeline_add_alias(ctx, "all_values", keyword)
    if "@" in keyword:
        timeline_add_alias(ctx, "emails", keyword)
    else:
        timeline_add_alias(ctx, "user_ids", keyword)
        timeline_add_alias(ctx, "names", keyword)
        timeline_add_alias(ctx, "hostnames", keyword)

    # Directory Users API cache: user_id/email/email local-part 기준 확장
    timeline_add_directory_info(ctx, get_directory_user_info(keyword))

    # Mailbox로 입력된 경우 XDR/email identity resolver를 통해 확장
    if "@" in keyword:
        mailbox_identity = resolve_identity_by_mailbox(keyword)
        timeline_add_alias(ctx, "names", mailbox_identity.get("user_name"))
        timeline_add_alias(ctx, "user_ids", mailbox_identity.get("user_id"))
        timeline_add_alias(ctx, "hostnames", mailbox_identity.get("hostname"))
        timeline_add_alias(ctx, "dept_names", mailbox_identity.get("dept_name"))

    # Hostname으로 입력된 경우 Endpoint identity resolver를 통해 확장
    host_identity = resolve_identity_by_hostname(keyword)
    if host_identity.get("hostname") != "None" or host_identity.get("user_name") != "None":
        timeline_add_alias(ctx, "hostnames", host_identity.get("hostname"))
        timeline_add_alias(ctx, "names", host_identity.get("user_name"))
        timeline_add_alias(ctx, "user_ids", host_identity.get("user_id"))
        timeline_add_alias(ctx, "dept_names", host_identity.get("dept_name"))

    # Endpoint map 역방향 확장: 이름/UserID/Hostname 중 하나가 맞으면 나머지 alias 추가
    for _ in range(2):
        changed = False
        for info in HOSTNAME_USER_MAP.values():
            if not isinstance(info, dict):
                continue
            values = [info.get("hostname"), info.get("user_name"), info.get("user_id")]
            if any(normalize_name_key(v) in ctx["all_keys"] for v in values if v):
                before = len(ctx["all_keys"])
                timeline_add_endpoint_info(ctx, info)
                changed = changed or len(ctx["all_keys"]) != before
        if not changed:
            break

    # Directory index 역방향 확장: 이름/UserID/email 중 하나가 맞으면 나머지 alias 추가
    seen_entries = set()
    for info in DIRECTORY_USER_INDEX.values():
        if not isinstance(info, dict):
            continue
        entry_key = (info.get("name"), info.get("user_id"), info.get("email"))
        if entry_key in seen_entries:
            continue
        seen_entries.add(entry_key)
        values = [info.get("name"), info.get("user_id"), info.get("email")]
        values += [str(info.get("email", "")).split("@", 1)[0]] if info.get("email") else []
        if any(normalize_name_key(v) in ctx["all_keys"] for v in values if v):
            timeline_add_directory_info(ctx, info)

    exc_dept = get_report_exception_dept(keyword)
    if exc_dept:
        timeline_add_alias(ctx, "dept_names", exc_dept)

    return ctx


def timeline_value_matches_context(value, ctx):
    value = str(value or "").strip()
    if not value or value == "None":
        return False

    key = normalize_name_key(value)
    if key and key in ctx.get("all_keys", set()):
        return True

    if "@" in value:
        local = value.split("@", 1)[0].strip()
        if normalize_name_key(local) in ctx.get("all_keys", set()):
            return True

    raw = ctx.get("input_lower", "")
    if raw and raw in value.lower():
        return True

    return False


def timeline_identity_matches(identity, ctx):
    if not isinstance(identity, dict):
        return False
    return any(timeline_value_matches_context(identity.get(k), ctx) for k in (
        "user_name", "user_id", "hostname", "mailbox"
    ))


def timeline_parse_dt(value):
    value = str(value or "").strip()
    if not value or value == "None":
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value[:19], fmt)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
    except Exception:
        return None


def timeline_bucket_minute(time_text):
    dt = timeline_parse_dt(time_text)
    if dt:
        bucket_minute = (dt.minute // 5) * 5
        return dt.replace(minute=bucket_minute, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")
    text = str(time_text or "")
    return text[:16] if len(text) >= 16 else text


def make_timeline_event(time_text, source, user, user_id, dept, asset, event, direction, peer, summary, indicator, raw, match_values):
    return {
        "time": str(time_text or "None"),
        "bucket": timeline_bucket_minute(time_text),
        "source": str(source or "None"),
        "user": str(user or "None"),
        "user_id": str(user_id or "None"),
        "dept": str(dept or "미분류"),
        "asset": str(asset or "None"),
        "event": str(event or "None"),
        "direction": str(direction or "None"),
        "peer": str(peer or "None"),
        "summary": str(summary or "None"),
        "indicator": str(indicator or "None"),
        "raw": raw,
        "match_values": [str(v) for v in (match_values or []) if str(v or "").strip()],
    }


TIMELINE_SOURCE_DISPLAY_NAMES = {
    "Detection": "Detection - XDR",
    "XDR": "Email - XDR",
    "Email": "Inbound Mail",
    "Outbound Mail": "Outbound Mail",
    "File": "File",
}


def timeline_source_display_name(source):
    return TIMELINE_SOURCE_DISPLAY_NAMES.get(str(source or ""), str(source or "None"))


def timeline_event_matches(event, ctx):
    for value in event.get("match_values", []):
        if timeline_value_matches_context(value, ctx):
            return True
    return False


def timeline_event_search_values(event):
    values = [
        event.get("time"),
        event.get("source"),
        timeline_source_display_name(event.get("source")),
        event.get("user"),
        event.get("user_id"),
        event.get("dept"),
        event.get("asset"),
        event.get("event"),
        event.get("direction"),
        event.get("peer"),
        event.get("summary"),
        event.get("indicator"),
    ]
    values.extend(event.get("match_values", []) or [])

    raw = event.get("raw")
    if raw is not None:
        try:
            values.append(json.dumps(raw, ensure_ascii=False, default=str))
        except Exception:
            values.append(str(raw))

    return values


def timeline_event_matches_keyword(event, keyword):
    keyword = normalize_timeline_keyword_text(keyword)
    if not keyword:
        return True

    search_text = normalize_timeline_keyword_text(" ".join(str(v or "") for v in timeline_event_search_values(event)))
    return keyword in search_text


def normalize_timeline_detection(d, ctx):
    if not isinstance(d, dict):
        return None
    if get_detection_sensor_type(d) != "endpoint":
        return None

    event_time = d.get("time")
    if not event_time:
        return None

    raw = d.get("rawData", {}) if isinstance(d.get("rawData"), dict) else {}
    hostname = raw.get("meta_hostname", "None")
    identity = resolve_identity_by_hostname(hostname)
    rule = "None"
    dd = d.get("detectionDescription", {})
    if isinstance(dd, dict):
        rule = dd.get("createdReasonId", "None") or "None"
    if rule == "None":
        rule = d.get("rule", "None") or d.get("detectionRule", "None") or "None"

    file_name, sha = get_display_file_and_sha(raw)
    private_ip = raw.get("meta_ip_address") or "None"
    public_ip = raw.get("meta_public_ip") or "None"
    summary = file_name if file_name != "None" else f"{private_ip} / {public_ip}"
    indicator = sha if sha != "None" else public_ip

    event = make_timeline_event(
        kst_time(event_time), "Detection",
        identity.get("user_name", "None"), identity.get("user_id", "None"), identity.get("dept_name", "미분류"),
        hostname, rule, "Host", private_ip, summary, indicator, d,
        [hostname, identity.get("user_name"), identity.get("user_id")]
    )
    return event if ctx is None or timeline_event_matches(event, ctx) else None


def normalize_timeline_xdr(d, ctx):
    if not isinstance(d, dict):
        return None
    if get_detection_sensor_type(d) != "email":
        return None

    row_data = extract_xdr_email_fields(d)
    if row_data.get("rule") not in XDR_EMAIL_RULES:
        return None

    identity = resolve_identity_by_mailbox(row_data.get("mailbox"))
    direction = f"{row_data.get('from', 'None')} → {row_data.get('to', 'None')}"
    peer = row_data.get("from") or row_data.get("sender_ip") or "None"
    indicator = row_data.get("ioc") if row_data.get("ioc") != "None" else row_data.get("ioc_sha", "None")
    event = make_timeline_event(
        row_data.get("time"), "XDR",
        identity.get("user_name", "None"), identity.get("user_id", "None"), identity.get("dept_name", "미분류"),
        row_data.get("mailbox", "None"), row_data.get("rule", "None"), direction, peer,
        row_data.get("subject", "None"), indicator, row_data.get("raw", d),
        [row_data.get("mailbox"), identity.get("user_name"), identity.get("user_id")]
    )
    return event if ctx is None or timeline_event_matches(event, ctx) else None


def normalize_timeline_email(m, ctx):
    if not isinstance(m, dict):
        return []

    event_time = m.get("receivedAt")
    if not event_time:
        return []

    from_addr = email_addr(m.get("from"))
    to_list = [email_addr(x) for x in (m.get("to", []) or []) if isinstance(x, dict)]
    cc_list = [email_addr(x) for x in (m.get("cc", []) or []) if isinstance(x, dict)]
    participants = [from_addr] + to_list + cc_list
    if ctx is not None and not any(timeline_value_matches_context(addr, ctx) for addr in participants):
        return []

    matched_addr = next((addr for addr in participants if ctx is not None and timeline_value_matches_context(addr, ctx)), from_addr)
    identity = resolve_identity_by_mailbox(matched_addr) if "@" in matched_addr else {}
    direction = f"{from_addr} → {join_list(to_list)}"
    reason = str(m.get("reason", "None") or "None")
    subject = str(m.get("subject", "None") or "None")
    cip = str(m.get("clientIp", "None") or "None")

    return [make_timeline_event(
        kst_time(event_time), "Email",
        identity.get("user_name", matched_addr), identity.get("user_id", matched_addr.split("@", 1)[0] if "@" in matched_addr else "None"),
        identity.get("dept_name", "미분류"), matched_addr, reason, direction, from_addr, subject, cip, m,
        participants + [identity.get("user_name"), identity.get("user_id")]
    )]


def normalize_timeline_mailscreen(row, ctx):
    if not isinstance(row, dict):
        return None
    row = enrich_mailscreen_sender_fields(row)

    event_time = str(row.get("date", "") or "").strip()
    if not event_time:
        return None

    identity = resolve_mailscreen_sender_identity(row)
    sender = mailscreen_identity_text(row.get("sender"))
    sender_detail = mailscreen_identity_text(row.get("sender_detail"))
    receiver = mailscreen_identity_text(row.get("receiver"))
    receiver_detail = mailscreen_identity_text(row.get("receiver_detail"))
    subject = str(row.get("subject", "") or "None")
    mail_process = str(row.get("mail_process", "") or "None")
    send_result = str(row.get("send_result", "") or "None")
    send_detail = str(row.get("send_detail", "") or "None")
    policy = str(row.get("policy", "") or "None")
    source_email = mailscreen_identity_text(row.get("sender_email")) or identity.get("email") or mailscreen_extract_email(sender, sender_detail)
    sender_name = mailscreen_identity_text(row.get("sender_name")) or identity.get("user_name", "None")
    sender_dept = mailscreen_identity_text(row.get("sender_dept")) or identity.get("dept_name", "미분류")
    asset = source_email or sender_detail or sender or identity.get("user_id", "None")
    event_name = f"{mail_process}/{send_result}" if mail_process != "None" and send_result != "None" else (send_result or mail_process)
    direction = f"{asset} → {receiver_detail or receiver or 'None'}"
    peer = receiver_detail or receiver or "None"
    match_values = [
        sender,
        sender_detail,
        source_email,
        sender_name,
        identity.get("user_id"),
        sender_dept,
        receiver,
        receiver_detail,
        subject,
        policy,
    ]

    event = make_timeline_event(
        event_time,
        "Outbound Mail",
        sender_name,
        identity.get("user_id", "None"),
        sender_dept,
        asset,
        event_name,
        direction,
        peer,
        subject,
        policy if policy != "None" else send_detail,
        row,
        match_values,
    )
    return event if ctx is None or timeline_event_matches(event, ctx) else None


def normalize_timeline_dlp(row, ctx):
    if not isinstance(row, dict):
        return None

    t = str(row.get("eventtimelocal", "") or "").strip()
    if not t:
        return None

    machine_name = str(row.get("machine_name", "None") or "None")
    client_name = str(row.get("client_name", "None") or "None")
    identity = resolve_identity_by_hostname(machine_name)
    dept_name = identity.get("dept_name", "미분류")
    user_name = identity.get("user_name") if identity.get("user_name") != "None" else client_name
    user_id = identity.get("user_id", "None") or "None"
    event_id = format_dlp_event_id(row.get("event_id", "None"))
    filename = str(row.get("filename", "None") or "None")
    destination = str(row.get("destination", "None") or "None")
    direction = f"{filename} → {destination}"
    indicator = str(row.get("filehash", "None") or "None")

    event = make_timeline_event(
        t, "File", user_name, user_id, dept_name, machine_name, event_id,
        direction, destination, filename, indicator, row,
        [machine_name, client_name, user_name, user_id]
    )
    return event if ctx is None or timeline_event_matches(event, ctx) else None


def iter_json_files(base_dir, suffix):
    if not os.path.isdir(base_dir):
        return []
    paths = []
    for name in os.listdir(base_dir):
        if name.endswith(suffix):
            paths.append(os.path.join(base_dir, name))
    return sorted(paths)


def group_timeline_events(events):
    grouped = {}
    for event in events:
        user_key = event.get("user_id") if event.get("user_id") != "None" else event.get("user")
        key = (
            event.get("bucket"),
            event.get("source"),
            normalize_name_key(user_key),
            normalize_name_key(event.get("asset")),
            normalize_name_key(event.get("event")),
            normalize_name_key(event.get("summary")),
        )
        if key not in grouped:
            grouped[key] = {
                "bucket": event.get("bucket"),
                "source": event.get("source"),
                "user": event.get("user"),
                "user_id": event.get("user_id"),
                "dept": event.get("dept"),
                "asset": event.get("asset"),
                "event": event.get("event"),
                "summary": event.get("summary"),
                "items": [],
            }
        grouped[key]["items"].append(event)

    groups = list(grouped.values())
    for group in groups:
        group["count"] = len(group.get("items", []))
        group["time"] = min((item.get("time", "") for item in group.get("items", [])), default=group.get("bucket", ""))

    groups.sort(key=lambda g: g.get("time", ""), reverse=True)
    return groups


def timeline_event_tokens(event):
    tokens = set()
    for value in event.get("match_values", []) or []:
        value = str(value or "").strip()
        if not value or value in {"None", "미분류"}:
            continue
        key = normalize_name_key(value)
        if key:
            tokens.add(key)
        if "@" in value:
            local_key = normalize_name_key(value.split("@", 1)[0])
            if local_key:
                tokens.add(local_key)
    return sorted(tokens)


def normalize_timeline_keyword_text(value):
    text = str(value or "").strip().lower()
    text = text.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return text


def timeline_keyword_tokens_from_text(value):
    text = normalize_timeline_keyword_text(value)
    if not text or text in {"none", "미분류"}:
        return []
    if len(text) > 2000:
        return []
    return [text]


def timeline_event_keyword_tokens(event):
    tokens = set()
    for value in timeline_event_search_values(event):
        tokens.update(timeline_keyword_tokens_from_text(value))
        if len(tokens) >= 300:
            break
    return sorted(tokens)[:300]


def timeline_event_key(source, cache_file, row_index, event):
    date_part = os.path.splitext(os.path.basename(cache_file))[0]
    raw = "|".join([
        str(source or ""),
        str(date_part or ""),
        str(row_index),
        str(event.get("time", "")),
        str(event.get("asset", "")),
        str(event.get("event", "")),
        str(event.get("summary", "")),
    ])
    digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{str(source or 'event').lower()}:{date_part}:{row_index}:{digest}"


def init_timeline_index_db(conn):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            event_key TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            time TEXT,
            bucket TEXT,
            user TEXT,
            user_id TEXT,
            dept TEXT,
            asset TEXT,
            event TEXT,
            direction TEXT,
            peer TEXT,
            summary TEXT,
            indicator TEXT,
            cache_file TEXT NOT NULL,
            row_index INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_tokens (
            token TEXT NOT NULL,
            event_key TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_keyword_tokens (
            token TEXT NOT NULL,
            event_key TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_files (
            path TEXT PRIMARY KEY,
            source TEXT,
            mtime REAL,
            size INTEGER,
            rows INTEGER,
            indexed_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_tokens_token ON timeline_tokens(token)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_tokens_event_key ON timeline_tokens(event_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_keyword_tokens_token ON timeline_keyword_tokens(token)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_keyword_tokens_event_key ON timeline_keyword_tokens(event_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_events_source ON timeline_events(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_events_time ON timeline_events(time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_events_bucket ON timeline_events(bucket)")
    conn.commit()


def insert_timeline_index_event(conn, event, cache_file, row_index):
    if not isinstance(event, dict):
        return 0
    source = str(event.get("source", "None") or "None")
    event_key = timeline_event_key(source, cache_file, row_index, event)
    conn.execute(
        """
        INSERT OR REPLACE INTO timeline_events (
            event_key, source, time, bucket, user, user_id, dept, asset, event,
            direction, peer, summary, indicator, cache_file, row_index
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_key,
            source,
            event.get("time", "None"),
            event.get("bucket", "None"),
            event.get("user", "None"),
            event.get("user_id", "None"),
            event.get("dept", "미분류"),
            event.get("asset", "None"),
            event.get("event", "None"),
            event.get("direction", "None"),
            event.get("peer", "None"),
            event.get("summary", "None"),
            event.get("indicator", "None"),
            cache_file,
            int(row_index),
        ),
    )
    token_count = 0
    for token in timeline_event_tokens(event):
        conn.execute("INSERT INTO timeline_tokens (token, event_key) VALUES (?, ?)", (token, event_key))
        token_count += 1
    for token in timeline_event_keyword_tokens(event):
        conn.execute("INSERT INTO timeline_keyword_tokens (token, event_key) VALUES (?, ?)", (token, event_key))
        token_count += 1
    return token_count


def timeline_events_from_db_rows(rows):
    events = []
    for row in rows:
        events.append({
            "event_key": row[0],
            "source": row[1],
            "time": row[2],
            "bucket": row[3],
            "user": row[4],
            "user_id": row[5],
            "dept": row[6],
            "asset": row[7],
            "event": row[8],
            "direction": row[9],
            "peer": row[10],
            "summary": row[11],
            "indicator": row[12],
            "cache_file": row[13],
            "row_index": row[14],
            "raw": None,
            "match_values": [],
        })
    return events


def load_timeline_raw_event(cache_file, row_index):
    try:
        row_index = int(row_index)
    except Exception:
        return None

    if not cache_file or not os.path.exists(cache_file):
        return None

    try:
        if str(cache_file).endswith(".jsonl"):
            with open(cache_file, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    if idx == row_index:
                        line = line.strip()
                        return json.loads(line) if line else None
            return None

        with open(cache_file, "r", encoding="utf-8") as f:
            rows = json.load(f)
        if isinstance(rows, dict) and isinstance(rows.get("items"), list):
            rows = rows.get("items", [])
        if isinstance(rows, list) and 0 <= row_index < len(rows):
            return rows[row_index]
    except Exception as e:
        log.warning(f"Failed to load timeline raw event {cache_file}#{row_index}: {e}")
    return None


def query_timeline_index(keyword, sources=None, text_keyword=""):
    if not os.path.exists(TIMELINE_INDEX_DB_PATH):
        return None, {"message": "Timeline index DB not found"}

    keyword = str(keyword or "").strip()
    text_keyword = str(text_keyword or "").strip()
    ctx = build_timeline_identity_context(keyword) if keyword else None
    identity_tokens = sorted(ctx.get("all_keys", set())) if ctx else []
    keyword_tokens = timeline_keyword_tokens_from_text(text_keyword)

    if not identity_tokens and not keyword_tokens:
        return [], {"message": "검색 token 없음", "events": 0, "groups": 0, "files": 0, "index": True}

    sources = sorted(set(sources or ["Detection", "XDR", "Email", "Outbound Mail", "File"]))
    where_clauses = []
    params = []

    if sources:
        source_placeholders = ",".join(["?"] * len(sources))
        where_clauses.append(f"e.source IN ({source_placeholders})")
        params.extend(sources)

    if identity_tokens:
        token_placeholders = ",".join(["?"] * len(identity_tokens))
        where_clauses.append(
            f"EXISTS (SELECT 1 FROM timeline_tokens t WHERE t.event_key = e.event_key AND t.token IN ({token_placeholders}))"
        )
        params.extend(identity_tokens)

    if keyword_tokens:
        keyword_placeholders = ",".join(["?"] * len(keyword_tokens))
        keyword_like_clause = " OR ".join(["kt.token LIKE ?"] * len(keyword_tokens))
        where_clauses.append(
            f"EXISTS (SELECT 1 FROM timeline_keyword_tokens kt WHERE kt.event_key = e.event_key AND (kt.token IN ({keyword_placeholders}) OR {keyword_like_clause}))"
        )
        params.extend(keyword_tokens)
        params.extend([f"%{token}%" for token in keyword_tokens])

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    sql = f"""
        SELECT DISTINCT
            e.event_key, e.source, e.time, e.bucket, e.user, e.user_id, e.dept,
            e.asset, e.event, e.direction, e.peer, e.summary, e.indicator,
            e.cache_file, e.row_index
        FROM timeline_events e
        WHERE {where_sql}
        ORDER BY e.time DESC
    """

    with sqlite3.connect(TIMELINE_INDEX_DB_PATH) as conn:
        init_timeline_index_db(conn)
        index_version_row = conn.execute(
            "SELECT value FROM timeline_meta WHERE key = ?",
            ("keyword_index_version",),
        ).fetchone()
        index_version = index_version_row[0] if index_version_row else ""
        if index_version != TIMELINE_KEYWORD_INDEX_VERSION:
            return None, {"message": "Timeline keyword index version mismatch"}
        if keyword_tokens:
            keyword_token_count = conn.execute("SELECT COUNT(*) FROM timeline_keyword_tokens").fetchone()[0]
            if keyword_token_count <= 0:
                return None, {"message": "Timeline keyword index empty"}
        rows = conn.execute(sql, params).fetchall()
        file_count = conn.execute("SELECT COUNT(*) FROM timeline_files").fetchone()[0]

    events = timeline_events_from_db_rows(rows)
    groups = group_timeline_events(events)
    return groups, {
        "message": f"인덱스 검색 완료: 이벤트 {len(events):,}건 / 그룹 {len(groups):,}개 / 파일 {file_count:,}개",
        "events": len(events),
        "groups": len(groups),
        "files": file_count,
        "aliases": sorted(ctx.get("all_values", set()))[:80] if ctx else [],
        "index": True,
    }


def index_timeline_cache_file(conn, cache_file, logical_source):
    events_count = 0
    tokens_count = 0
    rows_count = 0

    if logical_source == "detections":
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                rows = json.load(f)
        except Exception as e:
            log.warning(f"Timeline index failed to load {cache_file}: {e}")
            rows = []
        if not isinstance(rows, list):
            rows = []
        rows_count = len(rows)
        for idx, row in enumerate(rows):
            for event in (normalize_timeline_detection(row, None), normalize_timeline_xdr(row, None)):
                if event:
                    tokens_count += insert_timeline_index_event(conn, event, cache_file, idx)
                    events_count += 1

    elif logical_source == "emails":
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                rows = json.load(f)
        except Exception as e:
            log.warning(f"Timeline index failed to load {cache_file}: {e}")
            rows = []
        if not isinstance(rows, list):
            rows = []
        rows_count = len(rows)
        for idx, row in enumerate(rows):
            for event in normalize_timeline_email(row, None):
                tokens_count += insert_timeline_index_event(conn, event, cache_file, idx)
                events_count += 1

    elif logical_source == "mailscreen":
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
            rows = payload.get("items", []) if isinstance(payload, dict) else []
        except Exception as e:
            log.warning(f"Timeline index failed to load {cache_file}: {e}")
            rows = []
        if not isinstance(rows, list):
            rows = []
        rows_count = len(rows)
        for idx, row in enumerate(rows):
            event = normalize_timeline_mailscreen(row, None)
            if event:
                tokens_count += insert_timeline_index_event(conn, event, cache_file, idx)
                events_count += 1

    elif logical_source == "dlp":
        rows = load_jsonl(cache_file)
        rows_count = len(rows)
        for idx, row in enumerate(rows):
            event = normalize_timeline_dlp(row, None)
            if event:
                tokens_count += insert_timeline_index_event(conn, event, cache_file, idx)
                events_count += 1

    stat = os.stat(cache_file)
    conn.execute(
        "INSERT OR REPLACE INTO timeline_files (path, source, mtime, size, rows, indexed_at) VALUES (?, ?, ?, ?, ?, ?)",
        (cache_file, logical_source, float(stat.st_mtime), int(stat.st_size), rows_count, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    return events_count, tokens_count, rows_count


def delete_timeline_index_file(conn, cache_file):
    conn.execute(
        "DELETE FROM timeline_tokens WHERE event_key IN (SELECT event_key FROM timeline_events WHERE cache_file = ?)",
        (cache_file,),
    )
    conn.execute(
        "DELETE FROM timeline_keyword_tokens WHERE event_key IN (SELECT event_key FROM timeline_events WHERE cache_file = ?)",
        (cache_file,),
    )
    conn.execute("DELETE FROM timeline_events WHERE cache_file = ?", (cache_file,))
    conn.execute("DELETE FROM timeline_files WHERE path = ?", (cache_file,))


def rebuild_timeline_index(progress_cb=None, force=False):
    file_specs = []
    file_specs += [(path, "detections") for path in iter_json_files(DETECTIONS_DAY_DIR, ".json")]
    file_specs += [(path, "emails") for path in iter_json_files(EMAILS_DAY_DIR, ".json")]
    file_specs += [(path, "mailscreen") for path in iter_json_files(MAILSCREEN_DAY_DIR, ".json")]
    file_specs += [(path, "dlp") for path in iter_json_files(DLP_DAY_DIR, ".jsonl")]
    current_paths = {path for path, _ in file_specs}

    if force:
        for path in (TIMELINE_INDEX_DB_PATH, f"{TIMELINE_INDEX_DB_PATH}-wal", f"{TIMELINE_INDEX_DB_PATH}-shm"):
            if os.path.exists(path):
                os.remove(path)

    totals = {"events": 0, "tokens": 0, "files": 0, "rows": 0, "indexed": 0, "skipped": 0, "removed": 0}
    with sqlite3.connect(TIMELINE_INDEX_DB_PATH) as conn:
        init_timeline_index_db(conn)
        indexed_meta = {
            row[0]: {"mtime": float(row[1] or 0), "size": int(row[2] or 0)}
            for row in conn.execute("SELECT path, mtime, size FROM timeline_files").fetchall()
        }
        index_version_row = conn.execute(
            "SELECT value FROM timeline_meta WHERE key = ?",
            ("keyword_index_version",),
        ).fetchone()
        index_version = index_version_row[0] if index_version_row else ""
        if index_version != TIMELINE_KEYWORD_INDEX_VERSION:
            for table in ("timeline_tokens", "timeline_keyword_tokens", "timeline_events", "timeline_files"):
                conn.execute(f"DELETE FROM {table}")
            indexed_meta = {}
        elif indexed_meta and conn.execute("SELECT COUNT(*) FROM timeline_keyword_tokens").fetchone()[0] <= 0:
            indexed_meta = {}

        stale_paths = sorted(set(indexed_meta) - current_paths)
        for stale_path in stale_paths:
            if progress_cb:
                progress_cb(f"Timeline 인덱스 정리중 - {os.path.basename(stale_path)}")
            delete_timeline_index_file(conn, stale_path)
            totals["removed"] += 1

        for idx, (path, logical_source) in enumerate(file_specs, start=1):
            stat = os.stat(path)
            cached = indexed_meta.get(path)
            unchanged = (
                cached is not None
                and float(cached.get("mtime", 0)) == float(stat.st_mtime)
                and int(cached.get("size", 0)) == int(stat.st_size)
            )
            if unchanged:
                totals["skipped"] += 1
                continue

            if progress_cb:
                progress_cb(f"Timeline 증분 인덱싱중 {idx}/{len(file_specs)} - {logical_source} {os.path.basename(path)}")
            delete_timeline_index_file(conn, path)
            events_count, tokens_count, rows_count = index_timeline_cache_file(conn, path, logical_source)
            totals["events"] += events_count
            totals["tokens"] += tokens_count
            totals["rows"] += rows_count
            totals["indexed"] += 1
            if totals["indexed"] % 10 == 0:
                conn.commit()
        conn.commit()

        totals["events"] = conn.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]
        totals["tokens"] = conn.execute("SELECT COUNT(*) FROM timeline_tokens").fetchone()[0]
        totals["files"] = conn.execute("SELECT COUNT(*) FROM timeline_files").fetchone()[0]
        totals["rows"] = conn.execute("SELECT COALESCE(SUM(rows), 0) FROM timeline_files").fetchone()[0]
        conn.execute(
            "INSERT OR REPLACE INTO timeline_meta (key, value) VALUES (?, ?)",
            ("keyword_index_version", TIMELINE_KEYWORD_INDEX_VERSION),
        )
        conn.commit()

    totals["built_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    totals["db_path"] = TIMELINE_INDEX_DB_PATH
    return totals


# ======================================================
# Workers / data indexing
# - Runs full/incremental SQLite app-cache indexing and Timeline token indexing off the UI thread.
# - This is the shared Index Data button worker, not Timeline-only.
# - Later module target: modules/indexing/workers.py
# ======================================================
class DataIndexWorker(QThread):
    ok = pyqtSignal(dict)
    fail = pyqtSignal(str)
    progress = pyqtSignal(str)

    def run(self):
        try:
            stats = sync_app_cache_all(progress_cb=self.progress.emit)
            timeline_stats = rebuild_timeline_index(progress_cb=self.progress.emit)
            stats.update(timeline_stats)
            self.ok.emit(stats)
        except Exception as e:
            log.exception("Data index rebuild failed")
            self.fail.emit(str(e))


class DlpAllCacheLoadWorker(QThread):
    ok = pyqtSignal(object)
    fail = pyqtSignal(str)

    def __init__(self, category="전체", keyword="", sources=None, limit=SENSITIVE_FILES_PAGE_LIMIT, offset=0):
        super().__init__()
        self.category = category or "전체"
        self.keyword = keyword or ""
        self.sources = ["DLP", "Outbound Mail"] if sources is None else list(sources)
        self.limit = limit
        self.offset = offset

    def run(self):
        try:
            payload = query_sensitive_files_index(
                category=self.category,
                keyword=self.keyword,
                sources=self.sources,
                limit=self.limit,
                offset=self.offset,
            )
            self.ok.emit(payload)
        except Exception as e:
            log.exception("Sensitive Files cache load failed")
            self.fail.emit(str(e))


class SensitiveSitesLoadWorker(QThread):
    ok = pyqtSignal(object)
    fail = pyqtSignal(str)

    def __init__(self, category="전체", keyword="", sources=None, limit=SENSITIVE_SITES_PAGE_LIMIT, offset=0):
        super().__init__()
        self.category = category or "전체"
        self.keyword = keyword or ""
        self.sources = ["DLP"] if sources is None else list(sources)
        self.limit = limit
        self.offset = offset

    def run(self):
        try:
            log.info(
                "Sensitive Sites worker start category=%s keyword=%r sources=%s limit=%d offset=%d",
                self.category, self.keyword, self.sources, int(self.limit), int(self.offset),
            )
            payload = query_sensitive_sites_index(
                category=self.category,
                keyword=self.keyword,
                sources=self.sources,
                limit=self.limit,
                offset=self.offset,
            )
            log.info(
                "Sensitive Sites worker done total=%d returned=%d offset=%d index_ready=%s",
                int(payload.get("total", 0) or 0),
                len(payload.get("records", []) or []),
                int(payload.get("offset", 0) or 0),
                payload.get("index_ready"),
            )
            self.ok.emit(payload)
        except Exception as e:
            log.exception("Sensitive Sites cache load failed")
            self.fail.emit(str(e))




# ======================================================
# Workers / Timeline search
# - Searches indexed Timeline data in the background and falls back to cache scanning if needed.
# - Later module target: modules/timeline/workers.py
# ======================================================
class TimelineSearchWorker(QThread):
    ok = pyqtSignal(list, dict)
    fail = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, keyword, sources=None, text_keyword=""):
        super().__init__()
        self.keyword = str(keyword or "").strip()
        self.text_keyword = str(text_keyword or "").strip()
        self.sources = set(sources or ["Detection", "XDR", "Email", "Outbound Mail", "File"])

    def run(self):
        try:
            if not self.keyword and not self.text_keyword:
                self.ok.emit([], {"message": "검색어를 입력하세요.", "events": 0, "groups": 0})
                return

            index_groups, index_stats = query_timeline_index(self.keyword, self.sources, self.text_keyword)
            if index_groups is not None:
                self.ok.emit(index_groups, index_stats)
                return

            ctx = build_timeline_identity_context(self.keyword) if self.keyword else None
            events = []
            files_scanned = 0

            def append_if_match(event):
                if event and timeline_event_matches_keyword(event, self.text_keyword):
                    events.append(event)

            if "Detection" in self.sources or "XDR" in self.sources:
                paths = iter_json_files(DETECTIONS_DAY_DIR, ".json")
                for idx, path in enumerate(paths, start=1):
                    self.progress.emit(f"Detection - XDR / Email - XDR 캐시 검색중 {idx}/{len(paths)}")
                    files_scanned += 1
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            rows = json.load(f)
                    except Exception as e:
                        log.warning(f"Timeline failed to load {path}: {e}")
                        continue
                    if not isinstance(rows, list):
                        continue
                    for row in rows:
                        if "Detection" in self.sources:
                            event = normalize_timeline_detection(row, ctx)
                            append_if_match(event)
                        if "XDR" in self.sources:
                            event = normalize_timeline_xdr(row, ctx)
                            append_if_match(event)

            if "Email" in self.sources:
                paths = iter_json_files(EMAILS_DAY_DIR, ".json")
                for idx, path in enumerate(paths, start=1):
                    self.progress.emit(f"Inbound Mail 캐시 검색중 {idx}/{len(paths)}")
                    files_scanned += 1
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            rows = json.load(f)
                    except Exception as e:
                        log.warning(f"Timeline failed to load {path}: {e}")
                        continue
                    if not isinstance(rows, list):
                        continue
                    for row in rows:
                        for event in normalize_timeline_email(row, ctx):
                            append_if_match(event)

            if "Outbound Mail" in self.sources:
                paths = iter_json_files(MAILSCREEN_DAY_DIR, ".json")
                for idx, path in enumerate(paths, start=1):
                    self.progress.emit(f"Outbound Mail 캐시 검색중 {idx}/{len(paths)}")
                    files_scanned += 1
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            payload = json.load(f)
                        rows = payload.get("items", []) if isinstance(payload, dict) else []
                    except Exception as e:
                        log.warning(f"Timeline failed to load {path}: {e}")
                        continue
                    if not isinstance(rows, list):
                        continue
                    for row in rows:
                        event = normalize_timeline_mailscreen(row, ctx)
                        append_if_match(event)

            if "File" in self.sources:
                paths = iter_json_files(DLP_DAY_DIR, ".jsonl")
                for idx, path in enumerate(paths, start=1):
                    self.progress.emit(f"DLP 캐시 검색중 {idx}/{len(paths)}")
                    files_scanned += 1
                    for row in load_jsonl(path):
                        event = normalize_timeline_dlp(row, ctx)
                        append_if_match(event)

            groups = group_timeline_events(events)
            stats = {
                "message": f"전체 캐시 검색 완료: 이벤트 {len(events):,}건 / 그룹 {len(groups):,}개 / 파일 {files_scanned:,}개",
                "events": len(events),
                "groups": len(groups),
                "files": files_scanned,
                "aliases": sorted(ctx.get("all_values", set()))[:80] if ctx else [],
            }
            self.ok.emit(groups, stats)
        except Exception as e:
            log.exception("Timeline search failed")
            self.fail.emit(str(e))


# ======================================================
# UI components / Timeline
# - Lightweight clickable card for grouped timeline events.
# - Later module target: modules/timeline/widgets.py
# ======================================================
class TimelineEventCard(QFrame):
    clicked = pyqtSignal(object)

    def __init__(self, group, color, parent=None):
        super().__init__(parent)
        self.group = group
        self.color = color
        self.setCursor(Qt.PointingHandCursor)
        self.setObjectName("timelineEventCard")
        self.setStyleSheet(f"""
            QFrame#timelineEventCard {{
                background: {UI_THEME['surface']};
                border: 1px solid {color};
                border-radius: 12px;
            }}
            QLabel {{
                color: {UI_THEME['text']};
                background: transparent;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        source_label = timeline_source_display_name(group.get("source", "None"))
        title = QLabel(f"{group.get('bucket', 'None')}  [{source_label}]  {group.get('event', 'None')}  {group.get('count', 0)}건")
        title.setStyleSheet(f"color:{color}; font-weight:900; font-size:12px;")
        title.setWordWrap(True)
        user = QLabel(f"User: {group.get('user', 'None')} / {group.get('user_id', 'None')} / {group.get('dept', '미분류')}")
        user.setWordWrap(True)
        target = QLabel(f"Target: {group.get('asset', 'None')}")
        target.setWordWrap(True)
        summary = QLabel(f"Summary: {group.get('summary', 'None')}")
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color:{UI_THEME['text_muted']};")
        layout.addWidget(title)
        layout.addWidget(user)
        layout.addWidget(target)
        layout.addWidget(summary)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.group)
        super().mousePressEvent(event)


def resolve_history_endpoint_id_by_hostname(user_input: str):
    key = str(user_input or "").strip().lower()
    if not key:
        return None

    for e in ENDPOINTS:
        if not isinstance(e, dict):
            continue

        hostname = str(e.get("hostname", "")).strip().lower()
        if hostname != key:
            continue

        endpoint_id = str(e.get("id", "")).strip()
        if endpoint_id:
            return endpoint_id

    return None

QUERIES_PATH = os.path.join(BASE_DIR, "Query", "Queries.txt")

HISTORY_ALLOWED_QUERY_NAMES = [
    "Brute force logons (Data Lake)",
    "Disallowed credentials (Data Lake)",
    "Invalid logon (Data Lake)",
    "Successful logon (Data Lake)",
    "User account changed (Data Lake)",
    "User account created (Data Lake)",
    "User account deleted (Data Lake)",
    "User account locked out (Data Lake)",
    "User accounts (Data Lake)",
    "User logins on Linux (Data Lake)",
    "Audit log cleared (Data Lake)",
    "Audit policy changed (Data Lake)",
    "Browser plugins (Data Lake)",
    "Chrome extensions (Data Lake)",
    "Internet Explorer extensions (Data Lake)",
    "URL events on Windows (Data Lake)",
    "Running processes on Linux (Data Lake)",
    "Running processes on Windows (Data Lake)",
    "New service installed (Data Lake)",
    "Scheduled task created (Data Lake)",
    "Non-Microsoft programs run at Windows startup (Data Lake)",
    "Non-Microsoft services on Windows (Data Lake)",
    "Non-Microsoft startup items on Windows (Data Lake)",
    "Files changed on Windows (Data Lake)",
    "Windows programs (Data Lake)",
    "Device details (Data Lake)",
    "Network connections on Windows (Data Lake)",
    "DOS attack detected (Data Lake)",
]

HISTORY_QUERY_LABELS = {
    "Brute force logons (Data Lake)": "계정 공격",
    "Disallowed credentials (Data Lake)": "차단 자격증명",
    "Invalid logon (Data Lake)": "로그인 실패",
    "Successful logon (Data Lake)": "로그인 성공",
    "User account changed (Data Lake)": "계정 변경",
    "User account created (Data Lake)": "계정 생성",
    "User account deleted (Data Lake)": "계정 삭제",
    "User account locked out (Data Lake)": "계정 잠김",
    "User accounts (Data Lake)": "계정 목록",
    "User logins on Linux (Data Lake)": "리눅스 로그인",
    "Audit log cleared (Data Lake)": "감사로그 삭제",
    "Audit policy changed (Data Lake)": "감사정책 변경",
    "Browser plugins (Data Lake)": "브라우저 플러그인",
    "Chrome extensions (Data Lake)": "크롬 확장",
    "Internet Explorer extensions (Data Lake)": "IE 확장",
    "URL events on Windows (Data Lake)": "URL 접속",
    "Running processes on Linux (Data Lake)": "리눅스 프로세스",
    "Running processes on Windows (Data Lake)": "윈도우 프로세스",
    "New service installed (Data Lake)": "서비스 설치",
    "Scheduled task created (Data Lake)": "예약작업 생성",
    "Non-Microsoft programs run at Windows startup (Data Lake)": "시작프로그램",
    "Non-Microsoft services on Windows (Data Lake)": "비MS 서비스",
    "Non-Microsoft startup items on Windows (Data Lake)": "시작항목",
    "Files changed on Windows (Data Lake)": "파일 변경",
    "Windows programs (Data Lake)": "설치 프로그램",
    "Device details (Data Lake)": "장비 정보",
    "Network connections on Windows (Data Lake)": "네트워크 연결",
    "DOS attack detected (Data Lake)": "DOS 탐지",
}


def load_history_queries():
    if not os.path.exists(QUERIES_PATH):
        log.warning(f"[HISTORY QUERY] Queries file not found: {QUERIES_PATH}")
        return []

    try:
        with open(QUERIES_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        log.exception(f"[HISTORY QUERY] failed to load Queries.txt: {e}")
        return []

    items = raw.get("items", [])
    if not isinstance(items, list):
        return []

    result = []

    for item in items:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name", "")).strip()
        if name not in HISTORY_ALLOWED_QUERY_NAMES:
            continue

        query_id = str(item.get("id", "")).strip()
        if not query_id:
            continue

        variables = item.get("variables", [])
        if not isinstance(variables, list):
            variables = []

        result.append({
            "name": name,
            "id": query_id,
            "variables": variables,
            "raw": item,
        })

    result.sort(key=lambda x: x.get("name", ""))
    log.info(f"[HISTORY QUERY] loaded allowed queries: {len(result)}")
    return result


def get_history_query_by_name(query_name: str):
    target = str(query_name or "").strip()

    for item in load_history_queries():
        if str(item.get("name", "")).strip() == target:
            return item

    return None

def normalize_history_rows(query_name: str, rows: list):
    normalized = []

    for row in rows:
        if not isinstance(row, dict):
            continue

        raw = row.get("_raw", row)

        if query_name in (
            "Brute force logons (Data Lake)",
            "Invalid logon (Data Lake)",
            "Successful logon (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("subject_username", "")),
                "path": str(row.get("remote_address", "")),
                "pid": str(row.get("eventid", "")),
                "_raw": raw
            })

        elif query_name in (
            "Disallowed credentials (Data Lake)",
            "User account changed (Data Lake)",
            "User account created (Data Lake)",
            "User account deleted (Data Lake)",
            "User account locked out (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("subject_username", "")),
                "path": str(row.get("subject_domain", "")),
                "pid": str(row.get("eventid", "")),
                "_raw": raw
            })

        elif query_name == "User accounts (Data Lake)":
            normalized.append({
                "name": str(row.get("username", "")),
                "path": str(row.get("directory", "")),
                "pid": str(row.get("uid", "")),
                "_raw": raw
            })

        elif query_name == "User logins on Linux (Data Lake)":
            normalized.append({
                "name": str(row.get("username", "")),
                "path": str(row.get("host", "")),
                "pid": str(row.get("time", "")),
                "_raw": raw
            })

        elif query_name in (
            "Audit log cleared (Data Lake)",
            "Audit policy changed (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("subject_username", "")),
                "path": str(row.get("description", "")),
                "pid": str(row.get("eventid", "")),
                "_raw": raw
            })

        elif query_name in (
            "Browser plugins (Data Lake)",
            "Chrome extensions (Data Lake)",
            "Internet Explorer extensions (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("name", "")),
                "path": str(row.get("path", "")),
                "pid": str(row.get("version", "")),
                "_raw": raw
            })

        elif query_name == "URL events on Windows (Data Lake)":
            normalized.append({
                "name": str(row.get("browser_name", "")),
                "path": str(row.get("url", "")),
                "pid": str(row.get("username", "")),
                "_raw": raw
            })

        elif query_name in (
            "Running processes on Linux (Data Lake)",
            "Running processes on Windows (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("name", "")),
                "path": str(row.get("path", "")),
                "pid": str(row.get("pid", "")),
                "_raw": raw
            })

        elif query_name in (
            "New service installed (Data Lake)",
            "Scheduled task created (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("name", "")),
                "path": str(row.get("path", "")),
                "pid": str(row.get("eventid", "")),
                "_raw": raw
            })

        elif query_name in (
            "Non-Microsoft programs run at Windows startup (Data Lake)",
            "Non-Microsoft services on Windows (Data Lake)",
            "Non-Microsoft startup items on Windows (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("name", "")),
                "path": str(row.get("path", "")),
                "pid": str(row.get("version", "")),
                "_raw": raw
            })

        elif query_name in (
            "Files changed on Windows (Data Lake)",
            "Windows programs (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("filename") or row.get("name") or ""),
                "path": str(row.get("path", "")),
                "pid": str(row.get("version") or row.get("sha256") or ""),
                "_raw": raw
            })

        elif query_name == "Device details (Data Lake)":
            normalized.append({
                "name": str(row.get("ep_name", "")),
                "path": str(row.get("os", "")),
                "pid": str(row.get("type", "")),
                "_raw": raw
            })

        elif query_name in (
            "Network connections on Windows (Data Lake)",
            "DOS attack detected (Data Lake)",
        ):
            normalized.append({
                "name": str(row.get("source_ip") or row.get("type") or ""),
                "path": str(row.get("destination_ip") or row.get("description") or ""),
                "pid": str(row.get("destination_port") or row.get("eventid") or ""),
                "_raw": raw
            })

        else:
            normalized.append({
                "name": str(row.get("name") or row.get("subject_username") or row.get("username") or row.get("ep_name") or ""),
                "path": str(row.get("path") or row.get("description") or row.get("url") or ""),
                "pid": str(row.get("pid") or row.get("eventid") or row.get("version") or ""),
                "_raw": raw
            })

    return normalized

# ======================================================
# Configuration data / environment loaders
# - Loads department code mappings and environment files shared by API clients.
# - Later module target: core/env.py and core/config_data.py.
# ======================================================
def load_dept_map():
    path = USER_GROUP_ENV_PATH
    result = {}
    if not os.path.exists(path):
        return result
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    result[k.strip()] = v.strip()
    except Exception:
        pass
    return result


DEPT_MAP = load_dept_map()
reload_all_data()

# ======================================================
# API clients and UI-integrated service adapters
# - Keeps external-service clients grouped before MainWindow so they can move into modules later.
# - Later module targets: modules/sophos_event, modules/sophos_query, modules/firewall, modules/dlp.
# ======================================================
def load_env_from_file(path):
    if not os.path.exists(path):
        raise RuntimeError(f"Env file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

def load_dlp_env(path):
    if not os.path.exists(path):
        raise RuntimeError(f"Env file not found: {path}")

    values = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()

    return values

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



# ======================================================
# API clients / MailScreen
# - Uses the existing UI worker/config flow; daily cache is JSON under cache/mailscreen.
# ======================================================
MAILSCREEN_FIELD_NAMES = [
    "seq", "date", "mail_process", "send_result", "send_detail", "attach",
    "subject", "sender", "sender_detail", "dept", "receiver", "receiver_detail",
    "size", "policy", "process_date", "approver",
]


def mailscreen_env_bool(value, default=False):
    value = str(value if value is not None else "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "y", "on"}


def mailscreen_key_part_to_int(value):
    cleaned = str(value or "").strip()
    if not cleaned:
        raise RuntimeError("MailScreen RSA key part is empty")
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return int(cleaned, 16)
    if re.fullmatch(r"\d+", cleaned):
        return int(cleaned, 10)
    try:
        return int.from_bytes(base64.b64decode(cleaned), "big")
    except Exception as e:
        raise RuntimeError("Unsupported MailScreen RSA key format") from e


def mailscreen_rsa_encrypt_hex(plaintext, modulus, exponent):
    n = mailscreen_key_part_to_int(modulus)
    e = mailscreen_key_part_to_int(exponent)
    key_len = (n.bit_length() + 7) // 8
    data = str(plaintext or "").encode("utf-8")
    if len(data) > key_len - 11:
        raise RuntimeError("MailScreen login value is too long for RSA key")

    padding_len = key_len - len(data) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        padding.extend(b for b in secrets.token_bytes(padding_len - len(padding)) if b != 0)

    encoded = b"\x00\x02" + bytes(padding[:padding_len]) + b"\x00" + data
    encrypted = pow(int.from_bytes(encoded, "big"), e, n).to_bytes(key_len, "big")
    return encrypted.hex()


def mailscreen_clean_text(value):
    value = html.unescape(str(value or ""))
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    text = BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def mailscreen_tooltip_text(cell):
    candidates = []
    for node in [cell, *cell.find_all(True)]:
        value = node.get("onmouseover")
        if value:
            candidates.append(str(value))
    for value in candidates:
        match = re.search(r"tooltip\s*\([^,]+,\s*(['\"])(.*?)\1", value, re.IGNORECASE | re.DOTALL)
        if match:
            return mailscreen_clean_text(match.group(2))
    return ""


def mailscreen_cell_value(cell):
    visible = mailscreen_clean_text(cell.get_text(" ", strip=True))
    tooltip = mailscreen_tooltip_text(cell)
    return visible, tooltip


def mailscreen_parse_total_count(html_text):
    match = re.search(r"Total\s*:?\s*([\d,]+)\s*개", str(html_text or ""), re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


def mailscreen_response_preview(html_text, limit=500):
    text = mailscreen_clean_text(str(html_text or ""))
    return text[:limit]


def mailscreen_has_main_list(html_text):
    soup = BeautifulSoup(str(html_text or ""), "html.parser")
    return soup.select_one("#main_list") is not None


def mailscreen_save_debug_html(html_text, date_str, page, reason):
    safe_reason = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(reason or "debug"))[:40]
    path = os.path.join(
        LOG_DIR,
        f"mailscreen_{date_str}_page{page}_{safe_reason}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(html_text or ""))
    return path


def mailscreen_extract_login_tokens(html_text):
    soup = BeautifulSoup(html_text, "html.parser")

    def find_value(name):
        field = soup.find(attrs={"name": name}) or soup.find(id=name)
        if field:
            value = field.get("value") or field.get("content")
            if value:
                return str(value).strip()
        patterns = [
            rf"{re.escape(name)}\s*[:=]\s*['\"]([^'\"]+)['\"]",
            rf"var\s+{re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, html_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""

    tokens = {
        "ct": find_value("ct"),
        "rsa_key1": find_value("rsa_key1"),
        "rsa_key2": find_value("rsa_key2"),
    }
    missing = [k for k, v in tokens.items() if not v]
    if missing:
        raise RuntimeError("MailScreen login token missing: " + ", ".join(missing))
    return tokens


def mailscreen_parse_rows(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    tables = soup.select("#main_list")
    if not tables:
        raise RuntimeError("MailScreen #main_list table not found")

    rows = []
    for table in tables:
        for tr in table.select("tr")[1:]:
            cells = tr.find_all("td")
            if len(cells) < 13:
                continue
            checkbox = cells[0].find("input", attrs={"name": "chk[]"}) or cells[0].find("input", attrs={"type": "checkbox"})
            seq = mailscreen_clean_text(checkbox.get("value", "")) if checkbox else ""
            if not seq:
                continue

            values = [mailscreen_cell_value(cell) for cell in cells]
            row = {name: "" for name in MAILSCREEN_FIELD_NAMES}
            row["seq"] = seq
            row["date"] = values[1][1] or values[1][0]
            row["mail_process"] = values[2][1] or values[2][0]
            row["send_result"] = values[3][0]
            row["send_detail"] = values[3][1]
            row["attach"] = values[4][1] or values[4][0]
            row["subject"] = values[5][1] or values[5][0]
            row["sender"] = values[6][0]
            row["sender_detail"] = values[6][1]
            row["dept"] = values[7][1] or values[7][0]
            row["receiver"] = values[8][0]
            row["receiver_detail"] = values[8][1]
            row["size"] = values[9][1] or values[9][0]
            row["policy"] = values[10][1] or values[10][0]
            row["process_date"] = values[11][1] or values[11][0]
            row["approver"] = values[12][1] or values[12][0]
            rows.append(row)
    return rows


class MailScreenClient:
    def __init__(self, progress_cb=None):
        env = load_dlp_env(MAILSCREEN_ENV_PATH)
        self.progress_cb = progress_cb
        self.base_url = str(env.get("MS_BASE_URL", "")).strip().rstrip("/")
        self.username = str(env.get("MS_USERNAME", "")).strip()
        self.password = str(env.get("MS_PASSWORD", "")).strip()
        self.verify_ssl = mailscreen_env_bool(env.get("MS_VERIFY_SSL", "false"), default=False)
        self.timeout = int(str(env.get("MS_TIMEOUT", "30")).strip() or "30")
        self.row_num = int(str(env.get("MS_ROW_NUM", "100")).strip() or "100")
        self.sleep_seconds = float(str(env.get("MS_SLEEP", "0.3")).strip() or "0.3")

        if not self.base_url:
            raise RuntimeError("MS_BASE_URL missing")
        if not self.username:
            raise RuntimeError("MS_USERNAME missing")
        if not self.password:
            raise RuntimeError("MS_PASSWORD missing")

        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = "https://" + self.base_url

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
            )
        })

    def _notify_progress(self, message):
        if callable(self.progress_cb):
            try:
                self.progress_cb(str(message))
            except Exception:
                pass

    def _headers(self, referer_path="/", content_type="application/x-www-form-urlencoded"):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": f"{self.base_url}{referer_path}",
            "Origin": self.base_url,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _response_text(self, response):
        if not response.encoding:
            response.encoding = response.apparent_encoding or "utf-8"
        return response.text

    def load_index_page(self):
        r = self.session.get(
            f"{self.base_url}/index.php",
            headers=self._headers("/member/login_ok.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen index.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def load_top_page(self):
        r = self.session.get(
            f"{self.base_url}/top.php",
            headers=self._headers("/index.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen top.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def warmup_mail_page(self):
        r = self.session.get(
            f"{self.base_url}/mail/mail.php",
            headers=self._headers("/top.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen warmup mail.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def login(self):
        login_url = f"{self.base_url}/member/login.php"
        login_ok_url = f"{self.base_url}/member/login_ok.php"
        r = self.session.get(login_url, headers=self._headers("/member/logout.php", content_type=""), timeout=self.timeout, verify=self.verify_ssl)
        r.raise_for_status()
        tokens = mailscreen_extract_login_tokens(self._response_text(r))

        payload = {
            "targeturl": "",
            "ct": tokens["ct"],
            "lang": "ko",
            "saveemail": "on",
            "login_email": mailscreen_rsa_encrypt_hex(self.username, tokens["rsa_key1"], tokens["rsa_key2"]),
            "login_pwd": mailscreen_rsa_encrypt_hex(self.password, tokens["rsa_key1"], tokens["rsa_key2"]),
        }
        r = self.session.post(
            login_ok_url,
            data=payload,
            headers=self._headers("/member/login.php"),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        if "SID" not in self.session.cookies:
            raise RuntimeError("MailScreen login failed: SID cookie not issued")
        log.info("MailScreen login success: SID cookie issued")
        self._notify_progress("MailScreen 로그인 성공")

    def build_mail_payload(self, date_str, page):
        return {
            "who": "", "range": "", "sortby": "", "sortdir": "", "f_type": "",
            "app_approval_reason": "", "seqs": "", "app_etc_comment": "",
            "ref_approval_reason": "", "ref_etc_comment": "", "search_term": "free",
            "s_date": date_str, "s_hour": "0", "s_min": "0",
            "e_date": date_str, "e_hour": "23", "e_min": "59", "post_del": "0",
            "row_num_slt": str(self.row_num), "row_num": str(self.row_num), "gopage": str(page),
            "o_type": "", "prv": "", "att_act": "", "permit_id": "", "user_domain": "",
            "filter": "", "sender_ip": "", "user_name": "", "sender_email": "",
            "dept": "", "dept_code": "", "receiver_email": "", "header_subject": "",
            "virus_name": "", "oattach": "", "s_state": "",
        }

    def fetch_mail_page(self, date_str, page):
        self._notify_progress(f"MailScreen 조회중 {date_str} page={page}")
        r = self.session.post(
            f"{self.base_url}/mail/mail.php",
            data=self.build_mail_payload(date_str, page),
            headers=self._headers("/mail/mail.php"),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        text = self._response_text(r)
        log.info(
            "MailScreen mail.php status=%s final_url=%s content_type=%s body_len=%s page=%s",
            r.status_code,
            getattr(r, "url", ""),
            r.headers.get("Content-Type", ""),
            len(text),
            page,
        )
        if not mailscreen_has_main_list(text):
            debug_path = mailscreen_save_debug_html(text, date_str, page, "main_list_missing")
            preview = mailscreen_response_preview(text)
            log.error("MailScreen #main_list missing page=%s debug_html=%s preview=%s", page, debug_path, preview)
            raise RuntimeError(
                "MailScreen #main_list table not found. "
                f"Saved response HTML for diagnosis: {debug_path}. Preview: {preview}"
            )
        return text

    def collect_mail_day(self, date_str):
        first_html = self.fetch_mail_page(date_str, 1)
        rows = mailscreen_parse_rows(first_html)
        total = mailscreen_parse_total_count(first_html)
        page_count = math.ceil(total / self.row_num) if total is not None else None
        log.info(f"MailScreen page=1 rows={len(rows)} total={total}")
        self._notify_progress(f"MailScreen 1페이지 수집 {len(rows)}건")

        page = 2
        while page_count is None or page <= page_count:
            time.sleep(self.sleep_seconds)
            page_rows = mailscreen_parse_rows(self.fetch_mail_page(date_str, page))
            log.info(f"MailScreen page={page} rows={len(page_rows)}")
            self._notify_progress(f"MailScreen {page}페이지 수집 {len(page_rows)}건")
            if not page_rows:
                break
            rows.extend(page_rows)
            page += 1

        dedup = {}
        for row in rows:
            seq = str(row.get("seq", "")).strip()
            if seq and seq not in dedup:
                dedup[seq] = row
        return list(dedup.values())

    def refresh_mail_day(self, date_str):
        log.info(f"Refreshing MailScreen mail history ({date_str})")
        self.login()
        self.load_index_page()
        self.load_top_page()
        self.warmup_mail_page()
        items = self.collect_mail_day(date_str)
        payload = {
            "source": "mailscreen",
            "type": "mail_history",
            "date": date_str,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(items),
            "items": items,
        }
        file_path = os.path.join(MAILSCREEN_DAY_DIR, f"mailscreen_mail_{date_str}.json")
        save_json(file_path, payload)
        log.info(f"MailScreen saved: {len(items)} ({file_path})")
        self._notify_progress(f"MailScreen 저장 완료 {len(items)}건")
        return {"date": date_str, "count": len(items), "path": file_path}


# ======================================================
# API clients / DLP
# - Handles DLP login, paged retrieval, retry/fallback, and JSONL cache writes.
# - Later module target: modules/dlp/client.py
# ======================================================
class DlpClient:
    def __init__(self, progress_cb=None):
        env = load_dlp_env(DLP_ENV_PATH)
        self.progress_cb = progress_cb

        self.base_url = str(env.get("DLP_BASE_URL", "")).strip().rstrip("/")
        self.username = str(env.get("DLP_USERNAME", "")).strip()
        self.password = str(env.get("DLP_PASSWORD", "")).strip()

        verify_ssl_raw = str(env.get("DLP_VERIFY_SSL", "false")).strip().lower()
        self.verify_ssl = verify_ssl_raw == "true"

        timeout_raw = str(env.get("DLP_TIMEOUT", "30")).strip()
        try:
            self.timeout = int(timeout_raw)
        except Exception:
            self.timeout = 30

        if not self.base_url:
            raise RuntimeError("DLP_BASE_URL missing")
        if not self.username:
            raise RuntimeError("DLP_USERNAME missing")
        if not self.password:
            raise RuntimeError("DLP_PASSWORD missing")

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            )
        })


    def _notify_progress(self, message: str):
        if callable(self.progress_cb):
            try:
                self.progress_cb(str(message))
            except Exception:
                pass

    @property
    def base_home_url(self):
        return f"{self.base_url}/"

    @property
    def login_url(self):
        return f"{self.base_url}/index.php/login"

    @property
    def cf_log_list_url(self):
        return f"{self.base_url}/index.php/cf_log/list"

    def fetch_login_page(self):
        r = self.session.get(
            self.base_home_url,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        return r.text

    def extract_csrf_token(self, html: str):
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": "csrf_token_anon"})

        if not token_input:
            raise RuntimeError("csrf_token_anon input not found")

        token = str(token_input.get("value", "")).strip()
        if not token:
            raise RuntimeError("csrf_token_anon value is empty")

        return token

    def is_logged_in(self, html: str):
        success_keywords = [
            "로그아웃",
            "환영합니다!",
            "Endpoint Protector",
            "보고 및 분석",
            "/index.php/logout",
        ]
        return any(keyword in html for keyword in success_keywords)

    def login(self):
        html = self.fetch_login_page()
        csrf_token = self.extract_csrf_token(html)

        payload = {
            "csrf_token_anon": csrf_token,
            "username": self.username,
            "password": self.password,
            "useGoogleAuth": "0",
            "code": "",
        }

        headers = {
            "Referer": self.base_home_url,
            "Origin": self.base_url,
        }

        files_payload = {k: (None, str(v)) for k, v in payload.items()}

        r = self.session.post(
            self.login_url,
            files=files_payload,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=True,
        )
        r.raise_for_status()

        has_ratool_cookie = any(c.name == "ratool" for c in self.session.cookies)
        final_url = str(getattr(r, "url", "") or "")
        redirected_to_index = "/index.php/" in final_url
        log.info(
            f"DLP login post status={r.status_code} final_url={final_url} "
            f"redirected_to_index={redirected_to_index} ratool_cookie={has_ratool_cookie}"
        )

        if not self.is_logged_in(r.text) and not (redirected_to_index and has_ratool_cookie):
            raise RuntimeError("DLP login failed. Check credentials or login flow.")

    def build_cf_log_payload(self, date_str: str, draw: int = 1, start: int = 0, length: int = -1, start_dt: str = None, end_dt: str = None):
        start_dt = start_dt or f"{date_str} 00:00:00"
        end_dt = end_dt or f"{date_str} 23:30:00"

        columns = [
            ("id", False),
            ("event_id", True),
            ("eventtimelocal", True),
            ("eventtime", True),
            ("timestamp", True),
            ("machine_name", True),
            ("ip", True),
            ("client_name", True),
            ("content_policy", True),
            ("content_policy_type", True),
            ("filename", True),
            ("destination", True),
            ("destination_type", True),
            ("destinationDetails", True),
            ("emailSender", True),
            ("emailSubject", True),
            ("item_type", True),
            ("matched_item", True),
            ("item_details", True),
            ("filesize", True),
            ("filehash", True),
            ("os_value", True),
            ("epp_client_version", True),
            ("vid", True),
            ("pid", True),
            ("serialno", True),
            ("justification_id", True),
            ("justification", True),
            ("justification_export", True),
            ("shadow_id", True),
            ("cap_event_id", True),
            ("startDate", True),
            ("endDate", True),
            ("startServerDate", True),
            ("endServerDate", True),
            ("use_old_logs", True),
            ("real_filesize", True),
            ("repositoryType", True),
            ("startClientUtcDate", True),
            ("endClientUtcDate", True),
            ("loclogid", False),
            ("department_id", False),
            ("machine_id", False),
            ("log_id", False),
            ("is_deleted", False),
            ("shadowExists", True),
        ]

        payload = {
            "draw": str(draw),
            "order[0][column]": "4",
            "order[0][dir]": "desc",
            "start": str(start),
            "length": str(length),
            "search[value]": "",
            "search[regex]": "false",
        }

        for idx, (col_name, orderable) in enumerate(columns):
            payload[f"columns[{idx}][data]"] = col_name
            payload[f"columns[{idx}][name]"] = ""
            payload[f"columns[{idx}][searchable]"] = "true"
            payload[f"columns[{idx}][orderable]"] = "true" if orderable else "false"
            payload[f"columns[{idx}][search][value]"] = ""
            payload[f"columns[{idx}][search][regex]"] = "false"

        # 요청 맞춤: 날짜 필터는 columns[30]/[31] 검색값으로 전달
        payload["columns[30][search][value]"] = start_dt
        payload["columns[31][search][value]"] = end_dt

        return payload

    def _looks_like_login_html(self, text: str):
        txt = str(text or "")
        hints = ["로그아웃", "환영합니다!", "/index.php/logout", "Endpoint Protector"]
        return any(h in txt for h in hints)

    def _fetch_cf_logs(self, payload, timeout=None):
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/index.php/",
            "Origin": self.base_url,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

        r = self.session.post(
            self.cf_log_list_url,
            data=payload,
            headers=headers,
            timeout=timeout if timeout is not None else self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        content_type = str(r.headers.get("Content-Type", "") or "")
        body_preview = r.text[:600]
        log.info(
            f"DLP cf_log/list status={r.status_code} url={r.url} content_type={content_type} "
            f"body_len={len(r.text)}"
        )

        if self._looks_like_login_html(r.text):
            raise RuntimeError("DLP cf_log/list returned login/main HTML instead of JSON")

        try:
            result = r.json()
        except Exception as e:
            raise RuntimeError(f"Failed to parse DLP response as JSON: {body_preview}") from e

        if "data" not in result:
            keys = list(result.keys()) if isinstance(result, dict) else []
            raise RuntimeError(f"Unexpected DLP response keys={keys} preview={body_preview}")

        rows = result.get("data", [])
        if not isinstance(rows, list):
            rows = []

        records_total = result.get("recordsTotal", len(rows))
        records_filtered = result.get("recordsFiltered", len(rows))
        try:
            records_total = int(records_total)
        except Exception:
            records_total = len(rows)
        try:
            records_filtered = int(records_filtered)
        except Exception:
            records_filtered = len(rows)

        log.info(
            f"DLP cf_log/list parsed recordsTotal={records_total} recordsFiltered={records_filtered} rows={len(rows)}"
        )

        return {
            "rows": rows,
            "records_filtered": max(records_filtered, 0),
            "raw": result,
        }

    def fetch_daily_logs_window(self, date_str: str, start_dt: str, end_dt: str, length: int = -1, draw: int = 1, start: int = 0, timeout=None):
        payload = self.build_cf_log_payload(
            date_str=date_str,
            draw=draw,
            start=start,
            length=length,
            start_dt=start_dt,
            end_dt=end_dt,
        )
        return self._fetch_cf_logs(payload, timeout=timeout)

    def _merge_rows_unique(self, rows):
        dedup = {}
        order = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = (
                row.get("log_id")
                or row.get("id")
                or row.get("loclogid")
                or "|".join([
                    str(row.get("timestamp", "")),
                    str(row.get("event_id", "")),
                    str(row.get("machine_name", "")),
                    str(row.get("filename", "")),
                ])
            )
            if key in dedup:
                continue
            dedup[key] = row
            order.append(key)
        return [dedup[k] for k in order]

    def fetch_daily_logs(self, date_str: str):
        try:
            first_try = self.fetch_daily_logs_window(
                date_str=date_str,
                start_dt=f"{date_str} 00:00:00",
                end_dt=f"{date_str} 23:30:00",
                length=-1,
                draw=1,
            )
            first_rows = first_try.get("rows", [])
            first_filtered = int(first_try.get("records_filtered", len(first_rows)) or 0)
            if first_filtered > 0 and len(first_rows) == 0:
                log.warning(
                    f"DLP full-day fetch returned 0 rows but recordsFiltered={first_filtered}. "
                    "Retry with paged fetch (start/length)."
                )
            else:
                return first_rows
        except requests.exceptions.Timeout:
            log.warning(f"DLP full-day fetch timed out ({date_str}). Retry with paged fetch (start/length).")
        except requests.exceptions.RequestException as e:
            if "timed out" not in str(e).lower():
                raise
            log.warning(f"DLP full-day fetch timed out ({date_str}). Retry with paged fetch (start/length).")

        start_dt = f"{date_str} 00:00:00"
        end_dt = f"{date_str} 23:30:00"
        page_size = 500
        fallback_timeout = max(self.timeout, 60)
        retry_count = 2

        self._notify_progress("DLP 2차 조회 시작 (페이징 500건 단위)")

        def fetch_page_with_retry(page_start, draw):
            last_exc = None
            for attempt in range(1, retry_count + 1):
                try:
                    return self.fetch_daily_logs_window(
                        date_str=date_str,
                        start_dt=start_dt,
                        end_dt=end_dt,
                        start=page_start,
                        length=page_size,
                        draw=draw,
                        timeout=fallback_timeout,
                    )
                except requests.exceptions.Timeout as e:
                    last_exc = e
                    log.warning(f"DLP fallback page timeout start={page_start} attempt={attempt}/{retry_count}")
            if last_exc:
                raise last_exc

        first_page = fetch_page_with_retry(0, 1)

        total_count = first_page.get("records_filtered", 0)
        all_rows = list(first_page.get("rows", []))

        if total_count <= len(all_rows):
            merged = self._merge_rows_unique(all_rows)
            log.info(f"DLP fallback paged fetch completed ({date_str}) total={total_count} raw={len(all_rows)} unique={len(merged)}")
            return merged

        page_count = (total_count + page_size - 1) // page_size
        for page_index in range(1, page_count):
            page_start = page_index * page_size
            self._notify_progress(f"DLP 2차 조회 진행중 {page_index + 1}/{page_count} (start={page_start})")
            page = fetch_page_with_retry(page_start, page_index + 1)
            page_rows = page.get("rows", [])
            if not page_rows:
                break
            all_rows.extend(page_rows)

        merged = self._merge_rows_unique(all_rows)
        log.info(f"DLP fallback paged fetch completed ({date_str}) total={total_count} raw={len(all_rows)} unique={len(merged)}")
        self._notify_progress(f"DLP 2차 조회 완료 total={total_count} raw={len(all_rows)} unique={len(merged)}")
        return merged

    def refresh_dlp_day(self, date_str: str):
        log.info(f"Refreshing DLP ({date_str})")

        self.login()
        rows = self.fetch_daily_logs(date_str)

        file_path = os.path.join(DLP_DAY_DIR, f"{date_str}.jsonl")
        save_jsonl(file_path, rows)

        log.info(f"DLP saved: {len(rows)} ({file_path})")
        return {
            "date": date_str,
            "count": len(rows),
            "path": file_path,
        }


# ======================================================
# API clients / Sophos Firewall
# - Handles firewall XML API group lookup and response actions.
# - Later module target: modules/firewall/client.py
# ======================================================
class SophosFirewallClient:
    def __init__(self, firewall_config: dict = None):
        if firewall_config is None:
            load_env_from_file(FIREWALL_ENV_PATH)

            firewall_config = {
                "name": "Cloud",
                "host": os.getenv("FW_HOST", "").strip(),
                "port": os.getenv("FW_PORT", "").strip(),
                "username": os.getenv("FW_USERNAME", "").strip(),
                "password": os.getenv("FW_PASSWORD", "").strip(),
                "verify_ssl": os.getenv("FW_VERIFY_SSL", "false").strip().lower() == "true",
                "iphost_description": os.getenv("FW_IPHOST_DESCRIPTION", "").strip(),
                "iphost_group": os.getenv("FW_IPHOST_GROUP", "").strip(),
                "fqdnhost_group": os.getenv("FW_FQDNHOST_GROUP", "").strip(),
            }

        self.firewall_name = str(firewall_config.get("name", "Unknown")).strip() or "Unknown"
        self.host = str(firewall_config.get("host", "")).strip()
        self.port = str(firewall_config.get("port", "")).strip()
        self.username = str(firewall_config.get("username", "")).strip()
        self.password = str(firewall_config.get("password", "")).strip()
        self.verify_ssl = bool(firewall_config.get("verify_ssl", False))

        self.iphost_description = str(firewall_config.get("iphost_description", "")).strip()
        self.iphost_group = str(firewall_config.get("iphost_group", "")).strip()
        self.fqdnhost_group = str(firewall_config.get("fqdnhost_group", "")).strip()

        if not self.host:
            raise RuntimeError(f"{self.firewall_name}: FW_HOST missing")
        if not self.username:
            raise RuntimeError(f"{self.firewall_name}: FW_USERNAME missing")
        if not self.password:
            raise RuntimeError(f"{self.firewall_name}: FW_PASSWORD missing")

        self.url = f"https://{self.host}:{self.port}/webconsole/APIController"

    def _post_xml(self, reqxml: str) -> str:
        r = requests.post(
            self.url,
            files={"reqxml": (None, reqxml)},
            verify=self.verify_ssl,
            timeout=60,
        )
        r.raise_for_status()
        return r.text

    def build_ip_host_name(self, ip_address: str) -> str:
        return f"AIDR_{ip_address}"

    def build_ip_host_xml(self, ip_address: str) -> str:
        object_name = self._xml_value(self.build_ip_host_name(ip_address))
        ip_value = self._xml_value(ip_address)

        group_xml = ""
        if self.iphost_group:
            group_xml = f"""
      <HostGroupList>
        <HostGroup>{self._xml_value(self.iphost_group)}</HostGroup>
      </HostGroupList>"""

        description_xml = f"<Description>{self._xml_value(self.iphost_description)}</Description>" if self.iphost_description else ""

        reqxml = f"""
<Request>
  <Login>
    <Username>{self._xml_value(self.username)}</Username>
    <Password>{self._xml_value(self.password)}</Password>
  </Login>
  <Set operation="add">
    <IPHost>
      <Name>{object_name}</Name>
      <IPFamily>IPv4</IPFamily>
      {description_xml}
      <HostType>IP</HostType>
      <IPAddress>{ip_value}</IPAddress>{group_xml}
    </IPHost>
  </Set>
</Request>
""".strip()

        return reqxml

    def create_ip_host(self, ip_address: str) -> str:
        reqxml = self.build_ip_host_xml(ip_address)
        return self._post_xml(reqxml)

    def create_ip_host_bulk(self, ip_list: list) -> list:
        results = []

        for ip_address in ip_list:
            try:
                response_text = self.create_ip_host(ip_address)
                results.append({
                    "firewall": self.firewall_name,
                    "target": ip_address,
                    "ip": ip_address,
                    "name": self.build_ip_host_name(ip_address),
                    "success": True,
                    "response": response_text,
                    "error": "",
                })
            except Exception as e:
                results.append({
                    "firewall": self.firewall_name,
                    "target": ip_address,
                    "ip": ip_address,
                    "name": self.build_ip_host_name(ip_address),
                    "success": False,
                    "response": "",
                    "error": f"{type(e).__name__}: {e}",
                })

        return results

    def build_fqdn_host_name(self, domain: str) -> str:
        return f"AIDR_{domain}"

    def build_fqdn_host_xml(self, domain: str) -> str:
        object_name = self._xml_value(self.build_fqdn_host_name(domain))
        domain_value = self._xml_value(domain)

        desc_xml = ""
        if self.iphost_description:
            desc_xml = f"<Description>{self._xml_value(self.iphost_description)}</Description>"

        group_xml = ""
        if self.fqdnhost_group:
            group_xml = f"""
          <FQDNHostGroupList>
            <FQDNHostGroup>{self._xml_value(self.fqdnhost_group)}</FQDNHostGroup>
          </FQDNHostGroupList>"""

        reqxml = f"""
<Request>
  <Login>
    <Username>{self._xml_value(self.username)}</Username>
    <Password>{self._xml_value(self.password)}</Password>
  </Login>
  <Set operation="add">
    <FQDNHost>
      <Name>{object_name}</Name>
      {desc_xml}
      <FQDN>{domain_value}</FQDN>{group_xml}
    </FQDNHost>
  </Set>
</Request>
""".strip()

        return reqxml

    def create_fqdn_host(self, domain: str) -> str:
        reqxml = self.build_fqdn_host_xml(domain)
        return self._post_xml(reqxml)

    def create_fqdn_host_bulk(self, domain_list: list) -> list:
        results = []

        for domain in domain_list:
            try:
                response_text = self.create_fqdn_host(domain)
                results.append({
                    "firewall": self.firewall_name,
                    "target": domain,
                    "name": self.build_fqdn_host_name(domain),
                    "success": True,
                    "response": response_text,
                    "error": "",
                })
            except Exception as e:
                results.append({
                    "firewall": self.firewall_name,
                    "target": domain,
                    "name": self.build_fqdn_host_name(domain),
                    "success": False,
                    "response": "",
                    "error": f"{type(e).__name__}: {e}",
                })

        return results

    def _xml_value(self, value: str) -> str:
        value = str(value or "")
        return (
            value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    def build_ip_host_group_get_xml(self) -> str:
        group_name = self._xml_value(self.iphost_group)

        reqxml = f"""
<Request>
  <Login>
    <Username>{self._xml_value(self.username)}</Username>
    <Password>{self._xml_value(self.password)}</Password>
  </Login>
  <Get>
    <IPHostGroup>
      <Filter>
        <key name="Name" criteria="=">{group_name}</key>
      </Filter>
    </IPHostGroup>
  </Get>
</Request>
""".strip()

        return reqxml

    def build_fqdn_host_group_get_xml(self) -> str:
        group_name = self._xml_value(self.fqdnhost_group)

        reqxml = f"""
<Request>
  <Login>
    <Username>{self._xml_value(self.username)}</Username>
    <Password>{self._xml_value(self.password)}</Password>
  </Login>
  <Get>
    <FQDNHostGroup>
      <Filter>
        <key name="Name" criteria="=">{group_name}</key>
      </Filter>
    </FQDNHostGroup>
  </Get>
</Request>
""".strip()

        return reqxml

    def get_ip_host_group_raw(self) -> str:
        if not self.iphost_group:
            raise RuntimeError(f"{self.firewall_name}: FW_IPHOST_GROUP 값이 없습니다.")

        reqxml = self.build_ip_host_group_get_xml()
        return self._post_xml(reqxml)

    def get_fqdn_host_group_raw(self) -> str:
        if not self.fqdnhost_group:
            raise RuntimeError(f"{self.firewall_name}: FW_FQDNHOST_GROUP 값이 없습니다.")

        reqxml = self.build_fqdn_host_group_get_xml()
        return self._post_xml(reqxml)

# ======================================================
# API clients / Sophos Central
# - Refreshes detections, emails, endpoints, organization groups, and directory users into JSON cache.
# - Later module target: modules/sophos/client.py
# ======================================================
class SophosClient:
    def __init__(self):
        load_env_from_file(ENV_PATH)

        self.client_id = os.getenv("SOPHOS_CLIENT_ID", "").strip()
        self.client_secret = os.getenv("SOPHOS_CLIENT_SECRET", "").strip()
        self.token_url = os.getenv("SOPHOS_TOKEN_URL", "https://id.sophos.com/api/v2/oauth2/token").strip()
        self.whoami_url = os.getenv("SOPHOS_WHOAMI_URL", "https://api.central.sophos.com/whoami/v1").strip()

        self.token = None
        self.tenant_id = None
        self.base_url = None

        if not self.client_id or not self.client_secret:
            raise RuntimeError("SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET missing")

        self._auth()

    def _auth(self):
        log.info("Requesting access token")
        r = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "token",
            },
            timeout=45,
        )
        r.raise_for_status()
        self.token = r.json().get("access_token")
        if not self.token:
            raise RuntimeError("access_token missing")

        log.info("Calling WHOAMI")
        r = requests.get(
            self.whoami_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=45,
        )
        r.raise_for_status()
        d = r.json()

        self.tenant_id = d.get("id")
        host = None
        api_hosts = d.get("apiHosts") if isinstance(d.get("apiHosts"), dict) else {}
        host = api_hosts.get("dataRegion") or d.get("apiHost")

        if not self.tenant_id or not host:
            raise RuntimeError("WHOAMI missing tenant_id or host")

        host = str(host).strip()
        if host.startswith("http://") or host.startswith("https://"):
            self.base_url = host
        else:
            self.base_url = f"https://{host}"

        log.info(f"Tenant ID: {self.tenant_id}")
        log.info(f"Base URL: {self.base_url}")

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "X-Tenant-ID": self.tenant_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def refresh_detections_range(self, from_ts: str, to_ts: str):
        query_url = f"{self.base_url}/detections/v1/queries/detections"

        log.info("Refreshing detections by custom range")
        log.info(f"FROM: {from_ts}")
        log.info(f"TO  : {to_ts}")

        q = requests.post(
            query_url,
            headers=self._headers(),
            json={
                "from": from_ts,
                "to": to_ts,
                "sort": [{"field": "time", "direction": "desc"}],
            },
            timeout=60,
        )

        q.raise_for_status()
        qid = q.json().get("id")

        if not qid:
            raise RuntimeError("detections query id missing")

        log.info(f"Query ID: {qid}")

        results = []
        page = 1
        total_pages = None

        while True:
            log.info(f"Requesting page {page}...")

            r = requests.get(
                f"{query_url}/{qid}/results",
                headers=self._headers(),
                params={
                    "page": page,
                    "pageSize": 200,
                },
                timeout=60,
            )

            if r.status_code in (202, 400):
                log.info("Query not ready... waiting 5 sec")
                time.sleep(5)
                continue

            if r.status_code == 429:
                log.warning("Rate limit hit (429)... waiting 10 seconds")
                time.sleep(10)
                continue

            r.raise_for_status()
            data = r.json()

            pages = data.get("pages", {})
            if total_pages is None:
                total_pages = pages.get("total", 1)
                log.info(f"[TOTAL PAGES] {total_pages}")
                log.info(f"[TOTAL ITEMS] {pages.get('items')}")

            items = data.get("items", [])
            results.extend(items)

            log.info(f"[PAGE {page}] fetched={len(items)} total_so_far={len(results)}")

            if page >= total_pages:
                log.info("Reached last page.")
                break

            page += 1

        log.info(f"[FINAL API COUNT] total_results={len(results)}")

        bucket = defaultdict(list)
        for item in results:
            if not isinstance(item, dict):
                continue

            dk = day_key_from_iso(item.get("time"))
            if not dk:
                dk = "unknown"

            bucket[dk].append(item)

        saved_days = 0
        for dk, items in bucket.items():
            if dk == "unknown":
                continue

            save_day_json(DETECTIONS_DAY_DIR, dk, items)
            saved_days += 1

        log.info(f"Detections saved: {len(results)} (days: {saved_days})")

    def refresh_emails_range(self, from_ts: str, to_ts: str):
        url = f"{self.base_url}/email/v1/quarantine/messages/search"

        log.info("Refreshing emails by custom range")
        log.info(f"FROM: {from_ts}")
        log.info(f"TO  : {to_ts}")

        data = []
        body = {
            "beginDate": from_ts,
            "endDate": to_ts,
            "pageSize": 100
        }

        page = 1

        while True:
            log.info(f"Requesting email page {page}...")

            r = requests.post(
                url,
                headers=self._headers(),
                json=body,
                timeout=60
            )

            r.raise_for_status()
            j = r.json()

            items = j.get("items", [])
            if not items:
                log.info("No more email items.")
                break

            data.extend(items)

            log.info(f"Page {page} loaded. Total so far: {len(data)}")

            nk = (j.get("pages") or {}).get("nextKey")
            if not nk:
                log.info("No nextKey. End of pages.")
                break

            body["pageFromKey"] = nk
            page += 1
            time.sleep(0.3)

        bucket = defaultdict(list)
        for item in data:
            if not isinstance(item, dict):
                continue

            dk = day_key_from_iso(item.get("receivedAt"))
            if not dk:
                dk = "unknown"

            bucket[dk].append(item)

        saved_days = 0
        for dk, items in bucket.items():
            if dk == "unknown":
                continue
            save_day_json(EMAILS_DAY_DIR, dk, items)
            saved_days += 1

        log.info(f"Emails saved: {len(data)} (days: {saved_days})")

    def refresh_endpoints(self):
        url = f"{self.base_url}/endpoint/v1/endpoints"

        log.info("Refreshing endpoints")
        data = []
        params = {"pageSize": 100, "pageTotal": "true"}

        while True:
            r = requests.get(url, headers=self._headers(), params=params, timeout=45)
            r.raise_for_status()
            j = r.json()
            data.extend(j.get("items", []))
            nk = (j.get("pages") or {}).get("nextKey")
            if not nk:
                break
            params["pageFromKey"] = nk
            time.sleep(0.2)

        save_json(os.path.join(CACHE_DIR, "endpoints.json"), data)
        log.info(f"Endpoints saved: {len(data)}")

    def refresh_orgs(self):
        url = f"{self.base_url}/common/v1/directory/user-groups"

        log.info("Refreshing orgs")
        groups_out = []
        page = 1

        while True:
            r = requests.get(
                url,
                headers=self._headers(),
                params={"pageSize": 100, "pageTotal": "true", "page": page},
                timeout=45,
            )
            r.raise_for_status()
            j = r.json()
            items = j.get("items", [])
            if not items:
                break

            # UI friendly cache shape:
            # {deptCode, deptName, users:[{name:...}, ...]}
            for g in items:
                if not isinstance(g, dict):
                    continue
                dept_code = g.get("displayName") or g.get("name") or "None"
                dept_code = str(dept_code)
                dept_name = DEPT_MAP.get(dept_code, dept_code)

                users_obj = g.get("users", {})
                users = []
                if isinstance(users_obj, dict):
                    uitems = users_obj.get("items", [])
                    if isinstance(uitems, list):
                        for u in uitems:
                            if isinstance(u, dict):
                                user_entry = dict(u)
                                user_entry["name"] = u.get("name", "None")
                                users.append(user_entry)
                            else:
                                users.append({"name": str(u)})
                elif isinstance(users_obj, list):
                    for u in users_obj:
                        if isinstance(u, dict):
                            user_entry = dict(u)
                            user_entry["name"] = u.get("name", "None")
                            users.append(user_entry)
                        else:
                            users.append({"name": str(u)})

                groups_out.append({
                    "deptCode": dept_code,
                    "deptName": dept_name,
                    "users": users,
                })

            pages_info = j.get("pages") if isinstance(j.get("pages"), dict) else {}
            total = pages_info.get("total")
            if isinstance(total, int) and page >= total:
                break

            page += 1
            time.sleep(0.2)

        save_json(os.path.join(CACHE_DIR, "user_groups.json"), groups_out)
        log.info(f"Orgs saved: {len(groups_out)}")

    def refresh_users(self):
        url = f"{self.base_url}/common/v1/directory/users"

        log.info("Refreshing users")
        users = []
        page = 1

        while True:
            r = requests.get(
                url,
                headers=self._headers(),
                params={"pageSize": 100, "pageTotal": "true", "page": page},
                timeout=45,
            )
            r.raise_for_status()
            j = r.json()
            items = j.get("items", [])
            if not items:
                break

            users.extend([u for u in items if isinstance(u, dict)])

            pages_info = j.get("pages") if isinstance(j.get("pages"), dict) else {}
            total = pages_info.get("total")
            if isinstance(total, int) and page >= total:
                break

            page += 1
            time.sleep(0.2)

        save_json(os.path.join(CACHE_DIR, "users.json"), users)
        log.info(f"Users saved: {len(users)}")


# ======================================================
# Background worker (non-blocking UI)
# ======================================================
class RefreshWorker(QThread):
    ok = pyqtSignal(str)
    fail = pyqtSignal(str, str)
    progress = pyqtSignal(str, str)

    def __init__(self, job_name: str, date_str: str = "", parent=None):
        super().__init__(parent)
        self.job_name = job_name
        self.date_str = str(date_str or "").strip()

    def run(self):
        try:
            log.info("=== UI JOB START === %s", self.job_name)

            if self.job_name == "DLP":
                log.info("STEP 1: DlpClient init")
                api = DlpClient(progress_cb=lambda msg: self.progress.emit("DLP", msg))

                log.info("STEP 2: Before DLP refresh call")

                if not self.date_str:
                    raise RuntimeError("DLP date_str missing")

                api.refresh_dlp_day(self.date_str)

            elif self.job_name == "MailScreen":
                log.info("STEP 1: MailScreenClient init")
                api = MailScreenClient(progress_cb=lambda msg: self.progress.emit("MailScreen", msg))

                if not self.date_str:
                    raise RuntimeError("MailScreen date_str missing")

                api.refresh_mail_day(self.date_str)

            else:
                log.info("STEP 1: SophosClient init")
                api = SophosClient()

                log.info("STEP 2: Before refresh call")

                if self.job_name == "Detection":
                    if not self.date_str:
                        raise RuntimeError("Detection date_str missing")

                    start, end = self.date_str.split("|")
                    from_ts, to_ts = kst_date_range_to_utc_iso(start, end)

                    api.refresh_detections_range(from_ts, to_ts)

                elif self.job_name == "Email":
                    if not self.date_str:
                        raise RuntimeError("Email date_str missing")

                    start, end = self.date_str.split("|")
                    from_ts, to_ts = kst_date_range_to_utc_iso(start, end)

                    api.refresh_emails_range(from_ts, to_ts)

                elif self.job_name == "Endpoint":
                    api.refresh_endpoints()

                elif self.job_name == "Organization":
                    api.refresh_orgs()

                elif self.job_name == "User":
                    api.refresh_users()

                else:
                    raise RuntimeError(f"Unknown job: {self.job_name}")

            log.info("=== UI JOB END (SUCCESS) === %s", self.job_name)
            log.info("STEP 3: After refresh call")

            self.ok.emit(self.job_name)

            log.info("STEP 4: ok.emit done")

        except Exception as e:
            log.exception("=== UI JOB END (FAIL) === %s", self.job_name)
            self.fail.emit(self.job_name, f"{type(e).__name__}: {e}")

class LiveDiscoverWorker(QThread):
    ok = pyqtSignal(list)
    fail = pyqtSignal(str)

    def __init__(self, endpoint_name: str, program_name: str, query_type: str = "Process", parent=None):
        super().__init__(parent)
        self.endpoint_name = endpoint_name
        self.program_name = program_name
        self.query_type = query_type

    def run(self):
        try:
            log.info("[LIVE DISCOVER] worker start")
            log.info(f"[LIVE DISCOVER] endpoint_name={self.endpoint_name}")
            log.info(f"[LIVE DISCOVER] program_name={self.program_name}")
            log.info(f"[LIVE DISCOVER] query_type={self.query_type}")

            client = SophosLiveDiscoverClient()

            keyword = self.program_name.strip().lower()

            def sql_literal(value):
                return str(value or "").replace("'", "''")

            keyword_sql = sql_literal(keyword)

            if self.query_type == "Process":
                if keyword:
                    sql = f"""
                    SELECT name, path, pid
                    FROM processes
                    WHERE lower(name) LIKE '%{keyword_sql}%'
                    LIMIT 200
                    """
                else:
                    sql = """
                    SELECT name, path, pid
                    FROM processes
                    LIMIT 200
                    """

            elif self.query_type == "Service":
                if keyword:
                    sql = f"""
                    SELECT name, display_name, status, start_type
                    FROM services
                    WHERE
                        lower(name) LIKE '%{keyword_sql}%'
                        OR lower(display_name) LIKE '%{keyword_sql}%'
                    LIMIT 200
                    """
                else:
                    sql = """
                    SELECT name, display_name, status, start_type
                    FROM services
                    LIMIT 200
                    """

            elif self.query_type == "Scheduled Task":
                if keyword:
                    sql = f"""
                    SELECT name, path, enabled, state
                    FROM scheduled_tasks
                    WHERE
                        lower(name) LIKE '%{keyword_sql}%'
                        OR lower(path) LIKE '%{keyword_sql}%'
                    LIMIT 200
                    """
                else:
                    sql = """
                    SELECT name, path, enabled, state
                    FROM scheduled_tasks
                    LIMIT 200
                    """

            elif self.query_type == "Installed Program":
                if keyword:
                    sql = f"""
                    SELECT name, version, install_location
                    FROM programs
                    WHERE lower(name) LIKE '%{keyword_sql}%'
                    LIMIT 200
                    """
                else:
                    sql = """
                    SELECT name, version, install_location
                    FROM programs
                    LIMIT 200
                    """

            elif self.query_type == "Network Connection":
                if keyword:
                    sql = f"""
                    SELECT pid, local_address, local_port, remote_address, remote_port, state
                    FROM process_open_sockets
                    WHERE
                        lower(local_address) LIKE '%{keyword_sql}%'
                        OR lower(remote_address) LIKE '%{keyword_sql}%'
                        OR cast(local_port as varchar) LIKE '%{keyword_sql}%'
                        OR cast(remote_port as varchar) LIKE '%{keyword_sql}%'
                    LIMIT 200
                    """
                else:
                    sql = """
                    SELECT pid, local_address, local_port, remote_address, remote_port, state
                    FROM process_open_sockets
                    LIMIT 200
                    """

            elif self.query_type == "File Search":
                raw_input = self.program_name.strip()

                if not raw_input:
                    raise RuntimeError("File Search 는 입력값이 필요합니다. 폴더 경로, 파일명, 또는 전체 경로를 입력하세요.")

                # 1) 폴더 경로 입력 → 하위 파일 목록
                if raw_input.endswith("\\") or raw_input.endswith("/"):
                    normalized_dir = sql_literal(raw_input.rstrip("\\/").replace("\\", "\\\\"))
                    sql = f"""
                    SELECT path, filename, size, datetime(mtime, 'unixepoch') as mtime
                    FROM file
                    WHERE directory = '{normalized_dir}'
                    LIMIT 200
                    """

                # 2) 전체 경로 입력 → 해당 파일 확인
                elif "\\" in raw_input or "/" in raw_input:
                    normalized_path = sql_literal(raw_input.replace("\\", "\\\\"))
                    sql = f"""
                    SELECT path, filename, size, datetime(mtime, 'unixepoch') as mtime
                    FROM file
                    WHERE path = '{normalized_path}'
                    LIMIT 200
                    """

                # 3) 파일명 입력 → 파일명으로 경로 찾기
                else:
                    sql = f"""
                    SELECT path, filename, size, datetime(mtime, 'unixepoch') as mtime
                    FROM file
                    WHERE lower(filename) LIKE '%{sql_literal(keyword)}%'
                    LIMIT 200
                    """

            else:
                sql = """
                SELECT name, path, pid
                FROM processes
                LIMIT 200
                """

            run_data = client.run_ad_hoc_query(self.endpoint_name, sql)

            run_id = (
                run_data.get("id")
                or run_data.get("runId")
                or run_data.get("queryRunId")
            )

            if not run_id:
                raise RuntimeError(f"run_id not found: {run_data}")

            log.info(f"[LIVE DISCOVER] run_id={run_id}")

            max_wait = 60
            interval = 3
            waited = 0

            while waited < max_wait:
                status_data = client.get_run(run_id)
                log.info(f"[LIVE DISCOVER] status_data={status_data}")

                status = str(
                    status_data.get("status")
                    or status_data.get("state")
                    or ""
                ).lower()

                if status in ("finished", "completed", "done", "success", "succeeded"):
                    break

                if status in ("failed", "error", "cancelled", "canceled", "timeout"):
                    raise RuntimeError(f"query failed: {status_data}")

                time.sleep(interval)
                waited += interval
            else:
                raise RuntimeError("live discover polling timeout")

            result_data = client.get_results(run_id)
            log.info(f"[LIVE DISCOVER] result_data={result_data}")

            rows = []

            items = result_data.get("items", [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        rows.append(item)

            log.info(f"[LIVE DISCOVER] extracted_rows_count={len(rows)}")
            log.info(f"[LIVE DISCOVER] extracted_rows_sample={json.dumps(rows[:3], ensure_ascii=False)}")

            filtered = []

            for row in rows:
                if not isinstance(row, dict):
                    continue

                if self.query_type == "Process":
                    filtered.append({
                        "name": str(row.get("name", "")),
                        "path": str(row.get("path", "")),
                        "pid": str(row.get("pid", "")),
                        "_raw": row
                    })

                elif self.query_type == "Service":
                    filtered.append({
                        "name": str(row.get("name", "")),
                        "display_name": str(row.get("display_name", "")),
                        "status": str(row.get("status", "")),
                        "start_type": str(row.get("start_type", "")),
                        "_raw": row
                    })

                elif self.query_type == "Scheduled Task":
                    filtered.append({
                        "name": str(row.get("name", "")),
                        "path": str(row.get("path", "")),
                        "enabled": str(row.get("enabled", "")),
                        "state": str(row.get("state", "")),
                        "_raw": row
                    })

                elif self.query_type == "Installed Program":
                    filtered.append({
                        "name": str(row.get("name", "")),
                        "version": str(row.get("version", "")),
                        "install_location": str(row.get("install_location", "")),
                        "_raw": row
                    })

                elif self.query_type == "Network Connection":
                    filtered.append({
                        "pid": str(row.get("pid", "")),
                        "local_address": str(row.get("local_address", "")),
                        "local_port": str(row.get("local_port", "")),
                        "remote_address": str(row.get("remote_address", "")),
                        "remote_port": str(row.get("remote_port", "")),
                        "state": str(row.get("state", "")),
                        "_raw": row
                    })

                elif self.query_type == "File Search":
                    filtered.append({
                        "path": str(row.get("path", "")),
                        "filename": str(row.get("filename", "")),
                        "size": bytes_to_mb_text(row.get("size", "")),
                        "mtime": str(row.get("mtime", "")),
                        "_raw": row
                    })

                else:
                    filtered.append({
                        "name": str(row.get("name", "")),
                        "path": str(row.get("path", "")),
                        "pid": str(row.get("pid", "")),
                        "_raw": row
                    })

            log.info(f"[LIVE DISCOVER] filtered_count={len(filtered)}")
            log.info(f"[LIVE DISCOVER] filtered_sample={json.dumps(filtered[:3], ensure_ascii=False)}")
            self.ok.emit(filtered)

        except Exception as e:
            log.exception("[LIVE DISCOVER] worker fail")
            self.fail.emit(f"{type(e).__name__}: {e}")

class XdrQueryWorker(QThread):
    ok = pyqtSignal(list)
    fail = pyqtSignal(str)

    def __init__(self, query_name: str, endpoint_id: str = "", variable_value: str = "", from_iso: str = "", to_iso: str = "", parent=None):
        super().__init__(parent)
        self.query_name = query_name
        self.endpoint_id = endpoint_id
        self.variable_value = variable_value
        self.from_iso = from_iso
        self.to_iso = to_iso

    def run(self):
        try:
            log.info("[HISTORY QUERY] worker start")
            log.info(f"[HISTORY QUERY] query_name={self.query_name}")
            log.info(f"[HISTORY QUERY] endpoint_id={self.endpoint_id}")
            log.info(f"[HISTORY QUERY] variable_value={self.variable_value}")

            selected_query = get_history_query_by_name(self.query_name)
            if not selected_query:
                raise RuntimeError(f"saved query not found: {self.query_name}")

            query_id = str(selected_query.get("id", "")).strip()
            variables_meta = selected_query.get("variables", [])
            if not isinstance(variables_meta, list):
                variables_meta = []

            variables = {}
            if variables_meta and self.variable_value.strip():
                first_var = variables_meta[0] if isinstance(variables_meta[0], dict) else {}
                var_name = str(first_var.get("name", "")).strip()
                if var_name:
                    variables[var_name] = self.variable_value.strip()

            client = SophosXdrQueryClient()

            run_data = client.run_saved_query(
                query_id=query_id,
                endpoint_id=self.endpoint_id,
                from_iso=self.from_iso,
                to_iso=self.to_iso,
                variables=variables,
            )

            run_id = (
                run_data.get("id")
                or run_data.get("runId")
                or run_data.get("queryRunId")
            )

            if not run_id:
                raise RuntimeError(f"run_id not found: {run_data}")

            log.info(f"[HISTORY QUERY] run_id={run_id}")

            max_wait = 60
            interval = 3
            waited = 0

            while waited < max_wait:
                status_data = client.get_run(run_id)

                status = str(
                    status_data.get("status")
                    or status_data.get("state")
                    or ""
                ).lower()

                result = str(status_data.get("result") or "").lower()

                log.info(f"[HISTORY QUERY] status_data={status_data}")

                if status in ("finished", "completed", "done") and result in ("succeeded", "success"):
                    break

                if status in ("failed", "error", "cancelled", "canceled", "timeout") or result in ("failed", "timedout"):
                    raise RuntimeError(f"history query failed: {status_data}")

                time.sleep(interval)
                waited += interval
            else:
                raise RuntimeError("history query polling timeout")

            result_data = client.get_results(run_id)
            log.info(f"[HISTORY QUERY] result_data={result_data}")

            items = result_data.get("items", [])
            if not isinstance(items, list):
                items = []

            rows = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = dict(item)
                row["_raw"] = item
                rows.append(row)

            log.info(f"[HISTORY QUERY] rows_count={len(rows)}")
            self.ok.emit(rows)

        except Exception as e:
            log.exception("[HISTORY QUERY] worker fail")
            self.fail.emit(f"{type(e).__name__}: {e}")

class FirewallResponseWorker(QThread):
    ok = pyqtSignal(list)
    fail = pyqtSignal(str)

    def __init__(self, mode: str, target_list: list, firewall_configs: list = None, parent=None):
        super().__init__(parent)
        self.mode = str(mode or "").strip()
        self.target_list = target_list
        self.firewall_configs = firewall_configs or []

    def run(self):
        try:
            log.info("[FIREWALL RESPONSE] worker start")
            log.info(f"[FIREWALL RESPONSE] mode={self.mode}")
            log.info(f"[FIREWALL RESPONSE] target_count={len(self.target_list)}")
            log.info(f"[FIREWALL RESPONSE] target_list={self.target_list}")
            log.info(f"[FIREWALL RESPONSE] firewall_count={len(self.firewall_configs)}")

            all_results = []

            for fw_config in self.firewall_configs:
                fw_name = str(fw_config.get("name", "Unknown"))

                try:
                    log.info(f"[FIREWALL RESPONSE] start firewall={fw_name}")

                    client = SophosFirewallClient(firewall_config=fw_config)

                    if self.mode == "DOMAIN":
                        results = client.create_fqdn_host_bulk(self.target_list)
                    else:
                        results = client.create_ip_host_bulk(self.target_list)

                    all_results.extend(results)

                    log.info(f"[FIREWALL RESPONSE] done firewall={fw_name} count={len(results)}")

                except Exception as e:
                    log.exception(f"[FIREWALL RESPONSE] firewall failed: {fw_name}")

                    for target in self.target_list:
                        if self.mode == "DOMAIN":
                            object_name = f"AIDR_{target}"
                        else:
                            object_name = f"AIDR_{target}"

                        all_results.append({
                            "firewall": fw_name,
                            "target": target,
                            "ip": target,
                            "name": object_name,
                            "success": False,
                            "response": "",
                            "error": f"{type(e).__name__}: {e}",
                        })

            log.info(f"[FIREWALL RESPONSE] total_result_count={len(all_results)}")
            self.ok.emit(all_results)

        except Exception as e:
            log.exception("[FIREWALL RESPONSE] worker fail")
            self.fail.emit(f"{type(e).__name__}: {e}")

# ======================================================
# Firewall Group Get
# ======================================================
class FirewallGroupQueryWorker(QThread):
    ok = pyqtSignal(dict)
    fail = pyqtSignal(str)

    def __init__(self, firewall_config: dict, parent=None):
        super().__init__(parent)
        self.firewall_config = firewall_config or {}

    def run(self):
        fw_name = str(self.firewall_config.get("name", "Unknown"))

        try:
            log.info(f"[FIREWALL GROUP QUERY] worker start firewall={fw_name}")

            client = SophosFirewallClient(firewall_config=self.firewall_config)

            ip_raw = ""
            fqdn_raw = ""
            ip_result = {}
            fqdn_result = {}

            try:
                ip_raw = client.get_ip_host_group_raw()
                ip_result = parse_firewall_group_members(ip_raw, group_type="IP")
            except Exception as e:
                log.exception(f"[FIREWALL GROUP QUERY] IP group query failed firewall={fw_name}")
                ip_result = {
                    "group_type": "IP",
                    "group_name": client.iphost_group,
                    "members": [],
                    "status_code": "",
                    "status_message": "",
                    "raw": ip_raw,
                    "error": f"{type(e).__name__}: {e}",
                }

            try:
                fqdn_raw = client.get_fqdn_host_group_raw()
                fqdn_result = parse_firewall_group_members(fqdn_raw, group_type="DOMAIN")
            except Exception as e:
                log.exception(f"[FIREWALL GROUP QUERY] FQDN group query failed firewall={fw_name}")
                fqdn_result = {
                    "group_type": "DOMAIN",
                    "group_name": client.fqdnhost_group,
                    "members": [],
                    "status_code": "",
                    "status_message": "",
                    "raw": fqdn_raw,
                    "error": f"{type(e).__name__}: {e}",
                }

            data = {
                "firewall": fw_name,
                "ip_group": ip_result,
                "fqdn_group": fqdn_result,
            }

            log.info(
                f"[FIREWALL GROUP QUERY] worker ok firewall={fw_name} "
                f"ip_members={len(ip_result.get('members', []))} "
                f"fqdn_members={len(fqdn_result.get('members', []))}"
            )

            self.ok.emit(data)

        except Exception as e:
            log.exception(f"[FIREWALL GROUP QUERY] worker fail firewall={fw_name}")
            self.fail.emit(f"{fw_name}: {type(e).__name__}: {e}")

# ======================================================
# API clients / Sophos Live Discover
# - Runs Live Discover and History Query requests used by the Easy Query screen.
# ======================================================
class SophosLiveDiscoverClient:
    def __init__(self):
        load_env_from_file(ENV_PATH)

        self.client_id = os.getenv("SOPHOS_CLIENT_ID", "").strip()
        self.client_secret = os.getenv("SOPHOS_CLIENT_SECRET", "").strip()
        self.token_url = os.getenv(
            "SOPHOS_TOKEN_URL",
            "https://id.sophos.com/api/v2/oauth2/token"
        ).strip()
        self.whoami_url = os.getenv(
            "SOPHOS_WHOAMI_URL",
            "https://api.central.sophos.com/whoami/v1"
        ).strip()

        self.token = None
        self.tenant_id = None
        self.base_url = None

        if not self.client_id or not self.client_secret:
            raise RuntimeError("SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET missing")

        self._auth()

    def _auth(self):
        log.info("[LIVE DISCOVER] Requesting access token")

        r = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "token",
            },
            timeout=45,
        )
        r.raise_for_status()

        self.token = r.json().get("access_token")
        if not self.token:
            raise RuntimeError("access_token missing")

        log.info("[LIVE DISCOVER] Calling WHOAMI")

        r = requests.get(
            self.whoami_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=45,
        )
        r.raise_for_status()

        d = r.json()

        self.tenant_id = d.get("id")
        api_hosts = d.get("apiHosts") if isinstance(d.get("apiHosts"), dict) else {}
        host = api_hosts.get("dataRegion") or d.get("apiHost")

        if not self.tenant_id or not host:
            raise RuntimeError("WHOAMI missing tenant_id or host")

        host = str(host).strip()
        if host.startswith("http://") or host.startswith("https://"):
            self.base_url = host
        else:
            self.base_url = f"https://{host}"

        log.info(f"[LIVE DISCOVER] Tenant ID: {self.tenant_id}")
        log.info(f"[LIVE DISCOVER] Base URL: {self.base_url}")

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "X-Tenant-ID": self.tenant_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def run_ad_hoc_query(self, endpoint_name: str, query: str):
        url = f"{self.base_url}/live-discover/v1/queries/runs"

        body = {
            "adHocQuery": {
                "name": f"Live Discover - {endpoint_name}",
                "template": query
            },
            "matchEndpoints": {
                "all": False,
                "filters": [
                    {
                        "hostnameContains": endpoint_name
                    }
                ]
            }
        }

        log.info(f"[LIVE DISCOVER] run query for endpoint={endpoint_name}")
        log.info(f"[LIVE DISCOVER] query={query}")
        log.info(f"[LIVE DISCOVER] request_body={json.dumps(body, ensure_ascii=False)}")

        r = requests.post(
            url,
            headers=self._headers(),
            json=body,
            timeout=60,
        )

        log.info(f"[LIVE DISCOVER] status_code={r.status_code}")
        log.info(f"[LIVE DISCOVER] response_text={r.text}")

        r.raise_for_status()
        return r.json()

    def get_run(self, run_id: str):
        url = f"{self.base_url}/live-discover/v1/queries/runs/{run_id}"

        r = requests.get(
            url,
            headers=self._headers(),
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    def get_results(self, run_id: str):
        url = f"{self.base_url}/live-discover/v1/queries/runs/{run_id}/results"

        r = requests.get(
            url,
            headers=self._headers(),
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

# ======================================================
# API clients / Sophos XDR Query
# - Runs saved/custom XDR data-lake queries and returns tabular results to the UI workers.
# ======================================================
class SophosXdrQueryClient:
    def __init__(self):
        load_env_from_file(ENV_PATH)

        self.client_id = os.getenv("SOPHOS_CLIENT_ID", "").strip()
        self.client_secret = os.getenv("SOPHOS_CLIENT_SECRET", "").strip()
        self.token_url = os.getenv(
            "SOPHOS_TOKEN_URL",
            "https://id.sophos.com/api/v2/oauth2/token"
        ).strip()
        self.whoami_url = os.getenv(
            "SOPHOS_WHOAMI_URL",
            "https://api.central.sophos.com/whoami/v1"
        ).strip()

        self.token = None
        self.tenant_id = None
        self.base_url = None

        if not self.client_id or not self.client_secret:
            raise RuntimeError("SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET missing")

        self._auth()

    def _auth(self):
        r = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "token",
            },
            timeout=45,
        )
        r.raise_for_status()

        self.token = r.json().get("access_token")
        if not self.token:
            raise RuntimeError("access_token missing")

        r = requests.get(
            self.whoami_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=45,
        )
        r.raise_for_status()

        d = r.json()
        self.tenant_id = d.get("id")

        api_hosts = d.get("apiHosts") if isinstance(d.get("apiHosts"), dict) else {}
        host = api_hosts.get("dataRegion") or d.get("apiHost")

        if not self.tenant_id or not host:
            raise RuntimeError("WHOAMI missing tenant_id or host")

        host = str(host).strip()
        if host.startswith("http://") or host.startswith("https://"):
            self.base_url = host
        else:
            self.base_url = f"https://{host}"

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "X-Tenant-ID": self.tenant_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def run_query(self, query: str, endpoint_id: str, from_iso: str, to_iso: str):
        url = f"{self.base_url}/xdr-query/v1/queries/runs"

        body = {
            "adHocQuery": {
                "template": query
            },
            "matchEndpoints": {
                "filters": [
                    {
                        "ids": [endpoint_id]
                    }
                ]
            },
            "from": from_iso,
            "to": to_iso
        }

        log.info(f"[XDR QUERY] request_body={json.dumps(body, ensure_ascii=False)}")

        r = requests.post(
            url,
            headers=self._headers(),
            json=body,
            timeout=60,
        )
        log.info(f"[XDR QUERY] status_code={r.status_code}")
        log.info(f"[XDR QUERY] response_text={r.text}")
        r.raise_for_status()
        return r.json()

    def run_saved_query(self, query_id: str, endpoint_id: str = "", from_iso: str = "", to_iso: str = "", variables: dict = None):
        url = f"{self.base_url}/xdr-query/v1/queries/runs"

        if variables is None:
            variables = {}

        body = {
            "savedQuery": {
                "queryId": query_id
            }
        }

        if from_iso:
            body["from"] = from_iso
        if to_iso:
            body["to"] = to_iso
        if variables:
            body["savedQuery"]["variables"] = variables

        if endpoint_id:
            body["matchEndpoints"] = {
                "filters": [
                    {
                        "ids": [endpoint_id]
                    }
                ]
            }

        log.info(f"[HISTORY QUERY] request_body={json.dumps(body, ensure_ascii=False)}")

        r = requests.post(
            url,
            headers=self._headers(),
            json=body,
            timeout=60,
        )
        log.info(f"[HISTORY QUERY] status_code={r.status_code}")
        log.info(f"[HISTORY QUERY] response_text={r.text}")
        r.raise_for_status()
        return r.json()

    def get_run(self, run_id: str):
        url = f"{self.base_url}/xdr-query/v1/queries/runs/{run_id}"

        r = requests.get(
            url,
            headers=self._headers(),
            timeout=60,
        )
        log.info(f"[XDR QUERY] get_run_status_code={r.status_code}")
        log.info(f"[XDR QUERY] get_run_response_text={r.text}")
        r.raise_for_status()
        return r.json()

    def get_results(self, run_id: str, max_size: int = 1000):
        url = f"{self.base_url}/xdr-query/v1/queries/runs/{run_id}/results"

        r = requests.get(
            url,
            headers=self._headers(),
            params={"maxSize": max_size},
            timeout=60,
        )
        log.info(f"[XDR QUERY] get_results_status_code={r.status_code}")
        log.info(f"[XDR QUERY] get_results_response_text={r.text}")
        r.raise_for_status()
        return r.json()

# ======================================================
# Main UI
# ======================================================


class ReportPerfTimer:
    def __init__(self, name="report"):
        self.name = name
        self.started_at = time.perf_counter()
        self.last_at = self.started_at

    def mark(self, label):
        now = time.perf_counter()
        log.info(
            "[REPORT PERF] %s: %s %.3fs (total %.3fs)",
            self.name,
            label,
            now - self.last_at,
            now - self.started_at,
        )
        self.last_at = now

    def finish(self):
        now = time.perf_counter()
        log.info("[REPORT PERF] %s: total %.3fs", self.name, now - self.started_at)
        self.last_at = now


class SecurityReportWorker(QThread):
    progress = pyqtSignal(str)
    completed = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, report_builder, start_dt, end_dt, parent=None):
        super().__init__(parent)
        self.report_builder = report_builder
        self.start_dt = start_dt
        self.end_dt = end_dt

    def run(self):
        try:
            pdf_path = self.report_builder(
                self.start_dt,
                self.end_dt,
                progress_cb=self.progress.emit,
            )
            self.completed.emit(str(pdf_path or ""))
        except Exception as e:
            log.exception("Security report worker failed")
            self.failed.emit(f"{type(e).__name__}: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.color_config = ensure_color_env_file()
        apply_color_config_to_theme(self.color_config)

        self.auto_pending = []
        self.auto_index_after_refresh = False
        self.auto_continue_after_index = False

        self.dashboard_range = ""
        self.detection_range = ""
        self.email_range = ""
        self.xdr_range = ""
        self.dlp_range = ""
        self.sensitive_files_range = ""
        self.mailscreen_range = ""


        # 🔥 탭별 데이터 저장소
        self.dashboard_detections = []
        self.dashboard_xdr_detections = []
        self.dashboard_emails = []

        self.dashboard_compare_detections = []
        self.dashboard_compare_xdr_detections = []
        self.dashboard_compare_emails = []
        self.dashboard_compare_dlp = []
        self.dashboard_compare_mailscreen = []

        self.detection_detections = []
        self.email_emails = []
        self.xdr_detections = []
        self.dlp_rows = []
        self.sensitive_dlp_rows = []
        self.mailscreen_rows = []

        self.trend_colors = self.trend_colors_from_config(self.color_config)
        self.trend_visibility = {
            "Detection - XDR": True,
            "Email - XDR": True,
            "Inbound Mail": True,
            "Outbound Mail": True,
            "File": True,
        }

        self.setWindowTitle("Sophos Monitoring UI")
        self.resize(1500, 850)

        self.running = False
        self.worker = None

        self.history_queries_cache = load_history_queries()

        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("statusPill")
        self.status_label.setAlignment(Qt.AlignCenter)

        self.range_label = QLabel("")
        self.range_label.setObjectName("rangePill")
        self.range_label.setAlignment(Qt.AlignCenter)

        self._spin_timer = QTimer()
        self._spin_timer.timeout.connect(self._spin_tick)
        self._spin_phase = 0
        self._spin_base = "Running"

        # 🔥 자동 새로고침 타이머
        self.det_timer = QTimer()
        self.det_timer.timeout.connect(self.auto_refresh_detection)

        self.mail_timer = QTimer()
        self.mail_timer.timeout.connect(self.auto_refresh_email)

        self.dlp_timer = QTimer()
        self.dlp_timer.timeout.connect(self.auto_refresh_dlp)

        self.mailscreen_timer = QTimer()
        self.mailscreen_timer.timeout.connect(self.auto_refresh_mailscreen)

        # 🔥 캘린더 UI
        self.start_date_edit = QDateEdit()
        self.start_date_edit.setObjectName("datePicker")
        self.start_date_edit.setCalendarPopup(True)
        self.start_date_edit.setDisplayFormat("yyyy-MM-dd")

        self.end_date_edit = QDateEdit()
        self.end_date_edit.setObjectName("datePicker")
        self.end_date_edit.setCalendarPopup(True)
        self.end_date_edit.setDisplayFormat("yyyy-MM-dd")

        self.start_date_edit.setMinimumWidth(184)
        self.end_date_edit.setMinimumWidth(184)
        self.apply_date_picker_style(self.start_date_edit)
        self.apply_date_picker_style(self.end_date_edit)

        today = QDate.currentDate()
        self.end_date_edit.setDate(today)
        self.start_date_edit.setDate(today.addDays(-6))  # 기본 7일

        self.btn_apply_range = QPushButton("적용")
        self.btn_apply_range.clicked.connect(self.apply_date_range)
        self.btn_apply_range.setProperty("buttonRole", "primary")

        self.btn_color_settings = QPushButton("⚙")
        self.btn_color_settings.setToolTip("색상 설정")
        self.btn_color_settings.setFixedSize(38, 36)
        self.btn_color_settings.setProperty("buttonRole", "secondary")
        self.btn_color_settings.setStyleSheet(self.button_style("secondary"))
        self.btn_color_settings.clicked.connect(self.open_color_settings_dialog)

        # 🔥 Top Layout
        top = QHBoxLayout()
        top.addWidget(self.status_label)
        top.addStretch()
        top.addWidget(self.range_label)
        top.addWidget(self.start_date_edit)
        top.addWidget(self.end_date_edit)
        top.addWidget(self.btn_apply_range)
        top.addWidget(self.btn_color_settings)

        self.tabs = QTabWidget()
        self.logical_tab_widgets = {}
        self.logical_tab_locations = {}
        self.logical_tab_aliases = {
            "Detection": "Detection - XDR",
            "Detection XDR": "Email - XDR",
            "Inbound Mail": "Email",
            "Forensic": "Timeline",
            "Forensics": "Timeline",
            "Response": "Firewall",
        }
        self.group_subtab_bars = {}

        def register_top_tab(logical_name, widget, display_name):
            idx = self.tabs.addTab(widget, display_name)
            self.logical_tab_widgets[logical_name] = widget
            self.logical_tab_locations[logical_name] = (self.tabs, idx, None, None)
            return idx

        def add_group_tab(group_name, children):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 0, 0, 0)
            page_layout.setSpacing(0)

            subbar = QFrame(page)
            subbar.setObjectName("subtabBar")
            subbar_layout = QVBoxLayout(subbar)
            subbar_layout.setContentsMargins(0, 0, 0, 0)
            subbar_layout.setSpacing(0)
            subbar.setFixedWidth(260)
            subbar.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

            stack = QStackedWidget()
            parent_idx = self.tabs.addTab(page, group_name)
            self.group_subtab_bars[parent_idx] = subbar

            for logical_name, display_name, widget in children:
                child_idx = stack.addWidget(widget)
                self.logical_tab_widgets[logical_name] = widget
                self.logical_tab_locations[logical_name] = (self.tabs, parent_idx, stack, child_idx)

                btn = QPushButton(display_name)
                btn.setObjectName("subtabButton")
                btn.setCheckable(True)
                btn.setMinimumWidth(260)
                btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
                btn.clicked.connect(
                    lambda checked=False, p_idx=parent_idx, c_idx=child_idx, name=logical_name:
                        self.select_group_child_tab(p_idx, c_idx, name, hide_subtabs=True)
                )
                subbar_layout.addWidget(btn)

            page_layout.addWidget(stack, 1)
            subbar.adjustSize()
            subbar.move(0, 0)
            subbar.hide()
            return stack

        register_top_tab("Dashboard", self.tab_dashboard(), "Dashboard")
        self.detection_tabs = add_group_tab("Detection", [
            ("Detection - XDR", "Detection - XDR", self.tab_detection_xdr()),
            ("Email - XDR", "Email - XDR", self.tab_email_xdr()),
            ("Email", "Inbound Mail", self.tab_email()),
            ("Outbound Mail", "Outbound Mail", self.tab_outbound_mail()),
            ("File", "File", self.tab_dlp_file()),
        ])
        self.forensic_tabs = add_group_tab("Forensics", [
            ("Timeline", "Timeline", self.tab_timeline()),
            ("Sensitive Files", "Sensitive Files", self.tab_sensitive_files()),
            ("Sensitive Sites", "Sensitive Sites", self.tab_sensitive_sites()),
        ])
        self.response_tabs = add_group_tab("Response", [
            ("Firewall", "Firewall", self.tab_firewall()),
            ("Easy Query", "Easy Query", self.tab_live_discover()),
        ])
        self.asset_tabs = add_group_tab("Asset", [
            ("Endpoint", "Endpoint", self.tab_endpoint()),
            ("Organization", "Organization", self.tab_org()),
        ])
        register_top_tab("Config", self.tab_config(), "Config")

        root = QWidget()
        root.setObjectName("appRoot")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addLayout(top)
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)

        self.tabs.currentChanged.connect(self.on_top_tab_changed)
        self.tabs.tabBarClicked.connect(self.on_top_tab_clicked)
        QApplication.instance().installEventFilter(self)

        # 🔥 시작 시 기본 7일 데이터 로드
        self.apply_date_range()

        self.apply_main_stylesheet()


    def theme(self, key):
        return UI_THEME[key]

    def trend_colors_from_config(self, config):
        return {
            "Detection - XDR": normalize_hex_color(config.get("Threat_trend_Detection"), DEFAULT_COLOR_CONFIG["Threat_trend_Detection"]),
            "Email - XDR": normalize_hex_color(config.get("Threat_trend_Detection_XDR"), DEFAULT_COLOR_CONFIG["Threat_trend_Detection_XDR"]),
            "Email": normalize_hex_color(config.get("Threat_trend_Email"), DEFAULT_COLOR_CONFIG["Threat_trend_Email"]),
            "Outbound Mail": normalize_hex_color(config.get("Threat_trend_Outbound_Mail"), DEFAULT_COLOR_CONFIG["Threat_trend_Outbound_Mail"]),
            "File": normalize_hex_color(config.get("Threat_trend_File"), DEFAULT_COLOR_CONFIG["Threat_trend_File"]),
        }

    def main_stylesheet(self):
        t = UI_THEME
        return f"""
        QMainWindow, QWidget#appRoot {{
            background: {t['app_background']};
            color: {t['text']};
            font-family: {UI_FONT_FAMILY};
            font-size: 13px;
        }}

        QLabel#statusPill, QLabel#rangePill {{
            background: {t['status_blue_bg']};
            color: {t['accent']};
            border: 1px solid {t['status_blue_border']};
            border-radius: 12px;
            padding: 6px 12px;
            font-weight: 700;
            min-height: 20px;
        }}

        QLabel#rangePill {{
            background: {t['surface_muted']};
            color: {t['status_blue_text']};
            border-color: {t['status_blue_border']};
        }}

        QTabWidget::pane {{
            border: 1px solid #e5e7eb;
            border-radius: 18px;
            background: {t['surface']};
            top: -1px;
        }}

        QTabBar::tab {{
            background: #f8fafc;
            color: #64748b;
            padding: 10px 18px;
            margin-right: 5px;
            border: 1px solid #e5e7eb;
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
            min-height: 18px;
        }}

        QTabBar::tab:selected {{
            background: {t['surface']};
            color: {t['accent']};
            border: 1px solid {t['border']};
            border-bottom: 2px solid {t['accent']};
        }}

        QTabBar::tab:hover {{
            background: {t['accent_soft']};
            color: {t['accent']};
        }}

        QFrame#subtabBar {{
            background: {t['surface']};
            border: 1px solid #e5e7eb;
            border-top: 0px;
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
        }}

        QPushButton#subtabButton {{
            background: #f8fafc;
            color: #334155;
            padding: 10px 18px;
            border: 1px solid #e5e7eb;
            border-top: 0px;
            border-radius: 0px;
            min-height: 22px;
            text-align: left;
        }}

        QPushButton#subtabButton:hover {{
            background: {t['accent_soft']};
            color: {t['accent']};
        }}

        QPushButton#subtabButton:checked {{
            background: {t['surface']};
            color: {t['accent']};
            border-bottom: 2px solid {t['accent']};
        }}

        QCheckBox {{
            color: {t['checkbox_text']};
            spacing: 8px;
            font-weight: 700;
        }}

        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: 1px solid {t['border']};
            border-radius: 4px;
            background: {t['surface']};
        }}

        QCheckBox::indicator:checked {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {t['checkbox_checked_start']}, stop:1 {t['checkbox_checked_end']});
            border: 1px solid {t['checkbox_checked_end']};
        }}

        QPushButton {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {t['button_primary_stop_0']}, stop:0.18 {t['button_primary_stop_1']}, stop:0.54 {t['button_primary_stop_2']}, stop:1 {t['button_primary_stop_3']});
            color: {UI_THEME['button_primary_text']};
            border: 1px solid rgba(8, 99, 226, 0.28);
            border-radius: 10px;
            padding: 7px 18px;
            font-weight: 800;
        }}

        QPushButton:hover {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {t['button_primary_hover_stop_0']}, stop:0.16 {t['button_primary_hover_stop_1']}, stop:0.56 {t['button_primary_hover_stop_2']}, stop:1 {t['button_primary_hover_stop_3']});
            border: 1px solid rgba(8, 99, 226, 0.42);
        }}

        QDateEdit, QTimeEdit, QComboBox, QLineEdit, QTextEdit, QSpinBox {{
            background: {t['surface']};
            color: {t['text']};
            border: 1px solid {t['input_border']};
            border-radius: 10px;
            padding: 6px 10px;
            selection-background-color: {t['accent']};
            font-family: {UI_FONT_FAMILY};
            font-size: 13px;
            min-height: 22px;
        }}

        QComboBox {{ padding: 6px 32px 6px 12px; }}

        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 28px;
            border-left: 1px solid {t['border_soft']};
            border-top-right-radius: 10px;
            border-bottom-right-radius: 10px;
            background: {t['surface_muted']};
        }}

        QComboBox::down-arrow {{
            image: none;
            width: 0px;
            height: 0px;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 6px solid {t['accent']};
            margin-right: 8px;
        }}

        QComboBox QAbstractItemView {{
            background: {t['surface']};
            color: {t['text']};
            border: 1px solid {t['border']};
            border-radius: 10px;
            selection-background-color: {t['table_selection_bg']};
            selection-color: {t['table_selection_text']};
            padding: 4px;
        }}

        QTableWidget {{
            background: {t['surface']};
            color: {t['text']};
            border: 1px solid {t['accent_soft']};
            border-radius: 12px;
            gridline-color: {t['surface_muted']};
            selection-background-color: {t['table_selection_bg']};
            selection-color: {t['table_selection_text']};
            font-size: 13px;
        }}

        QTableWidget::item {{
            padding: 6px;
            border-bottom: 1px solid {t['surface_muted']};
        }}

        QHeaderView::section {{
            background: {t['table_header_bg']};
            color: {t['table_header_text']};
            border: none;
            border-right: 1px solid {t['accent_soft']};
            padding: 8px;
            font-weight: 800;
            font-size: 13px;
        }}

        QDateEdit#datePicker, QTimeEdit#timePicker, QSpinBox#numberInput, QLineEdit#formInput {{
            background: {t['surface']};
            color: #1f2937;
            border: 1px solid {t['border']};
            border-radius: 12px;
            padding: 7px 12px 7px 12px;
            font-size: 12px;
            font-weight: 700;
            min-height: 22px;
        }}

        QDateEdit#datePicker {{ padding-right: 30px; }}

        QDateEdit#datePicker::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 28px;
            border-left: 1px solid {t['border_soft']};
            border-top-right-radius: 12px;
            border-bottom-right-radius: 12px;
            background: {t['surface_muted']};
        }}

        QDateEdit#datePicker::down-arrow {{
            image: none;
            width: 0px;
            height: 0px;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 6px solid {t['accent']};
            margin-right: 8px;
        }}

        QTimeEdit#timePicker::up-button, QTimeEdit#timePicker::down-button, QSpinBox#numberInput::up-button, QSpinBox#numberInput::down-button {{
            width: 0px;
            height: 0px;
            border: none;
        }}

        QTimeEdit#timePicker::up-arrow, QTimeEdit#timePicker::down-arrow, QSpinBox#numberInput::up-arrow, QSpinBox#numberInput::down-arrow {{
            image: none;
            width: 0px;
            height: 0px;
        }}

        QSpinBox#intervalSpin {{
            background: {t['surface']};
            color: {t['text']};
            border: 1px solid {t['border']};
            border-radius: 8px;
            padding: 4px 22px 4px 8px;
            font-size: 12px;
            font-weight: 800;
            min-height: 18px;
        }}

        QSpinBox#intervalSpin::up-button, QSpinBox#intervalSpin::down-button {{
            subcontrol-origin: border;
            width: 18px;
            border-left: 1px solid {t['border_soft']};
            background: {t['surface_muted']};
        }}

        QSpinBox#intervalSpin::up-button {{
            subcontrol-position: top right;
            border-top-right-radius: 8px;
        }}

        QSpinBox#intervalSpin::down-button {{
            subcontrol-position: bottom right;
            border-bottom-right-radius: 8px;
        }}

        QSpinBox#intervalSpin::up-arrow {{
            width: 0px;
            height: 0px;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-bottom: 5px solid {t['accent']};
        }}

        QSpinBox#intervalSpin::down-arrow {{
            width: 0px;
            height: 0px;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 5px solid {t['accent']};
        }}

        QDateEdit:hover, QTimeEdit:hover, QComboBox:hover, QLineEdit:hover, QTextEdit:hover, QSpinBox:hover {{
            border-color: {t['accent_light']};
        }}

        QDateEdit#datePicker:hover, QTimeEdit#timePicker:hover, QSpinBox#numberInput:hover, QLineEdit#formInput:hover {{
            border-color: {t['accent']};
            background: #fafdff;
        }}

        QScrollBar:vertical {{
            background: transparent;
            width: 9px;
            margin: 4px 0 4px 0;
        }}

        QScrollBar::handle:vertical {{
            background: #cbd5e1;
            border-radius: 4px;
            min-height: 28px;
        }}

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """

    def apply_main_stylesheet(self):
        self.setStyleSheet(self.main_stylesheet())

    def config_root_stylesheet(self):
        return f"""
            QWidget#configRoot {{
                background: {UI_THEME['app_background']};
            }}
            QCheckBox {{
                color: {UI_THEME['checkbox_text']};
                font-size: 13px;
                font-weight: 700;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {UI_THEME['border']};
                border-radius: 4px;
                background: {UI_THEME['surface']};
            }}
            QCheckBox::indicator:checked {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {UI_THEME['checkbox_checked_start']}, stop:1 {UI_THEME['checkbox_checked_end']});
                border: 1px solid {UI_THEME['checkbox_checked_end']};
            }}
        """

    def apply_soft_shadow(self, widget, blur=28, y_offset=12, alpha=95):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(blur)
        shadow.setOffset(0, y_offset)
        r, g, b = UI_THEME["sierra_shadow"]
        shadow.setColor(QColor(r, g, b, min(max(alpha, 72), 96)))
        widget.setGraphicsEffect(shadow)

    def card_style(self, object_name, accent=True):
        return f"""
            QFrame#{object_name} {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {UI_THEME['surface']},
                    stop:1 {UI_THEME['surface_soft']});
                border: 1px solid {UI_THEME['accent_soft']};
                border-radius: 18px;
            }}
        """

    def button_style(self, variant="primary"):
        if variant == "secondary":
            return f"""
                QPushButton {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 {UI_THEME['button_secondary_start']},
                        stop:0.62 {UI_THEME['button_secondary_mid']},
                        stop:1 {UI_THEME['button_secondary_end']});
                    color: {UI_THEME['button_secondary_text']};
                    border: 1px solid {UI_THEME['border']};
                    border-radius: 12px;
                    padding: 8px 14px;
                    font-family: {UI_FONT_FAMILY};
                    font-size: 13px;
                    font-weight: 800;
                }}
                QPushButton:hover {{
                    background: {UI_THEME['accent_soft']};
                    border-color: {UI_THEME['accent']};
                }}
            """
        if variant == "ghost":
            return f"""
                QPushButton {{
                    background: transparent;
                    color: {UI_THEME['button_secondary_text']};
                    border: 1px solid {UI_THEME['border_soft']};
                    border-radius: 12px;
                    padding: 8px 14px;
                    font-family: {UI_FONT_FAMILY};
                    font-size: 13px;
                    font-weight: 800;
                }}
                QPushButton:hover {{
                    background: {UI_THEME['surface_muted']};
                    border-color: {UI_THEME['border']};
                }}
            """
        if variant == "mini":
            return f"""
                QPushButton {{
                    background: {UI_THEME['surface_muted']};
                    color: {UI_THEME['accent_text']};
                    border: 1px solid {UI_THEME['border_soft']};
                    border-radius: 8px;
                    padding: 2px 8px;
                    font-family: {UI_FONT_FAMILY};
                    font-size: 12px;
                    font-weight: 900;
                }}
                QPushButton:hover {{
                    background: {UI_THEME['accent_soft']};
                    border-color: {UI_THEME['border']};
                }}
            """
        return f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {UI_THEME['button_primary_stop_0']},
                    stop:0.18 {UI_THEME['button_primary_stop_1']},
                    stop:0.54 {UI_THEME['button_primary_stop_2']},
                    stop:1 {UI_THEME['button_primary_stop_3']});
                color: {UI_THEME['button_primary_text']};
                border: 1px solid rgba(8, 99, 226, 0.28);
                border-radius: 12px;
                padding: 9px 16px;
                font-family: {UI_FONT_FAMILY};
                font-size: 13px;
                font-weight: 800;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {UI_THEME['button_primary_hover_stop_0']},
                    stop:0.16 {UI_THEME['button_primary_hover_stop_1']},
                    stop:0.56 {UI_THEME['button_primary_hover_stop_2']},
                    stop:1 {UI_THEME['button_primary_hover_stop_3']});
                border-color: rgba(8, 99, 226, 0.42);
            }}
            QPushButton:pressed {{
                background: {UI_THEME['accent_deep']};
            }}
            QPushButton:disabled {{
                background: #cbd5e1;
                color: #f8fafc;
            }}
        """

    def apply_button_role(self, button, variant="primary", min_height=38):
        button.setProperty("buttonRole", variant)
        button.setStyleSheet(self.button_style(variant))
        if min_height:
            button.setMinimumHeight(min_height)

    def infer_button_role(self, button):
        role = button.property("buttonRole")
        if role:
            return str(role)
        text = button.text().strip()
        if text in {"+", "-"}:
            return "mini"
        if text in {"닫기", "Close"}:
            return "ghost"
        if button.toolTip() in {"색상 설정", "Trend color settings"}:
            return "secondary"
        return "primary"

    def restyle_themed_buttons(self):
        for button in self.findChildren(QPushButton):
            if button.text().strip().startswith("#") or button.property("buttonRole") == "color":
                continue
            role = self.infer_button_role(button)
            button.setProperty("buttonRole", role)
            button.setStyleSheet(self.button_style(role))

    def add_card_description(self, layout, text):
        desc = QLabel(text)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"""
            background: transparent;
            border: none;
            color: {UI_THEME['text_muted']};
            font-size: 12px;
            font-weight: 600;
        """)
        layout.addWidget(desc)

    def metric_table_html(self, metrics):
        header_cells = "".join(
            f"<td style='color:{UI_THEME['text_muted']}; font-size:11px; font-weight:700;'>{label}</td>"
            for label, _, _ in metrics
        )
        value_cells = "".join(
            f"<td><span style='color:{color or UI_THEME['accent']}; font-size:20px; font-weight:900;'>{value}</span></td>"
            for _, value, color in metrics
        )
        return f"""
        <table width='100%' cellspacing='0' cellpadding='0' style='line-height:22px; font-size:13px;'>
            <tr>{header_cells}</tr>
            <tr>{value_cells}</tr>
        </table>
        """

    def card_icon_kind(self, title):
        icons = {
            "Endpoints": "monitor",
            "Organization": "network",
            "Top File": "file",
            "Top Hash": "hash",
            "Folder Usage": "folder",
            "Threat Trend": "trend",
            "Top Analysis": "bars",
            "Detection - XDR Summary": "shield",
            "Detection Summary": "shield",
            "Email - XDR Summary": "radar",
            "Inbound Mail Summary": "mail",
            "File Summary": "file",
            "Cache Data": "database",
            "Auto Refresh": "refresh",
            "Export": "download",
            "Report": "report",
            "Folders": "folder",
        }
        return icons.get(title, "spark")

    def card_icon_pixmap(self, title, size=18):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        pen = QPen(QColor(UI_THEME["accent"]), 1.7)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        kind = self.card_icon_kind(title)
        w = size
        h = size
        if kind == "monitor":
            painter.drawRoundedRect(QRectF(3, 3, w - 6, h - 8), 2, 2)
            painter.drawLine(QPointF(w * 0.5, h - 5), QPointF(w * 0.5, h - 2))
            painter.drawLine(QPointF(w * 0.35, h - 2), QPointF(w * 0.65, h - 2))
        elif kind == "network":
            for x, y in [(w/2, 4), (4, h-5), (w-4, h-5)]:
                painter.drawEllipse(QPointF(x, y), 2.2, 2.2)
            painter.drawLine(QPointF(w/2, 6), QPointF(5, h-7))
            painter.drawLine(QPointF(w/2, 6), QPointF(w-5, h-7))
        elif kind == "file":
            path = QPainterPath()
            path.moveTo(5, 3)
            path.lineTo(w - 7, 3)
            path.lineTo(w - 3, 7)
            path.lineTo(w - 3, h - 3)
            path.lineTo(5, h - 3)
            path.closeSubpath()
            painter.drawPath(path)
            painter.drawLine(QPointF(7, 10), QPointF(w - 6, 10))
            painter.drawLine(QPointF(7, 13), QPointF(w - 8, 13))
        elif kind == "hash":
            painter.drawLine(QPointF(7, 3), QPointF(5, h - 3))
            painter.drawLine(QPointF(w - 5, 3), QPointF(w - 7, h - 3))
            painter.drawLine(QPointF(3, 7), QPointF(w - 3, 7))
            painter.drawLine(QPointF(3, h - 7), QPointF(w - 3, h - 7))
        elif kind == "folder":
            path = QPainterPath()
            path.moveTo(3, 6)
            path.lineTo(8, 6)
            path.lineTo(10, 8)
            path.lineTo(w - 3, 8)
            path.lineTo(w - 3, h - 4)
            path.lineTo(3, h - 4)
            path.closeSubpath()
            painter.drawPath(path)
        elif kind == "trend":
            points = [QPointF(3, h-5), QPointF(7, h-9), QPointF(11, h-7), QPointF(w-3, 4)]
            for a, b in zip(points, points[1:]):
                painter.drawLine(a, b)
            painter.drawEllipse(points[-1], 1.6, 1.6)
        elif kind == "bars":
            for i, height in enumerate([6, 10, 14]):
                x = 4 + i * 5
                painter.drawRoundedRect(QRectF(x, h - height - 2, 3, height), 1, 1)
        elif kind == "shield":
            path = QPainterPath()
            path.moveTo(w/2, 3)
            path.lineTo(w-4, 6)
            path.lineTo(w-5, 12)
            path.quadTo(w/2, h-2, 4, 12)
            path.lineTo(4, 6)
            path.closeSubpath()
            painter.drawPath(path)
        elif kind == "radar":
            painter.drawEllipse(QPointF(w/2, h/2), 6, 6)
            painter.drawEllipse(QPointF(w/2, h/2), 2, 2)
            painter.drawLine(QPointF(w/2, h/2), QPointF(w-4, 5))
        elif kind == "mail":
            painter.drawRoundedRect(QRectF(3, 5, w-6, h-10), 2, 2)
            painter.drawLine(QPointF(4, 6), QPointF(w/2, h/2))
            painter.drawLine(QPointF(w-4, 6), QPointF(w/2, h/2))
        elif kind == "database":
            painter.drawEllipse(QRectF(4, 3, w-8, 5))
            painter.drawLine(QPointF(4, 5.5), QPointF(4, h-5))
            painter.drawLine(QPointF(w-4, 5.5), QPointF(w-4, h-5))
            painter.drawEllipse(QRectF(4, h-8, w-8, 5))
        elif kind == "refresh":
            painter.drawArc(QRectF(4, 4, w-8, h-8), 40 * 16, 280 * 16)
            painter.drawLine(QPointF(w-5, 5), QPointF(w-3, 9))
            painter.drawLine(QPointF(w-5, 5), QPointF(w-9, 5))
        elif kind == "download":
            painter.drawLine(QPointF(w/2, 3), QPointF(w/2, h-7))
            painter.drawLine(QPointF(w/2, h-7), QPointF(w/2-4, h-11))
            painter.drawLine(QPointF(w/2, h-7), QPointF(w/2+4, h-11))
            painter.drawLine(QPointF(4, h-3), QPointF(w-4, h-3))
        elif kind == "report":
            painter.drawRoundedRect(QRectF(4, 3, w-8, h-6), 2, 2)
            painter.drawLine(QPointF(7, 8), QPointF(w-7, 8))
            painter.drawLine(QPointF(7, 12), QPointF(w-8, 12))
        else:
            painter.drawLine(QPointF(w/2, 3), QPointF(w/2, h-3))
            painter.drawLine(QPointF(3, h/2), QPointF(w-3, h/2))
            painter.drawEllipse(QPointF(w/2, h/2), 3, 3)
        painter.end()
        return pixmap

    def card_title_label_style(self, font_size=15, weight=800, letter_spacing="0.15px"):
        return f"""
            background: transparent;
            border: none;
            font-size:{font_size}px;
            font-weight:{weight};
            color:{UI_THEME['card_title_text']};
            letter-spacing:{letter_spacing};
        """

    def restyle_card_titles(self):
        for label in self.findChildren(QLabel):
            if label.property("cardTitle"):
                font_size = label.property("cardTitleFontSize") or 15
                weight = label.property("cardTitleWeight") or 800
                spacing = label.property("cardTitleLetterSpacing") or "0.15px"
                label.setStyleSheet(self.card_title_label_style(font_size, weight, spacing))

    def add_legacy_card_title(self, layout, title):
        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(9)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFixedSize(26, 26)
        icon_label.setStyleSheet(f"""
            QLabel {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffffff, stop:1 {UI_THEME['accent_soft']});
                border: 1px solid {UI_THEME['border']};
                border-radius: 10px;
            }}
        """)
        icon_glow = QGraphicsDropShadowEffect(self)
        icon_glow.setBlurRadius(10)
        icon_glow.setOffset(0, 2)
        r, g, b = UI_THEME["icon_glow"]
        icon_glow.setColor(QColor(r, g, b, 72))
        icon_label.setGraphicsEffect(icon_glow)
        icon_label.setPixmap(self.card_icon_pixmap(title, 16))

        label = QLabel(title)
        label.setProperty("cardTitle", True)
        label.setProperty("cardTitleFontSize", 15)
        label.setProperty("cardTitleWeight", 800)
        label.setProperty("cardTitleLetterSpacing", "0.15px")
        label.setStyleSheet(self.card_title_label_style(15, 800, "0.15px"))

        title_row.addWidget(icon_label)
        title_row.addWidget(label)
        title_row.addStretch()
        layout.addLayout(title_row)

    def add_card_title(self, layout, title, strong=True, action_text=None, action_callback=None):
        title_row = QHBoxLayout()
        title_row.setSpacing(10)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFixedSize(30, 30)
        icon_label.setStyleSheet(f"""
            QLabel {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {UI_THEME['surface']}, stop:1 {UI_THEME['accent_soft']});
                border: 1px solid {UI_THEME['accent_light']};
                border-radius: 12px;
            }}
        """)
        icon_glow = QGraphicsDropShadowEffect(self)
        icon_glow.setBlurRadius(14)
        icon_glow.setOffset(0, 3)
        r, g, b = UI_THEME["icon_glow"]
        icon_glow.setColor(QColor(r, g, b, 132))
        icon_label.setGraphicsEffect(icon_glow)
        icon_label.setPixmap(self.card_icon_pixmap(title, 18))

        title_label = QLabel(title)
        title_font_size = 16 if strong else 15
        title_label.setProperty("cardTitle", True)
        title_label.setProperty("cardTitleFontSize", title_font_size)
        title_label.setProperty("cardTitleWeight", 900)
        title_label.setProperty("cardTitleLetterSpacing", "0.2px")
        title_label.setStyleSheet(self.card_title_label_style(title_font_size, 900, "0.2px"))

        title_row.addWidget(icon_label)
        title_row.addWidget(title_label)
        title_row.addStretch()

        if action_text and action_callback:
            action_btn = QPushButton(action_text)
            action_btn.setFixedSize(34, 34)
            action_btn.setToolTip("Trend color settings")
            action_btn.setProperty("buttonRole", "secondary")
            action_btn.setStyleSheet(self.button_style("secondary"))
            action_btn.clicked.connect(action_callback)
            title_row.addWidget(action_btn)

        layout.addLayout(title_row)

        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background: {UI_THEME['border_soft']}; border: none;")
        layout.addWidget(divider)

    def apply_date_picker_style(self, date_edit):
        calendar = date_edit.calendarWidget()
        if not calendar:
            return

        calendar.setGridVisible(False)
        calendar.setStyleSheet(f"""
            QCalendarWidget {{
                background: {UI_THEME['surface']};
                border: 1px solid {UI_THEME['border']};
                border-radius: 14px;
                font-family: {UI_FONT_FAMILY};
                color: {UI_THEME['text']};
            }}
            QCalendarWidget QWidget#qt_calendar_navigationbar {{
                background: {UI_THEME['accent']};
                border-top-left-radius: 14px;
                border-top-right-radius: 14px;
                min-height: 34px;
            }}
            QCalendarWidget QToolButton {{
                background: transparent;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 6px;
                font-weight: 800;
            }}
            QCalendarWidget QToolButton:hover {{
                background: rgba(255, 255, 255, 0.16);
            }}
            QCalendarWidget QMenu {{
                background: {UI_THEME['surface']};
                color: {UI_THEME['text']};
                border: 1px solid {UI_THEME['border']};
                border-radius: 8px;
            }}
            QCalendarWidget QSpinBox {{
                background: rgba(255, 255, 255, 0.16);
                color: #ffffff;
                border: 1px solid rgba(255, 255, 255, 0.24);
                border-radius: 8px;
                padding: 3px 8px;
                font-weight: 800;
            }}
            QCalendarWidget QAbstractItemView {{
                background: {UI_THEME['surface']};
                color: #1f2937;
                selection-background-color: {UI_THEME['accent']};
                selection-color: #ffffff;
                border: none;
                outline: 0;
                gridline-color: {UI_THEME['surface_muted']};
                font-size: 12px;
                font-weight: 600;
            }}
            QCalendarWidget QAbstractItemView:enabled:hover {{
                background: {UI_THEME['surface_muted']};
                color: {UI_THEME['accent']};
            }}
        """)

    def prepare_form_control(self, widget, height=36):
        widget.setMinimumHeight(height)
        widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if isinstance(widget, QDateEdit):
            widget.setObjectName("datePicker")
            widget.setCalendarPopup(True)
            self.apply_date_picker_style(widget)
        elif isinstance(widget, QTimeEdit):
            widget.setObjectName("timePicker")
            widget.setButtonSymbols(QAbstractSpinBox.NoButtons)
        elif isinstance(widget, QSpinBox):
            widget.setObjectName("numberInput")
            widget.setButtonSymbols(QAbstractSpinBox.NoButtons)
        elif isinstance(widget, QLineEdit):
            widget.setObjectName("formInput")

        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def apply_runtime_color_config(self, config, persist=False):
        self.color_config = dict(config)
        apply_color_config_to_theme(self.color_config)
        self.trend_colors = self.trend_colors_from_config(self.color_config)
        if persist:
            save_color_env(self.color_config)

        self.apply_main_stylesheet()
        for widget in self.findChildren(QDateEdit):
            self.apply_date_picker_style(widget)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

        for frame in self.findChildren(QFrame):
            if frame.objectName() == "dashboardCard":
                frame.setStyleSheet(self.card_style("dashboardCard", accent=False))

        for widget in self.findChildren(QWidget):
            if widget.objectName() == "configRoot":
                widget.setStyleSheet(self.config_root_stylesheet())

        self.restyle_card_titles()
        if hasattr(self, "top_table"):
            self.top_table.setStyleSheet(self.top_table_stylesheet())
        if hasattr(self, "percent_label"):
            self.percent_label.setStyleSheet(f"""
                background: {UI_THEME['surface']};
                border: 1px solid {UI_THEME['border']};
                border-radius: 14px;
                color: {UI_THEME['text']};
                font-size: 13px;
                font-weight: 800;
                padding: 14px;
            """)

        self.restyle_themed_buttons()

        try:
            self.refresh_dashboard()
        except Exception as e:
            log.debug(f"Theme refresh skipped dashboard refresh: {e}")

    def create_color_preview(self, config):
        preview = {}
        frame = QFrame()
        frame.setObjectName("colorPreview")
        frame.setMinimumWidth(260)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("샘플 카드 제목")
        title.setProperty("previewRole", "title")

        primary_btn = QPushButton("Primary 버튼")
        primary_btn.setProperty("previewRole", "primary")
        secondary_btn = QPushButton("Secondary 버튼")
        secondary_btn.setProperty("previewRole", "secondary")

        checkbox = QCheckBox("체크박스 샘플")
        checkbox.setChecked(True)
        checkbox.setProperty("previewRole", "checkbox")

        table_header = QLabel("테이블 헤더")
        table_header.setProperty("previewRole", "tableHeader")
        table_row = QLabel("선택된 테이블 행")
        table_row.setProperty("previewRole", "tableRow")

        graph_title = QLabel("그래프 색상")
        graph_title.setStyleSheet("font-weight:800; color:#374151;")
        graph_row = QHBoxLayout()
        graph_row.setSpacing(6)
        graph_keys = [
            ("D", "Threat_trend_Detection"),
            ("X", "Threat_trend_Detection_XDR"),
            ("I", "Threat_trend_Email"),
            ("O", "Threat_trend_Outbound_Mail"),
            ("F", "Threat_trend_File"),
        ]
        graph_swatches = []
        for label_text, color_key in graph_keys:
            swatch = QLabel(label_text)
            swatch.setAlignment(Qt.AlignCenter)
            swatch.setFixedSize(34, 24)
            swatch.setProperty("colorKey", color_key)
            graph_swatches.append(swatch)
            graph_row.addWidget(swatch)
        graph_row.addStretch()

        layout.addWidget(title)
        layout.addWidget(primary_btn)
        layout.addWidget(secondary_btn)
        layout.addWidget(checkbox)
        layout.addWidget(table_header)
        layout.addWidget(table_row)
        layout.addWidget(graph_title)
        layout.addLayout(graph_row)
        layout.addStretch()

        preview.update({
            "frame": frame,
            "title": title,
            "primary_btn": primary_btn,
            "secondary_btn": secondary_btn,
            "checkbox": checkbox,
            "table_header": table_header,
            "table_row": table_row,
            "graph_swatches": graph_swatches,
        })
        self.update_color_preview(preview, config)
        return preview

    def update_color_preview(self, preview, config):
        c = default_color_config()
        c.update(config)
        for key, fallback in DEFAULT_COLOR_CONFIG.items():
            c[key] = normalize_hex_color(c.get(key), fallback)

        preview["frame"].setStyleSheet(f"""
            QFrame#colorPreview {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {c['UI_Surface']},
                    stop:1 {c['UI_Surface_Soft']});
                border: 1px solid {c['Card_Border']};
                border-radius: 16px;
            }}
        """)
        preview["title"].setStyleSheet(f"""
            background: transparent;
            border: none;
            color: {c['Card_Title_Text']};
            font-size: 15px;
            font-weight: 900;
        """)
        preview["primary_btn"].setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {c['Button_Primary_Stop_0']},
                    stop:0.18 {c['Button_Primary_Stop_1']},
                    stop:0.54 {c['Button_Primary_Stop_2']},
                    stop:1 {c['Button_Primary_Stop_3']});
                color: {c['Button_Primary_Text']};
                border: 1px solid {c['Primary_Blue']};
                border-radius: 10px;
                padding: 8px 12px;
                font-weight: 800;
            }}
        """)
        preview["secondary_btn"].setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {c['Button_Secondary_Start']},
                    stop:0.62 {c['Button_Secondary_Mid']},
                    stop:1 {c['Button_Secondary_End']});
                color: {c['Button_Secondary_Text']};
                border: 1px solid {c['Checkbox_Border']};
                border-radius: 10px;
                padding: 8px 12px;
                font-weight: 800;
            }}
        """)
        preview["checkbox"].setStyleSheet(f"""
            QCheckBox {{
                color: {c['Checkbox_Text']};
                font-weight: 800;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 15px;
                height: 15px;
                border: 1px solid {c['Checkbox_Border']};
                border-radius: 4px;
                background: {c['UI_Surface']};
            }}
            QCheckBox::indicator:checked {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {c['Checkbox_Checked_Start']},
                    stop:1 {c['Checkbox_Checked_End']});
            }}
        """)
        preview["table_header"].setStyleSheet(f"""
            background: {c['Table_Header_Background']};
            color: {c['Table_Header_Text']};
            border: 1px solid {c['Card_Border']};
            border-radius: 8px;
            padding: 7px;
            font-weight: 900;
        """)
        preview["table_row"].setStyleSheet(f"""
            background: {c['Table_Selection_Background']};
            color: {c['Table_Selection_Text']};
            border: 1px solid {c['Card_Border']};
            border-radius: 8px;
            padding: 7px;
            font-weight: 800;
        """)
        for swatch in preview["graph_swatches"]:
            color_key = swatch.property("colorKey")
            color = c.get(color_key, "#ffffff")
            text_color = "#ffffff" if QColor(color).lightness() < 150 else "#111827"
            swatch.setStyleSheet(f"""
                background: {color};
                color: {text_color};
                border: 1px solid {c['Checkbox_Border']};
                border-radius: 8px;
                font-weight: 900;
            """)

    def refresh_color_buttons(self, button_map, config):
        for key, button in button_map.items():
            button.setText(config[key])
            button.setStyleSheet(self.color_button_style(config[key]))

    def color_picker_row(self, dialog, config, key, label_text, button_map, on_change=None):
        row = QHBoxLayout()
        row.setSpacing(10)

        tooltip = COLOR_SETTING_TOOLTIPS.get(key, f"{label_text} 색상을 변경합니다.")

        label = QLabel(label_text)
        label.setMinimumWidth(210)
        label.setToolTip(tooltip)
        label.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-size:13px; font-weight:800;")

        btn = QPushButton(config.get(key, DEFAULT_COLOR_CONFIG[key]))
        btn.setMinimumWidth(112)
        btn.setToolTip(tooltip)
        btn.setProperty("buttonRole", "color")
        btn.setStyleSheet(self.color_button_style(config.get(key, DEFAULT_COLOR_CONFIG[key])))

        def choose_color():
            current = QColor(config.get(key, DEFAULT_COLOR_CONFIG[key]))
            color = QColorDialog.getColor(current, dialog, label_text)
            if not color.isValid():
                return
            config[key] = color.name()
            btn.setText(config[key])
            btn.setStyleSheet(self.color_button_style(config[key]))
            if on_change:
                on_change()

        btn.clicked.connect(choose_color)
        button_map[key] = btn
        row.addWidget(label)
        row.addWidget(btn)
        row.addStretch()
        return row

    def open_color_settings_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("UI Color Settings")
        dialog.setModal(True)
        dialog.resize(860, 620)

        original_config = dict(self.color_config)
        working_config = dict(self.color_config)
        preview_applied = {"value": False}
        button_map = {}

        root = QVBoxLayout(dialog)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        info = QLabel(f"저장 경로: {COLOR_ENV_PATH}\n테마 파일 경로: {COLOR_THEME_DIR}")
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{UI_THEME['text_soft']}; font-size:12px; font-weight:700;")
        root.addWidget(info)

        content = QHBoxLayout()
        content.setSpacing(14)

        preview = self.create_color_preview(working_config)

        def update_preview():
            self.update_color_preview(preview, working_config)

        tabs = QTabWidget()
        for group_name, items in COLOR_DIALOG_GROUPS:
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setContentsMargins(10, 10, 10, 10)
            tab_layout.setSpacing(8)
            for label_text, key in items:
                tab_layout.addLayout(
                    self.color_picker_row(
                        dialog,
                        working_config,
                        key,
                        label_text,
                        button_map,
                        on_change=update_preview,
                    )
                )
            tab_layout.addStretch()
            tabs.addTab(tab, group_name)

        content.addWidget(tabs, 2)
        content.addWidget(preview["frame"], 1)
        root.addLayout(content)

        actions = QHBoxLayout()
        actions.addStretch()

        btn_load_theme = QPushButton("테마 불러오기")
        btn_load_theme.setProperty("buttonRole", "secondary")
        btn_load_theme.setStyleSheet(self.button_style("secondary"))

        btn_save_theme = QPushButton("테마 저장")
        btn_save_theme.setProperty("buttonRole", "secondary")
        btn_save_theme.setStyleSheet(self.button_style("secondary"))

        btn_preview_apply = QPushButton("미리보기 적용")
        btn_preview_apply.setProperty("buttonRole", "secondary")
        btn_preview_apply.setStyleSheet(self.button_style("secondary"))

        btn_reset = QPushButton("기본값")
        btn_reset.setProperty("buttonRole", "secondary")
        btn_reset.setStyleSheet(self.button_style("secondary"))

        btn_save = QPushButton("저장")
        btn_save.setProperty("buttonRole", "primary")
        btn_save.setStyleSheet(self.button_style("primary"))

        btn_close = QPushButton("닫기")
        btn_close.setProperty("buttonRole", "ghost")
        btn_close.setStyleSheet(self.button_style("ghost"))

        def refresh_dialog_values():
            self.refresh_color_buttons(button_map, working_config)
            update_preview()

        def reset_defaults():
            working_config.clear()
            working_config.update(default_color_config())
            refresh_dialog_values()

        def apply_preview_only():
            self.apply_runtime_color_config(working_config, persist=False)
            preview_applied["value"] = True
            QMessageBox.information(self, "색상 설정", "현재 화면에만 미리보기로 적용했습니다. 저장 버튼을 누르면 파일에 저장됩니다.")

        def save_theme_preset():
            path, _ = QFileDialog.getSaveFileName(
                dialog,
                "테마 저장",
                os.path.join(COLOR_THEME_DIR, "theme.txt"),
                "Theme Files (*.txt);;All Files (*)",
            )
            if not path:
                return
            if not os.path.splitext(path)[1]:
                path = f"{path}.txt"
            save_color_env(working_config, path)
            QMessageBox.information(dialog, "테마 저장", f"테마를 저장했습니다.\n{path}")

        def load_theme_preset():
            path, _ = QFileDialog.getOpenFileName(
                dialog,
                "테마 불러오기",
                COLOR_THEME_DIR,
                "Theme Files (*.txt);;All Files (*)",
            )
            if not path:
                return
            loaded = load_color_env(path)
            working_config.clear()
            working_config.update(loaded)
            refresh_dialog_values()
            QMessageBox.information(dialog, "테마 불러오기", f"테마를 불러왔습니다.\n저장을 누르면 현재 기본 색상 파일에 반영됩니다.\n{path}")

        def save_and_apply():
            self.apply_runtime_color_config(working_config, persist=True)
            preview_applied["value"] = False
            QMessageBox.information(self, "색상 설정", "색상 설정을 저장하고 현재 화면에 적용했습니다.")
            dialog.accept()

        def discard_unsaved_preview():
            if preview_applied["value"]:
                self.apply_runtime_color_config(original_config, persist=False)

        btn_load_theme.clicked.connect(load_theme_preset)
        btn_save_theme.clicked.connect(save_theme_preset)
        btn_preview_apply.clicked.connect(apply_preview_only)
        btn_reset.clicked.connect(reset_defaults)
        btn_save.clicked.connect(save_and_apply)
        btn_close.clicked.connect(dialog.reject)
        dialog.rejected.connect(discard_unsaved_preview)

        actions.addWidget(btn_load_theme)
        actions.addWidget(btn_save_theme)
        actions.addWidget(btn_preview_apply)
        actions.addWidget(btn_reset)
        actions.addWidget(btn_close)
        actions.addWidget(btn_save)
        root.addLayout(actions)

        dialog.exec_()

    def open_trend_color_dialog(self):
        self.open_color_settings_dialog()

    def color_button_style(self, color):
        text_color = "#ffffff" if QColor(color).lightness() < 150 else "#111827"
        return f"""
            QPushButton {{
                background: {color};
                color: {text_color};
                border: 1px solid {UI_THEME['border']};
                border-radius: 10px;
                padding: 7px 10px;
                font-weight: 800;
            }}
        """

    def top_table_stylesheet(self):
        return f"""
            QTableWidget {{
                border: none;
                border-radius: 14px;
                background: {UI_THEME['surface']};
                color: {UI_THEME['text']};
                gridline-color: #e5e7eb;
                selection-background-color: {UI_THEME['table_selection_bg']};
                selection-color: {UI_THEME['table_selection_text']};
                font-size: 13px;
            }}
            QTableWidget::item {{
                padding: 6px;
                border-bottom: 1px solid {UI_THEME['surface_muted']};
            }}
            QHeaderView::section {{
                background: {UI_THEME['table_header_bg']};
                color: {UI_THEME['table_header_text']};
                font-weight: 800;
                border: none;
                padding: 8px;
            }}
        """

    def setup_report_font(self):
        try:
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont

            candidates = [
                os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "malgun.ttf"),
                os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "malgunbd.ttf"),
            ]

            regular_path = None

            for path in candidates:
                if os.path.exists(path) and path.lower().endswith("malgun.ttf"):
                    regular_path = path
                    break

            if regular_path:
                try:
                    pdfmetrics.registerFont(TTFont("ReportFont", regular_path))
                    return "ReportFont"
                except Exception:
                    pass

        except Exception:
            pass

        return "Helvetica"

    def draw_multiline_text(
        self,
        c,
        x,
        y,
        lines,
        line_height=16,
        max_width=480,
        font_name=None,
        font_size=10
    ):
        from reportlab.pdfbase.pdfmetrics import stringWidth

        if not lines:
            return y

        # 전달받지 못했으면 현재 캔버스 폰트 사용
        if not font_name:
            try:
                font_name = c._fontname
            except Exception:
                font_name = "Helvetica"

        for line in lines:
            text = str(line or "").strip()

            if not text:
                y -= line_height
                y = self.check_page(c, y, font_name=font_name, font_size=font_size)
                continue

            words = text.split()
            current = ""

            for word in words:
                trial = f"{current} {word}".strip()

                if stringWidth(trial, font_name, font_size) <= max_width:
                    current = trial
                else:
                    if current:
                        c.drawString(x, y, current)
                        y -= line_height
                        y = self.check_page(c, y, font_name=font_name, font_size=font_size)
                    current = word

            if current:
                c.drawString(x, y, current)
                y -= line_height
                y = self.check_page(c, y, font_name=font_name, font_size=font_size)

        return y

    def draw_dlp_dept_insight_lines(self, c, y_pos, lines, rf, margin, content_w):
        if not lines:
            return y_pos

        import re
        from reportlab.pdfbase.pdfmetrics import stringWidth

        def wrap_text(text, max_width, font_name=rf, font_size=10):
            text = str(text or "").strip()
            if not text:
                return [""]

            words = text.split()
            wrapped = []
            current = ""

            for word in words:
                test = word if not current else f"{current} {word}"
                if stringWidth(test, font_name, font_size) <= max_width:
                    current = test
                else:
                    if current:
                        wrapped.append(current)
                    current = word

            if current:
                wrapped.append(current)

            return wrapped or [""]

        # 평면 리스트를 "부서별 블록"으로 재구성
        blocks = []
        current_block = []

        for line in lines:
            text = str(line or "").strip()
            if not text:
                continue

            # "1. 디자인팀 | 총 ..." 형태면 새 블록 시작
            if re.match(r"^\d+\.\s+", text):
                if current_block:
                    blocks.append(current_block)
                current_block = [text]
            else:
                if not current_block:
                    current_block = [text]
                else:
                    current_block.append(text)

        if current_block:
            blocks.append(current_block)

        c.setFont(rf, 10)

        for block in blocks:
            header = str(block[0] or "").strip()
            sub_lines = [str(x or "").strip() for x in block[1:] if str(x or "").strip()]

            needed_height = 18 + max(1, len(sub_lines)) * 15 + 10
            y_pos = self.check_page(
                c, y_pos,
                threshold=max(needed_height, 120),
                font_name=rf,
                font_size=10
            )

            header_lines = wrap_text(header, content_w - 20, rf, 10)
            c.drawString(margin + 10, y_pos, header_lines[0])
            y_pos -= 15

            for extra in header_lines[1:]:
                c.drawString(margin + 24, y_pos, extra)
                y_pos -= 15

            for line in sub_lines:
                wrapped = wrap_text(line, content_w - 34, rf, 10)
                for idx, sub in enumerate(wrapped):
                    if idx == 0:
                        c.drawString(margin + 24, y_pos, sub)
                    else:
                        c.drawString(margin + 32, y_pos, sub)
                    y_pos -= 15

            y_pos -= 8

        return y_pos

    def is_dlp_blocked_row(self, row):
        if not isinstance(row, dict):
            return False

        event_name = str(row.get("event_id", "")).strip()
        return "차단" in event_name

    def build_report_identity_resolver(self):
        identity_cache = {}

        def resolve(machine_name):
            key = str(machine_name or "").strip()
            cache_key = normalize_name_key(key)
            if cache_key in identity_cache:
                return identity_cache[cache_key]

            endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(key)

            if user_type == "shared_pc":
                result = {
                    "user_name": endpoint_user_name,
                    "user_id": endpoint_user_id,
                    "user_type": user_type,
                    "dept_name": "공용PC",
                    "dept_code": "",
                    "is_unclassified": False,
                    "display_name": endpoint_user_name or key,
                }
            else:
                dept_name, dept_code = get_org_info_by_user(endpoint_user_name, endpoint_user_id, key)
                is_unclassified = False
                display_name = str(endpoint_user_name or "").strip()

                if not dept_name or dept_name == "미분류":
                    manual_dept = get_report_exception_dept(endpoint_user_name)
                    if not manual_dept:
                        manual_dept = get_report_exception_dept(key)
                    if manual_dept:
                        dept_name = manual_dept
                        dept_code = ""
                    else:
                        dept_name = "미분류"
                        if not display_name:
                            display_name = f"[NO_USER] {key}"
                        is_unclassified = True

                result = {
                    "user_name": endpoint_user_name,
                    "user_id": endpoint_user_id,
                    "user_type": user_type,
                    "dept_name": dept_name or "미분류",
                    "dept_code": dept_code or "",
                    "is_unclassified": is_unclassified,
                    "display_name": display_name,
                }

            identity_cache[cache_key] = result
            return result

        return resolve

    def build_dlp_overall_insight_lines(self, dlp_rows):
        if not dlp_rows:
            return ["DLP 이벤트가 확인되지 않았습니다."]

        AI_KW = [
            "openai", "chatgpt", "claude", "gemini", "copilot",
            "oaiusercontent", "bard", "perplexity",
            "ppl-ai-file-upload.s3.amazonaws.com",
            "clients6.google.com/upload",
            "aicreation.s3.ap-northeast-2.amazonaws.com"
        ]

        CLOUD_KW = [
            "drive", "dropbox", "onedrive", "sharepoint",
            "box.com", "notion", "confluence", "wetransfer",
            "mega", "icloud", "pcloud", "cloudflarestorage.com",
            "archisketch-resources.s3.ap-northeast-2.amazonaws.com",
            "sandollcloud.com"
        ]

        MESSENGER_TARGETS = {
            "kakaotalk",
            "nateon messenger",
            "naver line",
            "wechat",
            "viber",
            "messages",
            "whatsapp.root.dll",
        }

        MESSENGER_DEST_KW = [
            "files.slack.com",
            "app.slack.com",
            "www.instagram.com",
            "talk.naver.com",
            "media.channel.io",
            "chat.google.com",
        ]

        SENSITIVE_DOC_KW = [
            "신분증", "여권", "명함", "사업자", "사업자등록증",
            "통장사본", "계좌", "세금계산서", "임신확인서",
            "학자금", "잔액현황", "입금내역", "계약서"
        ]

        EXPENSE_KW = [
            "영수증", "거래확인증", "통행", "통행료", "주차", "주차료",
            "택배", "택시", "교통비", "식대", "회식", "접대비",
            "우편", "출장", "숙박", "환전", "주유", "로밍"
        ]

        AI_FILE_KW = [
            "chatgpt image", "gemini_generated_image", "claude", "/11_ai/"
        ]

        DESIGN_KW = [
            "배너", "banner", "thumb", "썸네일", "상세페이지", "누끼",
            "랜더링", "연출", "고화질", "promotion", "메인", "예고페이지",
            "스토리", "instagram", "인스타", "제품자료", "제품디자인",
            "시안", "팝업", "광고", "행사", "프로모션"
        ]

        MESSENGER_FILE_KW = [
            "kakaotalk_", "카카오톡 받은 파일", "네이트온 받은 파일",
            "viberdownloads", "xwechat_files", "whatsapp image",
            "messages/attachments", "wechat", "viber"
        ]

        VIDEO_EXT = {".mp4", ".mov", ".m4a", ".avi"}

        def norm(v):
            return str(v or "").strip()

        def low(v):
            return norm(v).lower()

        def kw_match(text, kw_list):
            t = low(text)
            return any(k in t for k in kw_list)

        def get_source_name(row):
            return (
                row.get("source")
                or row.get("source_name")
                or row.get("fileName")
                or row.get("filename")
                or ""
            )

        def extract_file_ext_for_report(path_text):
            s = str(path_text or "").strip().lower()

            if not s or s == "none":
                return ""

            # URL 파라미터/앵커 제거
            s = s.split("?", 1)[0]
            s = s.split("#", 1)[0]

            # 윈도우/리눅스 경로 구분자 통일
            s = s.replace("\\", "/")

            # 마지막 파일명만 추출
            filename = s.rsplit("/", 1)[-1].strip()

            if not filename or "." not in filename:
                return ""

            # 마지막 . 오른쪽만 확장자로 사용
            ext = filename.rsplit(".", 1)[-1].strip()

            # 확장자에 섞인 공백, 괄호, 제어문자 등 제거
            ext = re.sub(r"[^a-z0-9]+", "", ext)

            if not ext:
                return ""

            return f".{ext}"

        def get_target_name(row):
            return row.get("target") or row.get("destination") or ""

        def get_target_type(row):
            return row.get("targetType") or row.get("target_type") or row.get("destination_type") or ""

        def get_dest_detail(row):
            return (
                row.get("destinationDetails")
                or row.get("destination_details")
                or row.get("item_details")
                or ""
            )

        def classify_row(row):
            return classify_dlp_destination(
                get_target_name(row),
                get_target_type(row),
                get_dest_detail(row),
            )

        def classify_filename_detail(path_text):
            s = low(path_text)
            base = os.path.basename(norm(path_text))
            base_l = base.lower()
            ext = os.path.splitext(base_l)[1]

            # 우선순위 중요
            if any(k in s for k in SENSITIVE_DOC_KW):
                return "민감 개인 증빙 / 신분 관련"

            if any(k in s for k in EXPENSE_KW):
                return "영수증 / 정산 / 비용 증빙"

            if any(k in s for k in AI_FILE_KW):
                return "AI 생성 / AI 작업 결과물"

            if ext in VIDEO_EXT:
                return "영상 / 녹음 파일"

            if any(k in s for k in DESIGN_KW):
                return "상품 이미지 / 디자인 시안"

            if any(k in s for k in MESSENGER_FILE_KW):
                return "메신저 수신 이미지 / 외부 공유본"

            return "기타 이미지 / 파일"

        bucket_rows = defaultdict(list)
        for row in dlp_rows:
            if not isinstance(row, dict):
                continue
            category = classify_row(row)
            bucket_rows[category].append(row)

        ranked = sorted(
            bucket_rows.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:3]

        lines = []
        total_count = len(dlp_rows)

        for idx, (category, rows) in enumerate(ranked, 1):
            cnt = len(rows)

            detail_counter = Counter()
            dest_counter = Counter()
            ext_counter = Counter()

            for row in rows:
                src = norm(get_source_name(row))
                dest_detail = normalize_report_destination(get_dest_detail(row))
                ext = extract_file_ext_for_report(src)

                detail_label = classify_filename_detail(src)
                detail_counter[detail_label] += 1

                if dest_detail and dest_detail != "None":
                    dest_counter[dest_detail] += 1

                if ext:
                    ext_counter[ext] += 1

            block_lines = []
            block_lines.append(f"{category} (약 {cnt:,}건 / 전체 {round(cnt / total_count * 100, 1)}%)")

            top_details = detail_counter.most_common(3)
            if top_details:
                for label, sub_cnt in top_details:
                    block_lines.append(f"- {label} ({sub_cnt}건)")

            top_dests = dest_counter.most_common(2)
            if top_dests:
                dest_text = " / ".join([f"{name} ({d_cnt}건)" for name, d_cnt in top_dests])
                block_lines.append(f"- 주요 목적지: {dest_text}")

            top_exts = ext_counter.most_common(3)
            if top_exts:
                ext_text = " / ".join([f"{ext} ({e_cnt}건)" for ext, e_cnt in top_exts])
                block_lines.append(f"- 주요 확장자: {ext_text}")

            lines.append(block_lines)

        return lines

    def build_dlp_dept_insight_lines(self, dlp_dept_rank, metrics):
        if not dlp_dept_rank:
            return ["DLP 이벤트가 확인되지 않았습니다."]

        total_events = sum(d.get("total", 0) for d in dlp_dept_rank)
        lines = []

        AI_KW = [
            "openai", "chatgpt", "claude", "gemini", "copilot",
            "oaiusercontent", "bard", "perplexity",
            "ppl-ai-file-upload.s3.amazonaws.com",
            "clients6.google.com/upload",
            "aicreation.s3.ap-northeast-2.amazonaws.com"
        ]

        CLOUD_KW = [
            "drive", "dropbox", "onedrive", "sharepoint",
            "box.com", "notion", "confluence", "wetransfer",
            "mega", "icloud", "pcloud", "cloudflarestorage.com",
            "archisketch-resources.s3.ap-northeast-2.amazonaws.com",
            "sandollcloud.com"
        ]

        MESSENGER_TARGETS = {
            "kakaotalk",
            "nateon messenger",
            "naver line",
            "wechat",
            "viber",
            "messages",
            "whatsapp.root.dll",
        }

        MESSENGER_DEST_KW = [
            "files.slack.com",
            "app.slack.com",
            "www.instagram.com",
            "talk.naver.com",
            "media.channel.io",
        ]

        SENSITIVE_EXT = {
            ".xlsx", ".xls", ".csv", ".pdf", ".dwg",
            ".psd", ".ai", ".doc", ".docx", ".ppt",
            ".pptx", ".zip", ".7z", ".tar", ".sql"
        }

        def kw_match(text, kw_list):
            t = str(text or "").lower()
            return any(k in t for k in kw_list)

        def top_share(cnt, base):
            if not base:
                return 0.0
            return round(cnt / base * 100, 1)

        def normalize_text(value):
            return str(value or "").strip().lower()

        def is_ai(dest_detail):
            return kw_match(dest_detail, AI_KW)

        def is_messenger(target_name, dest_detail):
            t = normalize_text(target_name)
            d = normalize_text(dest_detail)
            return (t in MESSENGER_TARGETS) or kw_match(d, MESSENGER_DEST_KW)

        def is_mail(target_type, dest_detail):
            ttype = normalize_text(target_type)
            d = normalize_text(dest_detail)
            return ttype == "e-mail" or ("mail" in d)

        def is_cloud(target_name, target_type, dest_detail):
            t = normalize_text(target_name)
            ttype = normalize_text(target_type)
            d = normalize_text(dest_detail)

            if ttype == "cloud services / file sharing":
                return True
            if t in {"airdrop outgoing", "filezilla", "google drive file stream"}:
                return True
            if kw_match(d, CLOUD_KW):
                return True
            return False

        for rank, item in enumerate(dlp_dept_rank[:5], 1):
            dept_name = item.get("dept_name", "미분류")
            total = item.get("total", 0)
            blocked = item.get("blocked", 0)
            allowed = item.get("allowed", 0)
            block_ratio = item.get("block_ratio", 0.0)
            user_count = item.get("user_count", 0)
            machine_count = item.get("machine_count", 0)
            top_dests = item.get("top_dest_details", [])
            top_types = item.get("top_target_types", [])
            top_srcs = item.get("top_sources", [])
            top_dest_group_rows = item.get("top_dest_group_rows", [])

            share_pct = round(total / total_events * 100, 1) if total_events else 0.0

            header = (
                f"{rank}. {dept_name} | 총 {total}건 (전체 {share_pct}%) / "
                f"차단 {blocked}건 / 허용 {allowed}건 / 차단율 {block_ratio}%"
            )
            lines.append(header)

            if user_count > 0:
                avg_user = round(total / user_count, 1)
                if avg_user >= 100:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 소수 사용자 집중 발생 가능성 높음.")
                elif avg_user >= 50:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 반복 사용자 여부 확인 필요.")
                else:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 분산 발생 양상.")

            if machine_count > 0:
                avg_pc = round(total / machine_count, 1)
                if avg_pc >= 100:
                    lines.append(f"- PC당 평균 {avg_pc}건 — 특정 단말 집중 여부 점검 필요.")

            if block_ratio >= 90:
                lines.append("- 정책 차단률 90% 이상 — 통제가 효과적으로 작동 중이나 우회 시도 여부 병행 점검 권장.")
            elif block_ratio <= 10 and total >= 100:
                lines.append(f"- 차단율 {block_ratio}%로 낮음 — 정책 미적용 구간이거나 업무 예외 처리가 광범위하게 적용되고 있을 가능성.")

            classified_dests = []
            ai_related = False
            messenger_related = False
            mail_related = False
            cloud_related = False

            for group_row in top_dest_group_rows[:5]:
                target_name = str(group_row.get("target_text", "") or "")
                target_type = str(group_row.get("target_text", "") or "")
                dest_detail = str(group_row.get("dest_detail", "") or "")
                cnt = int(group_row.get("count", 0) or 0)

                category = classify_dlp_destination(target_name, target_type, dest_detail)

                if category == "AI/생성형AI":
                    ai_related = True
                elif category == "메신저/고객상담":
                    messenger_related = True
                elif category == "메일/대용량 첨부":
                    mail_related = True
                elif category == "클라우드/오브젝트 스토리지":
                    cloud_related = True

                if category != "웹 브라우저/기타":
                    classified_dests.append(f"{category}({dest_detail or target_name}) {cnt}건({top_share(cnt, total)}%)")

            if classified_dests:
                lines.append("- 주요 분류: " + " / ".join(classified_dests[:3]) + " — 민감 데이터 포함 여부 확인 필요.")

            type_flags = []
            for t_name, cnt in top_types[:3]:
                t_lower = str(t_name or "").lower()
                if "instant messaging" in t_lower:
                    type_flags.append(f"메신저({t_name}) {cnt}건")
                elif "e-mail" in t_lower:
                    type_flags.append(f"메일({t_name}) {cnt}건")
                elif "cloud services / file sharing" in t_lower:
                    type_flags.append(f"클라우드/파일공유({t_name}) {cnt}건")

            if type_flags:
                lines.append("- 주요 대상유형: " + " / ".join(type_flags))

            sensitive_files = []
            for src, cnt in top_srcs[:5]:
                src_str = str(src or "")
                _, ext = os.path.splitext(src_str.lower())
                if ext in SENSITIVE_EXT:
                    sensitive_files.append(f"{os.path.basename(src_str)} ({cnt}건)")

            if sensitive_files:
                lines.append("- 민감 파일 유형 포함: " + " / ".join(sensitive_files[:3]))

            sensitive_related = len(sensitive_files) > 0

            if ai_related and sensitive_related:
                lines.append("→ AI 서비스 + 민감 파일 조합 → 정보 유출 리스크 상위 점검 대상")
            elif ai_related:
                lines.append("→ AI 서비스 업로드 → 파일 내용 기준 추가 검토 필요")
            elif messenger_related and sensitive_related:
                lines.append("→ 메신저 + 민감 파일 조합 → 외부 전송 파일 추가 점검 필요")
            elif mail_related and sensitive_related:
                lines.append("→ 메일 + 민감 파일 조합 → 송신 파일 적정성 확인 필요")
            elif cloud_related and block_ratio < 30:
                lines.append("→ 클라우드/파일공유 비중 존재 + 낮은 차단율 → 정책 예외 범위 재검토 권장")

        return lines

    def build_dlp_destination_insight_rows(self, dlp_rows, dept_resolver=None):
        if not dlp_rows:
            return []

        def get_target_name(row):
            return row.get("target") or row.get("destination") or ""

        def get_target_type(row):
            return row.get("targetType") or row.get("target_type") or row.get("destination_type") or ""

        def get_dest_detail(row):
            return (
                row.get("destinationDetails")
                or row.get("destination_detail")
                or row.get("destination_details")
                or row.get("destination")
                or row.get("item_details")
                or ""
            )

        def get_source_name(row):
            return str(
                row.get("filename", "")
                or row.get("source", "")
                or row.get("source_name", "")
                or row.get("fileName", "")
                or row.get("item_name", "")
                or "None"
            ).strip()

        dept_cache = {}

        def resolve_dept(machine_name):
            key = str(machine_name or "").strip()
            if key in dept_cache:
                return dept_cache[key]

            if not key:
                dept_cache[key] = "미분류"
                return dept_cache[key]

            if dept_resolver:
                resolved = dept_resolver(key)
                if isinstance(resolved, dict):
                    dept_name = str(resolved.get("dept_name", "미분류") or "미분류")
                else:
                    dept_name = str(resolved or "미분류")
                dept_cache[key] = dept_name
                return dept_cache[key]

            endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(key)
            if user_type == "shared_pc":
                dept_name = "공용PC"
            else:
                dept_name, _ = get_org_info_by_user(endpoint_user_name, endpoint_user_id, key)
                if not dept_name or dept_name == "미분류":
                    dept_name = (
                        get_report_exception_dept(endpoint_user_name)
                        or get_report_exception_dept(key)
                        or "미분류"
                    )

            dept_cache[key] = dept_name or "미분류"
            return dept_cache[key]

        total_rows = 0
        category_stats = defaultdict(lambda: {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "destinations": defaultdict(lambda: {
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "departments": Counter(),
                "sources": Counter(),
                "target_types": Counter(),
            }),
        })

        for row in dlp_rows:
            if not isinstance(row, dict):
                continue

            raw_dest = get_dest_detail(row)
            dest_name = normalize_report_destination(raw_dest)
            if not dest_name or dest_name == "None":
                continue

            target_name = get_target_name(row)
            target_type = get_target_type(row)
            category = classify_dlp_destination(target_name, target_type, raw_dest)
            blocked = self.is_dlp_blocked_row(row)

            machine_name = str(row.get("machine_name", "") or "").strip()
            dept_name = resolve_dept(machine_name)
            source_name = get_source_name(row)

            total_rows += 1
            cat_stat = category_stats[category]
            cat_stat["total"] += 1
            cat_stat["blocked" if blocked else "allowed"] += 1

            dest_stat = cat_stat["destinations"][dest_name]
            dest_stat["total"] += 1
            dest_stat["blocked" if blocked else "allowed"] += 1

            if dept_name and dept_name != "None":
                dest_stat["departments"][dept_name] += 1
            if source_name and source_name != "None":
                dest_stat["sources"][source_name] += 1
            if target_type and target_type != "None":
                dest_stat["target_types"][str(target_type)] += 1

        category_rows = []
        for category, stat in sorted(category_stats.items(), key=lambda x: (-x[1]["total"], x[0]))[:5]:
            cat_total = stat["total"]
            dest_rows = []

            for dest_name, dest_stat in sorted(
                stat["destinations"].items(),
                key=lambda x: (-x[1]["total"], x[0])
            )[:5]:
                top_departments = dest_stat["departments"].most_common(3)
                department_total = sum(dest_stat["departments"].values())
                top_department_total = sum(cnt for _, cnt in top_departments)
                department_other_count = max(department_total - top_department_total, 0)
                department_other_dept_count = max(len(dest_stat["departments"]) - len(top_departments), 0)
                top_sources = [
                    (shorten_path_text(name, 34), cnt)
                    for name, cnt in dest_stat["sources"].most_common(3)
                ]

                dest_rows.append({
                    "destination": dest_name,
                    "total": dest_stat["total"],
                    "allowed": dest_stat["allowed"],
                    "blocked": dest_stat["blocked"],
                    "share": round((dest_stat["total"] / cat_total) * 100, 1) if cat_total else 0.0,
                    "top_departments": top_departments,
                    "department_other_count": department_other_count,
                    "department_other_dept_count": department_other_dept_count,
                    "top_sources": top_sources,
                    "top_target_types": dest_stat["target_types"].most_common(2),
                })

            category_rows.append({
                "category": category,
                "total": cat_total,
                "allowed": stat["allowed"],
                "blocked": stat["blocked"],
                "share": round((cat_total / total_rows) * 100, 1) if total_rows else 0.0,
                "top_destinations": dest_rows,
            })

        return category_rows

    def get_dlp_destination_category_comment(self, category, top_destination):
        dest = str(top_destination or "주요 목적지")
        comments = {
            "AI/생성형AI": f"{dest} 중심의 AI 서비스 사용이 확인됩니다. 업로드 파일에 개인정보·계약·영업자료가 포함됐는지 우선 점검하세요.",
            "문서/PDF/이미지 변환": f"{dest} 등 외부 변환 서비스 사용이 반복됩니다. 변환 대상 문서의 민감정보 포함 여부 확인이 필요합니다.",
            "메일/대용량 첨부": f"{dest} 대용량 첨부 사용이 확인됩니다. 정상 업무 여부와 외부 수신자 적정성을 파일명 기준으로 확인하세요.",
            "클라우드/오브젝트 스토리지": f"{dest} 스토리지 목적지가 확인됩니다. SaaS 임시 버킷 또는 외부 저장소 업로드 가능성을 점검하세요.",
            "메신저/고객상담": f"{dest} 메신저·고객상담 첨부 목적지가 확인됩니다. 고객응대 자료와 외부 공유 파일을 구분해 검토하세요.",
            "디자인/협업 SaaS": f"{dest} 디자인·협업 도구 사용이 확인됩니다. 시안·이미지·제안서 등 외부 업로드 파일을 확인하세요.",
            "소셜/미디어 업로드": f"{dest} 소셜·미디어 업로드 목적지가 확인됩니다. 공개 채널 업로드 여부와 파일 성격을 점검하세요.",
            "쇼핑몰/판매자/파트너 포털": f"{dest} 판매자·파트너 포털 목적지가 확인됩니다. 업무상 제출 파일인지 확인하고 반복 업로드를 점검하세요.",
            "채용/HR": f"{dest} 채용·HR 목적지가 확인됩니다. 이력서·증빙자료 등 개인정보 포함 파일 처리 적정성을 확인하세요.",
            "광고/마케팅/분석": f"{dest} 광고·마케팅·분석 목적지가 확인됩니다. 캠페인 소재나 고객 데이터 업로드 여부를 확인하세요.",
            "업무/공공/금융 포털": f"{dest} 업무·공공·금융 포털 목적지가 확인됩니다. 정상 제출 업무인지와 첨부파일의 민감도 확인이 필요합니다.",
            "내부 파일서버": f"{dest} 내부 파일서버 접근이 확인됩니다. 외부 반출보다 내부 공유 경로 사용 맥락을 확인하세요.",
            "로컬/앱 임시파일": f"{dest} 로컬 또는 앱 임시 경로가 확인됩니다. 실제 전송 대상과 원본 앱을 추가 확인하세요.",
            "IP 직접 접속": f"{dest} IP 직접 접속 목적지가 확인됩니다. 서비스 식별과 업무 관련성을 우선 확인하세요.",
        }
        return comments.get(category, f"{dest} 목적지 사용이 확인됩니다. 반복 발생 부서와 파일명을 기준으로 업무 적정성을 검토하세요.")

    def draw_dlp_destination_insights(self, c, y_pos, category_rows, rf, margin, content_w):
        from reportlab.pdfbase.pdfmetrics import stringWidth

        def wrap_cell_text(text, max_width, font_size=7, max_lines=2):
            text = str(text or "").strip()
            if not text:
                return [""]

            lines = []
            for raw_line in text.split("\n"):
                words = raw_line.split() or [raw_line]
                current = ""
                for word in words:
                    if stringWidth(word, rf, font_size) > max_width:
                        pieces = []
                        piece = ""
                        for ch in word:
                            if stringWidth(piece + ch, rf, font_size) <= max_width:
                                piece += ch
                            else:
                                if piece:
                                    pieces.append(piece)
                                piece = ch
                        if piece:
                            pieces.append(piece)
                    else:
                        pieces = [word]

                    for piece in pieces:
                        test = piece if not current else f"{current} {piece}"
                        if stringWidth(test, rf, font_size) <= max_width:
                            current = test
                        else:
                            if current:
                                lines.append(current)
                            current = piece
                if current:
                    lines.append(current)

            if max_lines and len(lines) > max_lines:
                lines = lines[:max_lines]
                suffix = "..."
                while lines[-1] and stringWidth(lines[-1] + suffix, rf, font_size) > max_width:
                    lines[-1] = lines[-1][:-1]
                lines[-1] = (lines[-1].rstrip() + suffix) if lines[-1] else suffix

            return lines or [""]

        def draw_table(headers, rows, col_widths, y_table, font_size=6.8, line_height=8):
            header_h = 19
            table_w = sum(col_widths)
            y_table = self.check_page(c, y_table, threshold=100, font_name=rf, font_size=font_size)
            table_top = y_table + 4

            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(margin + 1.4, y_table - header_h + 1.8, table_w, header_h, 5, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.roundRect(margin, y_table - header_h + 4, table_w, header_h, 5, fill=1, stroke=0)
            c.setFillGray(1)
            c.setFont(rf, font_size)
            ox = margin
            for h, cw in zip(headers, col_widths):
                c.drawString(ox + 4, y_table - 11, str(h))
                ox += cw
            c.setFillColor(colors.black)
            y_table -= header_h

            for ri, row in enumerate(rows):
                wrapped_cells = []
                max_lines = 1
                for val, cw in zip(row, col_widths):
                    wrapped = wrap_cell_text(val, cw - 7, font_size=font_size, max_lines=3)
                    wrapped_cells.append(wrapped)
                    max_lines = max(max_lines, len(wrapped))

                row_h = max(25, (max_lines * line_height) + 13)
                y_table = self.check_page(c, y_table, threshold=row_h + 45, font_name=rf, font_size=font_size)

                bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                c.setFillColor(bg)
                c.rect(margin, y_table - row_h + 4, table_w, row_h, fill=1, stroke=0)
                c.setFillColor(colors.HexColor("#111827"))
                c.setFont(rf, font_size)

                ox = margin
                for cell_lines, cw in zip(wrapped_cells, col_widths):
                    ty = y_table - 9
                    for line in cell_lines:
                        c.drawString(ox + 4, ty, line)
                        ty -= line_height
                    ox += cw

                c.setStrokeColor(colors.HexColor("#d6e4f5"))
                c.setLineWidth(0.45)
                c.line(margin, y_table - row_h + 4, margin + table_w, y_table - row_h + 4)
                y_table -= row_h

            c.setStrokeColor(colors.HexColor("#cfe1ff"))
            c.setLineWidth(0.65)
            c.roundRect(margin, y_table + 4, table_w, table_top - (y_table + 4), 5, fill=0, stroke=1)
            c.setStrokeColor(colors.black)
            return y_table - 10

        def draw_category_visual(rows, y_chart):
            if not rows:
                return y_chart

            chart_h = 152
            y_chart = self.check_page(c, y_chart, threshold=chart_h + 40, font_name=rf, font_size=8)
            card_x = margin
            card_y = y_chart - chart_h + 4
            card_w = content_w
            colors_palette = [
                colors.HexColor("#0b63ff"),
                colors.HexColor("#16a3a3"),
                colors.HexColor("#8b5cf6"),
                colors.HexColor("#f59e0b"),
                colors.HexColor("#ef4444"),
            ]

            # 프로그램 UI 톤과 맞춘 밝은 카드 + 부드러운 그림자
            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(card_x + 2.2, card_y - 2.2, card_w, chart_h, 10, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#ffffff"))
            c.roundRect(card_x, card_y, card_w, chart_h, 10, fill=1, stroke=0)
            c.setStrokeColor(colors.HexColor("#cfe1ff"))
            c.setLineWidth(0.7)
            c.roundRect(card_x, card_y, card_w, chart_h, 10, fill=0, stroke=1)

            c.setFont(rf, 8.4)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.drawString(card_x + 12, y_chart - 14, "Top 분류 시각화")
            c.setFont(rf, 7)
            c.setFillColor(colors.HexColor("#667085"))
            c.drawRightString(card_x + card_w - 12, y_chart - 14, "총건수 기준 / 허용·차단 포함")

            max_total = max(int(row.get("total", 0) or 0) for row in rows) or 1
            bar_x = card_x + 14
            bar_y = y_chart - 36
            label_w = 86
            bar_w = 190
            row_gap = 18

            for idx, row in enumerate(rows[:5]):
                total = int(row.get("total", 0) or 0)
                category = str(row.get("category", "-"))
                y_row = bar_y - idx * row_gap
                color = colors_palette[idx % len(colors_palette)]
                share_w = max(4, bar_w * total / max_total)

                c.setFont(rf, 6.8)
                c.setFillColor(colors.HexColor("#344054"))
                label = f"{idx + 1}. {category}"
                while stringWidth(label, rf, 6.8) > label_w and len(label) > 5:
                    label = label[:-2] + "…"
                c.drawString(bar_x, y_row, label)

                c.setFillColor(colors.HexColor("#eef4ff"))
                c.roundRect(bar_x + label_w, y_row - 5, bar_w, 7, 3, fill=1, stroke=0)
                c.setFillColor(color)
                c.roundRect(bar_x + label_w, y_row - 5, share_w, 7, 3, fill=1, stroke=0)
                c.setFillColor(colors.HexColor("#1f2937"))
                c.setFont(rf, 6.8)
                c.drawRightString(bar_x + label_w + bar_w + 42, y_row - 1, f"{total:,}건")

            pie_rows = rows[:5]
            pie_sum = sum(int(row.get("total", 0) or 0) for row in pie_rows) or 1
            cx = card_x + card_w - 96
            cy = card_y + 78
            radius = 42
            start_angle = 90
            for idx, row in enumerate(pie_rows):
                total = int(row.get("total", 0) or 0)
                extent = 360 * total / pie_sum
                c.setFillColor(colors_palette[idx % len(colors_palette)])
                c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, start_angle, extent, fill=1, stroke=0)
                start_angle += extent

            c.setFillColor(colors.white)
            c.circle(cx, cy, radius * 0.55, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.setFont(rf, 10)
            c.drawCentredString(cx, cy + 3, "TOP 5")
            c.setFillColor(colors.HexColor("#667085"))
            c.setFont(rf, 6.8)
            c.drawCentredString(cx, cy - 9, f"{pie_sum:,}건")
            c.setFillColor(colors.black)
            return y_chart - chart_h - 12

        if not category_rows:
            c.setFont(rf, 10)
            c.setFillColor(colors.black)
            c.drawString(margin + 6, y_pos, "DLP 목적지 데이터가 확인되지 않았습니다.")
            return y_pos - 18

        top_total = sum(int(row.get("total", 0) or 0) for row in category_rows)
        c.setFont(rf, 9)
        c.setFillColor(colors.HexColor("#374151"))
        c.drawString(margin + 6, y_pos, f"전체 DLP 목적지 중 총건수 상위 5개 분류를 표시합니다. (상위 분류 합계 {top_total:,}건)")
        y_pos -= 18

        y_pos = draw_category_visual(category_rows, y_pos)

        summary_rows = []
        for idx, row in enumerate(category_rows, 1):
            top_dest_text = ", ".join([
                f"{d.get('destination')}({d.get('total')})"
                for d in row.get("top_destinations", [])[:3]
            ]) or "-"
            summary_rows.append([
                str(idx),
                row.get("category", "-"),
                str(row.get("total", 0)),
                str(row.get("allowed", 0)),
                str(row.get("blocked", 0)),
                f"{row.get('share', 0.0)}%",
                top_dest_text,
            ])

        y_pos = draw_table(
            ["순위", "분류", "총", "허용", "차단", "비율", "주요 목적지"],
            summary_rows,
            [28, 112, 36, 36, 36, 42, content_w - 290],
            y_pos,
            font_size=7.0,
            line_height=8
        )

        for rank_idx, row in enumerate(category_rows, start=1):
            category = row.get("category", "-")
            total_count = int(row.get("total", 0) or 0)
            allowed = int(row.get("allowed", 0) or 0)
            blocked = int(row.get("blocked", 0) or 0)
            share = row.get("share", 0.0)
            top_destinations = row.get("top_destinations", [])
            top_destination = top_destinations[0].get("destination", "-") if top_destinations else "-"

            y_pos -= 20 if rank_idx > 1 else 10
            y_pos = self.check_page(c, y_pos, threshold=210, font_name=rf, font_size=9)
            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(margin + 2.4, y_pos - 33.4, content_w, 36, 10, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#f8fbff"))
            c.roundRect(margin, y_pos - 31, content_w, 36, 10, fill=1, stroke=0)
            c.setStrokeColor(colors.HexColor("#93c5fd"))
            c.setLineWidth(0.8)
            c.roundRect(margin, y_pos - 31, content_w, 36, 10, fill=0, stroke=1)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.roundRect(margin + 10, y_pos - 20, 48, 16, 8, fill=1, stroke=0)
            c.setFont(rf, 7.2)
            c.setFillColor(colors.white)
            c.drawCentredString(margin + 34, y_pos - 15, f"TOP {rank_idx}")
            c.setFont(rf, 9.2)
            c.setFillColor(colors.HexColor("#111827"))
            c.drawString(
                margin + 68,
                y_pos - 8,
                str(category)
            )
            c.setFont(rf, 7.2)
            c.setFillColor(colors.HexColor("#667085"))
            c.drawString(
                margin + 68,
                y_pos - 21,
                f"총 {total_count:,}건 · 허용 {allowed:,}건 · 차단 {blocked:,}건 · 전체 {share}%"
            )
            y_pos -= 43

            comment = self.get_dlp_destination_category_comment(category, top_destination)
            c.setFont(rf, 7.4)
            c.setFillColor(colors.HexColor("#374151"))
            for line in wrap_cell_text(comment, content_w - 12, font_size=7.4, max_lines=2):
                c.drawString(margin + 6, y_pos, line)
                y_pos -= 10
            y_pos -= 2

            dest_rows = []
            for dest in top_destinations[:5]:
                dept_lines = [f"{name}({cnt})" for name, cnt in dest.get("top_departments", [])]
                department_other_count = int(dest.get("department_other_count", 0) or 0)
                department_other_dept_count = int(dest.get("department_other_dept_count", 0) or 0)
                if department_other_count > 0:
                    dept_lines.append(f"외 {department_other_dept_count}개 부서({department_other_count})")
                dept_text = "\n".join(dept_lines) or "-"
                source_text = "\n".join([f"{name}({cnt})" for name, cnt in dest.get("top_sources", [])]) or "-"
                dest_rows.append([
                    dest.get("destination", "-"),
                    str(dest.get("total", 0)),
                    str(dest.get("allowed", 0)),
                    str(dest.get("blocked", 0)),
                    f"{dest.get('share', 0.0)}%",
                    dept_text,
                    source_text,
                ])

            y_pos = draw_table(
                ["목적지", "총", "허용", "차단", "비중", "주요 부서", "주요 파일"],
                dest_rows or [["-", "0", "0", "0", "0%", "-", "-"]],
                [118, 30, 30, 30, 44, 105, content_w - 357],
                y_pos,
                font_size=6.7,
                line_height=8
            )
            c.setStrokeColor(colors.HexColor("#dbeafe"))
            c.setLineWidth(1.2)
            c.line(margin + 8, y_pos + 2, margin + content_w - 8, y_pos + 2)
            c.setStrokeColor(colors.black)
            y_pos -= 34

        c.setFillColor(colors.black)
        return y_pos

    def draw_dlp_dept_insight_blocks(self, c, y_pos, blocks, rf, margin, content_w):
        if not blocks:
            return y_pos

        from reportlab.pdfbase.pdfmetrics import stringWidth

        def wrap_text(text, max_width, font_name=rf, font_size=10):
            text = str(text or "").strip()
            if not text:
                return [""]

            words = text.split()
            lines = []
            current = ""

            for word in words:
                test = word if not current else f"{current} {word}"
                if stringWidth(test, font_name, font_size) <= max_width:
                    current = test
                else:
                    if current:
                        lines.append(current)
                    current = word

            if current:
                lines.append(current)

            return lines or [""]

        c.setFont(rf, 10)

        for idx, block in enumerate(blocks, 1):
            if not block:
                continue

            # 현재 build_dlp_dept_insight_lines()는 block list 반환 구조
            if not isinstance(block, (list, tuple)):
                block = [str(block)]

            header = str(block[0] or "")
            sub_lines = [str(x or "") for x in block[1:]]

            # 페이지 여유 확인
            needed = 24 + (len(sub_lines) * 15) + 12
            y_pos = self.check_page(c, y_pos, threshold=max(needed, 120), font_name=rf, font_size=10)

            prefix = f"{idx}. "
            prefix_w = stringWidth(prefix, rf, 10)

            header_lines = wrap_text(header, content_w - 20 - prefix_w, rf, 10)

            # 제목
            c.drawString(margin + 8, y_pos, prefix + header_lines[0])
            y_pos -= 15

            for extra in header_lines[1:]:
                c.drawString(margin + 8 + prefix_w, y_pos, extra)
                y_pos -= 15

            # 하위 bullet
            for line in sub_lines:
                wrapped = wrap_text(line, content_w - 34, rf, 10)
                for sub in wrapped:
                    c.drawString(margin + 22, y_pos, sub)
                    y_pos -= 15

            y_pos -= 6

        return y_pos


    def generate_security_report_v2(self):
        self.start_security_report_worker()

    def start_security_report_worker(self):
        if getattr(self, "security_report_worker", None) and self.security_report_worker.isRunning():
            QMessageBox.information(self, "Report", "보고서 생성이 이미 진행 중입니다.")
            return

        start_dt = combine_date_time(self.report_start_date, self.report_start_time)
        end_dt = combine_date_time(self.report_end_date, self.report_end_time)

        self.security_report_worker = SecurityReportWorker(self._generate_security_report_v2, start_dt, end_dt, self)
        self.security_report_worker.progress.connect(self.on_security_report_progress)
        self.security_report_worker.completed.connect(self.on_security_report_finished)
        self.security_report_worker.failed.connect(self.on_security_report_failed)

        if hasattr(self, "btn_security_report"):
            self.btn_security_report.setEnabled(False)
            self.btn_security_report.setText("Generating Report...")
        self.statusBar().showMessage("보고서 생성 준비 중...")
        self.security_report_worker.start()

    def on_security_report_progress(self, message):
        self.statusBar().showMessage(str(message or "보고서 생성 중..."))

    def on_security_report_finished(self, pdf_path):
        if hasattr(self, "btn_security_report"):
            self.btn_security_report.setEnabled(True)
            self.btn_security_report.setText("Download Security Report (PDF)")
        self.statusBar().showMessage("보고서 생성 완료", 5000)
        QMessageBox.information(self, "완료", f"보고서 저장 완료\n{pdf_path}")
        try:
            os.startfile(pdf_path)
        except Exception:
            pass

    def on_security_report_failed(self, error_message):
        if hasattr(self, "btn_security_report"):
            self.btn_security_report.setEnabled(True)
            self.btn_security_report.setText("Download Security Report (PDF)")
        self.statusBar().showMessage("보고서 생성 실패", 5000)
        QMessageBox.critical(self, "오류", str(error_message or "보고서 생성 실패"))

    def _generate_security_report_v2(self, start_dt, end_dt, progress_cb=None):
        perf = ReportPerfTimer("security_report")

        def progress(message):
            log.info("[REPORT] %s", message)
            if progress_cb:
                progress_cb(message)

        try:
            progress("데이터 로딩 중...")
            os.makedirs(REPORT_DIR, exist_ok=True)

            start_date = start_dt.strftime("%Y-%m-%d")
            end_date = end_dt.strftime("%Y-%m-%d")

            endpoint_detections = load_endpoint_detections_by_range(start_date, end_date)
            xdr_detections_report = load_xdr_email_detections_by_range(start_date, end_date)
            emails = load_emails_by_range(start_date, end_date)
            mailscreen_rows = load_mailscreen_by_range(start_date, end_date)
            dlp_rows = load_dlp_by_range(start_date, end_date)
            perf.mark("load data")
            progress("DLP 분석 중...")
            report_identity_resolver = self.build_report_identity_resolver()

            dlp_total_count = len(dlp_rows)
            dlp_blocked_rows = [r for r in dlp_rows if self.is_dlp_blocked_row(r)]
            dlp_allowed_rows = [r for r in dlp_rows if not self.is_dlp_blocked_row(r)]

            dlp_blocked_count = len(dlp_blocked_rows)
            dlp_allowed_count = len(dlp_allowed_rows)

            dlp_blocked_pct = round((dlp_blocked_count / dlp_total_count) * 100, 1) if dlp_total_count else 0.0
            dlp_allowed_pct = round((dlp_allowed_count / dlp_total_count) * 100, 1) if dlp_total_count else 0.0

            detection_timeline = defaultdict(int)
            for d in endpoint_detections:
                if not isinstance(d, dict):
                    continue
                t = d.get("time")
                if t:
                    try:
                        dt  = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                        kst = dt.astimezone(timezone(timedelta(hours=9)))
                        detection_timeline[kst.strftime("%Y-%m-%d")] += 1
                    except Exception:
                        pass

            # ── Email - XDR 부서별 집계 ─────────────────────────────
            _xdr_dept_stats = defaultdict(lambda: {
                "total": 0,
                "rules": Counter(),
                "mailboxes": set(),
                "users": set(),
                "iocs": Counter(),
            })
            for _d in xdr_detections_report:
                if not isinstance(_d, dict):
                    continue
                _row_data = extract_xdr_email_fields(_d)
                _mailbox  = _row_data.get("mailbox", "")
                _rule_val = _row_data.get("rule", "")
                _ioc_val  = _row_data.get("ioc", "")
                _identity = resolve_identity_by_mailbox(_mailbox)
                _dept     = _identity.get("dept_name", "미분류") or "미분류"
                _stat     = _xdr_dept_stats[_dept]
                _stat["total"] += 1
                if _rule_val:
                    _stat["rules"][_rule_val] += 1
                if _mailbox and _mailbox != "None":
                    _stat["mailboxes"].add(_mailbox)
                _uname = _identity.get("user_name", "")
                if _uname and _uname != "None":
                    _stat["users"].add(_uname)
                if _ioc_val and _ioc_val != "None":
                    _stat["iocs"][_ioc_val] += 1

            xdr_dept_rank = sorted(
                [
                    {
                        "dept_name": _dn,
                        "total":     _st["total"],
                        "mailbox_count": len(_st["mailboxes"]),
                        "user_count":    len(_st["users"]),
                        "top_rules":     _st["rules"].most_common(3),
                        "top_iocs":      _st["iocs"].most_common(5),
                        "mailboxes_preview": sorted(list(_st["mailboxes"]))[:5],
                    }
                    for _dn, _st in _xdr_dept_stats.items()
                ],
                key=lambda x: (-x["total"], x["dept_name"])
            )

            # ── Outbound Mail(MailScreen) 부서/결재 집계 ─────────────────────────
            outbound_rows = []
            outbound_dept_stats = defaultdict(lambda: {
                "total": 0,
                "success": 0,
                "fail": 0,
                "approved": 0,
                "rejected": 0,
                "canceled": 0,
                "senders": set(),
                "receivers": Counter(),
                "policies": Counter(),
                "processes": Counter(),
            })
            outbound_process_counter = Counter()
            outbound_policy_counter = Counter()
            outbound_receiver_domain_counter = Counter()
            outbound_success_count = 0
            outbound_fail_count = 0

            def _outbound_receiver_domain(value):
                text = str(value or "").strip()
                if not text or text == "None":
                    return "None"
                first = text.split(",")[0].strip().split()[0].strip("<>()[];,")
                if "@" in first:
                    return first.rsplit("@", 1)[-1].lower() or "None"
                return "None"

            for _row in mailscreen_rows:
                if not isinstance(_row, dict):
                    continue
                _row = enrich_mailscreen_sender_fields(_row)
                _dt = timeline_parse_dt(_row.get("date"))
                if _dt and (_dt < start_dt or _dt > end_dt):
                    continue

                outbound_rows.append(_row)
                _dept = str(_row.get("sender_dept") or _row.get("dept") or "미분류").strip() or "미분류"
                _sender = str(_row.get("sender_name") or _row.get("sender_email") or _row.get("sender") or "None").strip()
                _send_result = str(_row.get("send_result") or "None").strip()
                _mail_process = str(_row.get("mail_process") or "None").strip()
                _policy = str(_row.get("policy") or "None").strip()
                _receiver_domain = _outbound_receiver_domain(_row.get("receiver_detail") or _row.get("receiver"))

                _stat = outbound_dept_stats[_dept]
                _stat["total"] += 1
                if _sender and _sender != "None":
                    _stat["senders"].add(_sender)
                if _receiver_domain != "None":
                    _stat["receivers"][_receiver_domain] += 1
                    outbound_receiver_domain_counter[_receiver_domain] += 1
                if _policy and _policy != "None":
                    _stat["policies"][_policy] += 1
                    outbound_policy_counter[_policy] += 1
                if _mail_process and _mail_process != "None":
                    _stat["processes"][_mail_process] += 1
                    outbound_process_counter[_mail_process] += 1

                if _send_result == "성공":
                    _stat["success"] += 1
                    outbound_success_count += 1
                elif _send_result == "실패":
                    _stat["fail"] += 1
                    outbound_fail_count += 1

                if "결재" in _mail_process and "승인" in _mail_process:
                    _stat["approved"] += 1
                elif "결재" in _mail_process and "반려" in _mail_process:
                    _stat["rejected"] += 1
                elif "결재" in _mail_process and "취소" in _mail_process:
                    _stat["canceled"] += 1

            outbound_dept_rank = sorted(
                [
                    {
                        "dept_name": _dept,
                        "total": _st["total"],
                        "success": _st["success"],
                        "fail": _st["fail"],
                        "approved": _st["approved"],
                        "rejected": _st["rejected"],
                        "canceled": _st["canceled"],
                        "sender_count": len(_st["senders"]),
                        "top_policies": _st["policies"].most_common(3),
                        "top_receivers": _st["receivers"].most_common(3),
                        "top_processes": _st["processes"].most_common(3),
                    }
                    for _dept, _st in outbound_dept_stats.items()
                ],
                key=lambda x: (-x["total"], x["dept_name"])
            )
            outbound_approval_rows = [
                {"status": "결재(승인)", "total": sum(int(x.get("approved", 0) or 0) for x in outbound_dept_rank)},
                {"status": "결재(반려)", "total": sum(int(x.get("rejected", 0) or 0) for x in outbound_dept_rank)},
                {"status": "결재(취소)", "total": sum(int(x.get("canceled", 0) or 0) for x in outbound_dept_rank)},
            ]
            outbound_approval_rows = [x for x in outbound_approval_rows if int(x.get("total", 0) or 0) > 0]

            perf.mark("pre-metrics aggregation")
            metrics = self.build_security_insight_metrics(
                endpoint_detections,
                emails,
                dlp_rows,
                detection_timeline,
                report_identity_resolver=report_identity_resolver,
            )
            perf.mark("security metrics")
            progress("PDF 생성 중...")
            dlp_dept_rank        = metrics.get("dlp_dept_rank", [])
            dlp_dept_block_rank  = metrics.get("dlp_dept_block_rank", [])
            unclassified_user_counts = metrics.get("unclassified_user_counts", [])
            det_dept_rank        = metrics.get("det_dept_rank", [])
            selected_days = max((end_dt.date() - start_dt.date()).days + 1, 1)

            risk = self.build_security_risk_assessment(metrics, selected_days=selected_days)
            insight_lines = self.build_security_insight_lines(metrics)
            action_items = self.build_security_action_items(metrics, risk)
            manager_summary = self.build_security_manager_summary(metrics, risk)
            score_breakdown = risk.get("score_breakdown", [])

            cross_host_count       = metrics.get("cross_host_count", 0)
            cross_host_ratio       = metrics.get("cross_host_ratio", 0.0)
            overlap_day_count      = metrics.get("overlap_day_count", 0)
            triple_overlap_count   = metrics.get("triple_overlap_count", 0)
            repeated_cross_count   = metrics.get("repeated_cross_host_count", 0)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            pdf_path = os.path.join(
                REPORT_DIR,
                f"Security_Report_{start_date}_{end_date}.pdf"
            )
            pdf_path = get_unique_path(pdf_path)

            c          = canvas.Canvas(pdf_path, pagesize=A4)
            PAGE_W, _  = A4
            rf         = self.setup_report_font()
            perf.mark("pdf setup")
            MARGIN     = 45
            CONTENT_W  = PAGE_W - MARGIN * 2   # ≈ 505pt

            # ── 공통 헬퍼 ────────────────────────────────────────
            page_state = {"number": 1}
            theme = {
                "page_bg": colors.HexColor("#f8fbff"),
                "primary": colors.HexColor("#005ce6"),
                "primary_dark": colors.HexColor("#174ea6"),
                "border": colors.HexColor("#bfdbfe"),
                "shadow": colors.HexColor("#d8e8f6"),
                "text": colors.HexColor("#111827"),
                "muted": colors.HexColor("#667085"),
                "card": colors.white,
            }

            def draw_page_background():
                c.saveState()
                c.setFillColor(theme["page_bg"])
                c.rect(0, 0, PAGE_W, A4[1], fill=1, stroke=0)
                c.restoreState()

            def draw_soft_card(x, y_top, w, h, radius=10, fill=None, stroke=None, shadow=True):
                fill = fill or theme["card"]
                stroke = stroke or theme["border"]
                if shadow:
                    c.setFillColor(theme["shadow"])
                    c.roundRect(x + 2.4, y_top - h - 2.6, w, h, radius, fill=1, stroke=0)
                c.setFillColor(fill)
                c.roundRect(x, y_top - h, w, h, radius, fill=1, stroke=0)
                c.setStrokeColor(stroke)
                c.setLineWidth(0.65)
                c.roundRect(x, y_top - h, w, h, radius, fill=0, stroke=1)

            def draw_page_footer():
                c.saveState()
                c.setFont(rf, 7)
                c.setFillColor(theme["muted"])
                c.drawCentredString(PAGE_W / 2, 24, f"- {page_state['number']} -")
                c.restoreState()

            def after_show_page():
                page_state["number"] += 1
                draw_page_background()
                c.setFont(rf, 10)
                c.setFillColor(theme["text"])

            draw_page_background()
            c._smu_report_draw_footer = draw_page_footer
            c._smu_report_after_show_page = after_show_page

            def new_page():
                draw_page_footer()
                c.showPage()
                after_show_page()
                return 810

            def section_bar(title, y_pos):
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(MARGIN + 1.8, y_pos - 24.2, CONTENT_W, 24, 8, fill=1, stroke=0)
                c.setFillColor(theme["primary_dark"])
                c.roundRect(MARGIN, y_pos - 22, CONTENT_W, 24, 8, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, 11)
                c.drawString(MARGIN + 10, y_pos - 14, title)
                c.setFillColor(theme["text"])
                return y_pos - 38

            def numbered_list(lines, y_pos, indent=MARGIN + 10):
                c.setFont(rf, 10)

                def wrap_by_width(text, max_width, font_name=rf, font_size=10):
                    text = str(text or "").strip()
                    if not text:
                        return [""]

                    words = text.split()
                    wrapped = []
                    current = ""

                    for word in words:
                        test = word if not current else f"{current} {word}"
                        if c.stringWidth(test, font_name, font_size) <= max_width:
                            current = test
                        else:
                            if current:
                                wrapped.append(current)
                            current = word

                    if current:
                        wrapped.append(current)

                    return wrapped or [""]

                for i, item in enumerate(lines, 1):
                    y_pos = self.check_page(c, y_pos, threshold=140, font_name=rf, font_size=10)

                    if isinstance(item, list):
                        block_lines = [str(x or "") for x in item]
                    else:
                        block_lines = [str(item or "")]

                    prefix = f"{i}. "
                    prefix_w = c.stringWidth(prefix, rf, 10)

                    first_lines = wrap_by_width(block_lines[0], CONTENT_W - 20 - prefix_w, rf, 10)
                    c.drawString(indent, y_pos, prefix + first_lines[0])
                    y_pos -= 15

                    for extra in first_lines[1:]:
                        c.drawString(indent + prefix_w, y_pos, extra)
                        y_pos -= 15

                    for sub in block_lines[1:]:
                        sub_lines = wrap_by_width(sub, CONTENT_W - 30 - prefix_w, rf, 10)

                        for idx, extra in enumerate(sub_lines):
                            if idx == 0:
                                c.drawString(indent + prefix_w + 4, y_pos, extra)
                            else:
                                c.drawString(indent + prefix_w + 12, y_pos, extra)
                            y_pos -= 15

                    y_pos -= 10

                return y_pos

            def mini_table(x, y_pos, headers, rows, col_widths, font_size=9):
                """앱 UI 톤의 헤더+행 소형 테이블 (페이지 넘김 없음)."""
                from reportlab.pdfbase.pdfmetrics import stringWidth

                row_h = 19
                total_w = sum(col_widths)
                table_top = y_pos + 4

                # 헤더: DLP 목적지 인사이트와 동일한 파란 라운드 스타일
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(x + 1.3, y_pos - row_h + 1.6, total_w, row_h, 5, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.roundRect(x, y_pos - row_h + 4, total_w, row_h, 5, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, font_size)
                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw
                c.setFillColor(theme["text"])
                y_pos -= row_h

                # 행
                for ri, row in enumerate(rows):
                    bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)
                    ox = x
                    for val, cw in zip(row, col_widths):
                        text = str(val)
                        while stringWidth(text, rf, font_size) > cw - 8 and len(text) > 3:
                            text = text[:-2] + "…"
                        c.drawString(ox + 4, y_pos - 11, text)
                        ox += cw
                    c.setStrokeColor(colors.HexColor("#d6e4f5"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)
                    y_pos -= row_h

                c.setStrokeColor(colors.HexColor("#cfe1ff"))
                c.setLineWidth(0.65)
                c.roundRect(x, y_pos + 4, total_w, table_top - (y_pos + 4), 5, fill=0, stroke=1)
                c.setStrokeColor(colors.black)
                return y_pos - 8

            def mini_table_multiline(x, y_pos, headers, rows, col_widths, font_size=8, line_height=11):
                def wrap_cell_text(text, max_width, max_lines=None):
                    from reportlab.pdfbase.pdfmetrics import stringWidth

                    def split_long_token(token, width):
                        parts = []
                        current = ""
                        for ch in token:
                            test = current + ch
                            if stringWidth(test, rf, font_size) <= width:
                                current = test
                            else:
                                if current:
                                    parts.append(current)
                                current = ch
                        if current:
                            parts.append(current)
                        return parts or [""]

                    def ellipsize_to_width(text_value, width):
                        text_value = str(text_value or "").rstrip()
                        if stringWidth(text_value, rf, font_size) <= width:
                            return text_value

                        suffix = "..."
                        out = text_value
                        while out and stringWidth(out + suffix, rf, font_size) > width:
                            out = out[:-1]

                        return (out.rstrip() + suffix) if out else suffix

                    lines = []

                    for raw_line in str(text or "").split("\n"):
                        raw_line = str(raw_line).strip()
                        if not raw_line:
                            lines.append("")
                            continue

                        words = raw_line.split()
                        current = ""

                        if not words:
                            lines.append("")
                            continue

                        for word in words:
                            if stringWidth(word, rf, font_size) > max_width:
                                pieces = split_long_token(word, max_width)
                            else:
                                pieces = [word]

                            for piece in pieces:
                                test = piece if not current else f"{current} {piece}"
                                if stringWidth(test, rf, font_size) <= max_width:
                                    current = test
                                else:
                                    if current:
                                        lines.append(current)
                                    current = piece

                        if current:
                            lines.append(current)

                    if not lines:
                        lines = [""]

                    if max_lines and len(lines) > max_lines:
                        lines = lines[:max_lines]
                        lines[-1] = ellipsize_to_width(lines[-1], max_width)

                    return lines

                header_h = 19
                total_w = sum(col_widths)
                table_top = y_pos + 4
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(x + 1.3, y_pos - header_h + 1.6, total_w, header_h, 5, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.roundRect(x, y_pos - header_h + 4, total_w, header_h, 5, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, font_size)
                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw
                c.setFillColor(theme["text"])
                y_pos -= header_h

                for ri, row in enumerate(rows):
                    wrapped_cells = []
                    max_lines = 1

                    for col_idx, (val, cw) in enumerate(zip(row, col_widths)):
                        if col_idx == 0:      # 소스
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=5)
                        elif col_idx == 1:    # 분류/대상유형
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=5)
                        elif col_idx == 2:    # 목적지 세부정보
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=1)
                        else:                 # 건수
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=1)

                        wrapped_cells.append(wrapped)
                        max_lines = max(max_lines, len(wrapped))

                    row_h = max(26, (max_lines * line_height) + 16)

                    if y_pos - row_h < 40:
                        y_pos = new_page()
                        table_top = y_pos + 4

                        c.setFillColor(colors.HexColor("#dbeafe"))
                        c.roundRect(x + 1.3, y_pos - header_h + 1.6, total_w, header_h, 5, fill=1, stroke=0)
                        c.setFillColor(theme["primary"])
                        c.roundRect(x, y_pos - header_h + 4, total_w, header_h, 5, fill=1, stroke=0)
                        c.setFillGray(1)
                        c.setFont(rf, font_size)

                        ox = x
                        for h, cw in zip(headers, col_widths):
                            c.drawString(ox + 4, y_pos - 11, str(h))
                            ox += cw

                        c.setFillColor(theme["text"])
                        y_pos -= header_h

                    bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)

                    ox = x
                    for cell_lines, cw in zip(wrapped_cells, col_widths):
                        text_block_h = max(1, len(cell_lines)) * line_height
                        top_padding = max(4, (row_h - text_block_h) / 2)
                        text_block_h = len(cell_lines) * line_height
                        ty = y_pos - ((row_h - text_block_h) / 2) - 1

                        for line in cell_lines:
                            c.drawString(ox + 4, ty, str(line))
                            ty -= line_height

                        ox += cw

                    c.setStrokeColor(colors.HexColor("#d6e4f5"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)
                    y_pos -= row_h

                c.setStrokeColor(colors.HexColor("#cfe1ff"))
                c.setLineWidth(0.65)
                c.roundRect(x, y_pos + 4, total_w, table_top - (y_pos + 4), 5, fill=0, stroke=1)
                c.setStrokeColor(colors.black)
                return y_pos - 8


            def mini_table_fixed(x, y_pos, headers, rows, col_widths, font_size=6.8, row_h=20):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                total_w = sum(col_widths)

                def fit_text(text, max_width):
                    text = str(text or "").replace("\n", " / ").strip()
                    if not text:
                        return "-"

                    if stringWidth(text, rf, font_size) <= max_width:
                        return text

                    ell = "…"
                    usable = max_width - stringWidth(ell, rf, font_size)
                    if usable <= 8:
                        return ell

                    out = ""
                    for ch in text:
                        test = out + ch
                        if stringWidth(test, rf, font_size) > usable:
                            break
                        out = test

                    return (out.rstrip() + ell) if out else ell

                # 헤더
                c.setFillColor(colors.HexColor("#2f5ea8"))
                c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)

                c.setFont(rf, font_size)
                c.setFillColor(colors.white)

                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw

                # 헤더 세로선
                c.setStrokeColor(colors.white)
                c.setLineWidth(0.4)
                ox = x
                for cw in col_widths[:-1]:
                    ox += cw
                    c.line(ox, y_pos - row_h + 4, ox, y_pos + 4)

                c.setFillColor(colors.black)
                c.setStrokeColor(colors.HexColor("#c7d3e3"))
                y_pos -= row_h

                # 본문
                for ri, row in enumerate(rows):
                    bg = colors.HexColor("#f7f9fc") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)

                    ox = x
                    c.setFont(rf, font_size)
                    c.setFillColor(colors.black)

                    for idx, (val, cw) in enumerate(zip(row, col_widths)):
                        text = fit_text(val, cw - 8)

                        if idx == len(col_widths) - 1:
                            # 건수는 우측 정렬
                            tw = stringWidth(text, rf, font_size)
                            c.drawString(ox + cw - tw - 4, y_pos - 11, text)
                        else:
                            c.drawString(ox + 4, y_pos - 11, text)

                        ox += cw

                    # 세로선
                    ox = x
                    for cw in col_widths[:-1]:
                        ox += cw
                        c.setStrokeColor(colors.HexColor("#d6deea"))
                        c.setLineWidth(0.35)
                        c.line(ox, y_pos - row_h + 4, ox, y_pos + 4)

                    # 가로선
                    c.setStrokeColor(colors.HexColor("#d6deea"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)

                    y_pos -= row_h

                return y_pos - 6

            def draw_distribution_card(title, rows, y_pos, *, label_key="dept_name", value_key="total",
                                       subtitle="총건수 기준", empty_text="데이터가 확인되지 않았습니다."):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                rows = [r for r in (rows or []) if int(r.get(value_key, 0) or 0) > 0][:5]
                card_h = 150
                y_pos = self.check_page(c, y_pos, threshold=card_h + 48, font_name=rf, font_size=8)
                if not rows:
                    draw_soft_card(MARGIN, y_pos, CONTENT_W, 44, radius=10, fill=theme["card"], stroke=theme["border"], shadow=True)
                    c.setFont(rf, 8.5)
                    c.setFillColor(theme["muted"])
                    c.drawString(MARGIN + 12, y_pos - 24, empty_text)
                    c.setFillColor(theme["text"])
                    return y_pos - 58

                draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=12, fill=theme["card"], stroke=theme["border"], shadow=True)
                palette = [
                    colors.HexColor("#0b63ff"),
                    colors.HexColor("#16a3a3"),
                    colors.HexColor("#8b5cf6"),
                    colors.HexColor("#f59e0b"),
                    colors.HexColor("#ef4444"),
                ]
                c.setFont(rf, 8.5)
                c.setFillColor(theme["primary"])
                c.drawString(MARGIN + 14, y_pos - 16, title)
                c.setFont(rf, 7)
                c.setFillColor(theme["muted"])
                c.drawRightString(MARGIN + CONTENT_W - 14, y_pos - 16, subtitle)

                max_total = max(int(row.get(value_key, 0) or 0) for row in rows) or 1
                total_sum = sum(int(row.get(value_key, 0) or 0) for row in rows) or 1
                bar_x = MARGIN + 16
                bar_y = y_pos - 40
                label_w = 104
                bar_w = 178
                row_gap = 18

                for idx, row in enumerate(rows):
                    value = int(row.get(value_key, 0) or 0)
                    label = str(row.get(label_key, "-") or "-")
                    y_row = bar_y - idx * row_gap
                    color = palette[idx % len(palette)]
                    display = f"{idx + 1}. {label}"
                    while stringWidth(display, rf, 6.8) > label_w and len(display) > 5:
                        display = display[:-2] + "…"
                    c.setFont(rf, 6.8)
                    c.setFillColor(colors.HexColor("#344054"))
                    c.drawString(bar_x, y_row, display)
                    c.setFillColor(colors.HexColor("#eef4ff"))
                    c.roundRect(bar_x + label_w, y_row - 5, bar_w, 7, 3, fill=1, stroke=0)
                    c.setFillColor(color)
                    c.roundRect(bar_x + label_w, y_row - 5, max(4, bar_w * value / max_total), 7, 3, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.drawRightString(bar_x + label_w + bar_w + 48, y_row - 1, f"{value:,}건")

                cx = MARGIN + CONTENT_W - 92
                cy = y_pos - 78
                radius = 41
                start_angle = 90
                for idx, row in enumerate(rows):
                    value = int(row.get(value_key, 0) or 0)
                    extent = 360 * value / total_sum
                    c.setFillColor(palette[idx % len(palette)])
                    c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, start_angle, extent, fill=1, stroke=0)
                    start_angle += extent
                c.setFillColor(theme["card"])
                c.circle(cx, cy, radius * 0.55, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.setFont(rf, 9.5)
                c.drawCentredString(cx, cy + 3, "TOP 5")
                c.setFillColor(theme["muted"])
                c.setFont(rf, 6.8)
                c.drawCentredString(cx, cy - 9, f"{total_sum:,}건")
                c.setFillColor(theme["text"])
                return y_pos - card_h - 18

            def draw_rank_header(rank, title, meta, y_pos, *, accent=None):
                y_pos = self.check_page(c, y_pos, threshold=76, font_name=rf, font_size=8)
                accent = accent or theme["primary"]
                draw_soft_card(MARGIN, y_pos, CONTENT_W, 38, radius=11, fill=colors.HexColor("#f8fbff"), stroke=colors.HexColor("#93c5fd"), shadow=True)
                c.setFillColor(accent)
                c.roundRect(MARGIN + 10, y_pos - 24, 52, 17, 8.5, fill=1, stroke=0)
                c.setFillColor(colors.white)
                c.setFont(rf, 7.2)
                c.drawCentredString(MARGIN + 36, y_pos - 18.5, f"TOP {rank}")
                c.setFillColor(theme["text"])
                c.setFont(rf, 9.2)
                c.drawString(MARGIN + 72, y_pos - 12, str(title))
                c.setFillColor(theme["muted"])
                c.setFont(rf, 7.2)
                c.drawString(MARGIN + 72, y_pos - 26, str(meta))
                c.setFillColor(theme["text"])
                return y_pos - 48

            def wrap_report_text(text, max_width, font_size=8, font_name=None):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                font_name = font_name or rf
                text = str(text or "").strip()
                if not text:
                    return [""]
                lines = []
                for raw_line in text.split("\n"):
                    words = raw_line.split() or [raw_line]
                    current = ""
                    for word in words:
                        pieces = [word]
                        if stringWidth(word, font_name, font_size) > max_width:
                            pieces = []
                            piece = ""
                            for ch in word:
                                if stringWidth(piece + ch, font_name, font_size) <= max_width:
                                    piece += ch
                                else:
                                    if piece:
                                        pieces.append(piece)
                                    piece = ch
                            if piece:
                                pieces.append(piece)
                        for piece in pieces:
                            test = piece if not current else f"{current} {piece}"
                            if stringWidth(test, font_name, font_size) <= max_width:
                                current = test
                            else:
                                if current:
                                    lines.append(current)
                                current = piece
                    if current:
                        lines.append(current)
                return lines or [""]

            def draw_numbered_card_list(items, y_pos, *, accent=None, chip_prefix="", font_size=8.1):
                accent = accent or theme["primary"]
                for idx, item in enumerate(items or [], start=1):
                    if isinstance(item, (list, tuple)):
                        header = str(item[0] if item else "")
                        details = [str(x) for x in item[1:] if str(x or "").strip()]
                    else:
                        header = str(item or "")
                        details = []
                    if chip_prefix:
                        header = re.sub(r"^\d+\.\s*", "", header).strip()

                    chip_w = 46 if chip_prefix else 28
                    header_lines = wrap_report_text(header, CONTENT_W - chip_w - 56, font_size=font_size)
                    detail_lines = []
                    for detail in details:
                        bullet = detail if detail.lstrip().startswith(("-", "→")) else f"- {detail}"
                        detail_lines.extend(wrap_report_text(bullet, CONTENT_W - 42, font_size=7.2))

                    card_h = max(34, 18 + len(header_lines) * 10 + len(detail_lines) * 9 + (4 if detail_lines else 0))
                    y_pos = self.check_page(c, y_pos, threshold=card_h + 54, font_name=rf, font_size=font_size)
                    draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=10, fill=theme["card"], stroke=theme["border"], shadow=True)

                    chip_text = f"{chip_prefix}{idx}" if chip_prefix else str(idx)
                    c.setFillColor(accent)
                    c.roundRect(MARGIN + 10, y_pos - 24, chip_w, 16, 8, fill=1, stroke=0)
                    c.setFillColor(colors.white)
                    c.setFont(rf, 7)
                    c.drawCentredString(MARGIN + 10 + chip_w / 2, y_pos - 18.5, chip_text)

                    text_x = MARGIN + chip_w + 20
                    text_y = y_pos - 14
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)
                    for line in header_lines:
                        c.drawString(text_x, text_y, line)
                        text_y -= 10

                    if detail_lines:
                        text_y -= 2
                        c.setFillColor(theme["muted"])
                        c.setFont(rf, 7.2)
                        for line in detail_lines:
                            c.drawString(MARGIN + 18, text_y, line)
                            text_y -= 9

                    c.setFillColor(theme["text"])
                    y_pos -= card_h + 9
                return y_pos

            def draw_insight_block_cards(blocks, y_pos, *, accent=None):
                return draw_numbered_card_list(blocks, y_pos, accent=accent or theme["primary"], chip_prefix="TOP ", font_size=8.1)

            def draw_risk_score_card(y_pos):
                card_h = 74
                y_pos = self.check_page(c, y_pos, threshold=card_h + 50, font_name=rf, font_size=8)
                draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=13, fill=theme["card"], stroke=theme["border"], shadow=True)
                c.setFillColor(theme["primary"])
                c.roundRect(MARGIN + 14, y_pos - 28, 58, 18, 9, fill=1, stroke=0)
                c.setFillColor(colors.white)
                c.setFont(rf, 8)
                c.drawCentredString(MARGIN + 43, y_pos - 22, str(risk_level))

                c.setFillColor(theme["text"])
                c.setFont(rf, 18)
                c.drawString(MARGIN + 86, y_pos - 24, f"{risk_score}/100점")
                c.setFont(rf, 8)
                c.setFillColor(theme["muted"])
                c.drawString(MARGIN + 86, y_pos - 40, f"선택 기간 {selected_days}일 기준 종합 위험도")

                summary = (risk.get("factors", []) or ["주요 위험 요인을 기준으로 산정되었습니다."])[0]
                summary_lines = wrap_report_text(summary, CONTENT_W - 236, font_size=7.6)[:2]
                c.setFont(rf, 7.6)
                for idx, line in enumerate(summary_lines):
                    c.drawRightString(MARGIN + CONTENT_W - 16, y_pos - 22 - idx * 12, line)
                c.setFillColor(theme["text"])
                return y_pos - card_h - 18

            def summary_mini_card(x, y_pos, w, h, title, value, sub_text="", accent=None):
                accent = accent or colors.HexColor("#eef5ff")
                draw_soft_card(x, y_pos, w, h, radius=9, fill=accent, stroke=theme["border"], shadow=True)

                c.setFillColor(theme["primary_dark"])
                c.setFont(rf, 8)
                c.drawString(x + 10, y_pos - 15, str(title))

                c.setFillColor(theme["text"])
                c.setFont(rf, 18)
                c.drawString(x + 10, y_pos - 36, str(value))

                if sub_text:
                    c.setFillColor(theme["muted"])
                    c.setFont(rf, 7)
                    c.drawString(x + 10, y_pos - 49, str(sub_text))

                c.setFillColor(theme["text"])

            # ═══════════════════════════════════════════════════
            # PAGE 1 — 커버
            # ═══════════════════════════════════════════════════
            y = 810

            # 제목
            c.setFont(rf, 25)
            c.setFillColor(theme["text"])
            c.drawString(MARGIN, y, "보안 분석 보고서")
            c.setFillColor(theme["primary"])
            c.roundRect(MARGIN, y - 11, 74, 3, 1.5, fill=1, stroke=0)
            y -= 28
            c.setFont(rf, 9)
            c.setFillColor(theme["muted"])
            c.drawString(MARGIN, y, f"분석 기간: {start_dt.strftime('%Y-%m-%d %H:%M')} ~ {end_dt.strftime('%Y-%m-%d %H:%M')}")
            c.setFillColor(theme["text"])
            y -= 24

            # 리스크 카드
            risk_level = risk.get("level", "LOW")
            risk_score = risk.get("score", 0)
            rc = {
                "CRITICAL": colors.HexColor("#991b1b"),
                "HIGH": colors.HexColor("#dc2626"),
                "MEDIUM": colors.HexColor("#f59e0b"),
                "LOW": colors.HexColor("#10b981"),
            }.get(risk_level, colors.HexColor("#64748b"))
            draw_soft_card(MARGIN, y, CONTENT_W, 72, radius=12, fill=rc, stroke=rc, shadow=True)
            c.setFillGray(1)
            c.setFont(rf, 10)
            c.drawString(MARGIN + 16, y - 18, "종합 위험도")
            c.setFont(rf, 28)
            c.drawString(MARGIN + 16, y - 54, str(risk_level))
            c.setFont(rf, 24)
            c.drawRightString(MARGIN + CONTENT_W - 18, y - 54, f"Score: {risk_score}/100")
            c.setFillColor(theme["text"])
            y -= 88

            # 숫자 카드 3개
            card_data = [
                ("Endpoint Detection", metrics.get("endpoint_detection_count", 0), colors.HexColor("#1d4ed8")),
                ("Email Events",       metrics.get("email_count", 0),              colors.HexColor("#0f766e")),
                ("DLP Events",         metrics.get("dlp_count", 0),                colors.HexColor("#92400e")),
            ]
            cw_card = (CONTENT_W - 12) / 3
            for i, (ct, cv, cc) in enumerate(card_data):
                cx = MARGIN + i * (cw_card + 6)
                draw_soft_card(cx, y, cw_card, 70, radius=11, fill=cc, stroke=cc, shadow=True)
                c.setFillGray(1)
                c.setFont(rf, 8.2)
                c.drawString(cx + 11, y - 18, ct)
                c.setFont(rf, 27)
                c.drawString(cx + 11, y - 53, f"{int(cv):,}" if isinstance(cv, int) else str(cv))
                c.setFillColor(theme["text"])
            y -= 84

            # 교차 호스트 배너
            cross_hosts = metrics.get("cross_hosts", [])
            if cross_hosts:
                draw_soft_card(MARGIN, y, CONTENT_W, 48, radius=10, fill=colors.HexColor("#fff4d6"), stroke=colors.HexColor("#fde68a"), shadow=True)
                c.setFillColorRGB(0.65, 0.28, 0.0)
                c.setFont(rf, 9)
                c.drawString(MARGIN + 8, y - 14, "⚠  Detection + DLP 동시 발생 호스트")
                c.setFillGray(0.15)
                c.setFont(rf, 9)
                hosts_txt = ",   ".join(cross_hosts[:6])
                c.drawString(MARGIN + 8, y - 30, hosts_txt)
                c.setFillGray(0)
                y -= 56

            # 상관분석 미니 카드
            mini_gap = 6
            mini_w = (CONTENT_W - (mini_gap * 3)) / 4
            mini_h = 54

            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 0,
                y,
                mini_w,
                mini_h,
                "교차 호스트",
                f"{cross_host_count}",
                "Detection + DLP"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 1,
                y,
                mini_w,
                mini_h,
                "교차 비율",
                f"{cross_host_ratio}%",
                "탐지 호스트 기준"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 2,
                y,
                mini_w,
                mini_h,
                "동시 발생일",
                f"{overlap_day_count}",
                "Detection + DLP"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 3,
                y,
                mini_w,
                mini_h,
                "3종 동시일",
                f"{triple_overlap_count}",
                "Det + Email + DLP"
            )

            y -= (mini_h + 14)

            repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])

            if repeated_cross_count > 0:
                if repeated_cross_hosts_preview:
                    preview = ", ".join(repeated_cross_hosts_preview)
                    msg = f"반복 교차 호스트 {repeated_cross_count}개 확인 — {preview}"
                else:
                    msg = f"반복 교차 호스트 {repeated_cross_count}개 확인 — 단발성보다 반복형 패턴 점검 필요"

                words = str(msg).split()
                wrapped_msg = []
                current = ""

                for word in words:
                    test = word if not current else f"{current} {word}"
                    if c.stringWidth(test, rf, 8) <= (CONTENT_W - 16):
                        current = test
                    else:
                        if current:
                            wrapped_msg.append(current)
                        current = word

                if current:
                    wrapped_msg.append(current)

                if not wrapped_msg:
                    wrapped_msg = [msg]

                line_h = 10
                box_h = max(24, len(wrapped_msg) * line_h + 12)

                draw_soft_card(MARGIN, y + 2, CONTENT_W, box_h, radius=8, fill=colors.HexColor("#f1f6ff"), stroke=theme["border"], shadow=False)

                c.setFillColorRGB(0.28, 0.38, 0.56)
                c.setFont(rf, 8)

                text_y = y - 12
                for line in wrapped_msg:
                    c.drawString(MARGIN + 8, text_y, line)
                    text_y -= line_h

                c.setFillGray(0)

                # 박스 높이 + 아래 여백 확보
                y -= (box_h + 10)

            # 관리자 요약 — 핵심 항목만 카드형으로 요약
            y = section_bar("관리자 요약", y)

            manager_highlights = [
                f"총 이벤트: Detection {metrics.get('endpoint_detection_count', 0):,}건 / Email {metrics.get('email_count', 0):,}건 / DLP {metrics.get('dlp_count', 0):,}건",
            ]
            if metrics.get("top_host"):
                manager_highlights.append(
                    f"최다 탐지 호스트: {metrics.get('top_host')} ({metrics.get('top_host_count', 0):,}건)"
                )
            if metrics.get("top_rule"):
                manager_highlights.append(
                    f"주요 탐지 룰: {metrics.get('top_rule')} ({metrics.get('top_rule_count', 0):,}건)"
                )
            top_dlp_dept = metrics.get("top_dlp_dept", {}) or {}
            if top_dlp_dept:
                manager_highlights.append(
                    f"DLP 최다 부서: {top_dlp_dept.get('dept_name', '미분류')} ({top_dlp_dept.get('total', 0):,}건)"
                )
            if cross_host_count > 0:
                manager_highlights.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count:,}개 — 우선 점검 대상"
                )
            if triple_overlap_count > 0:
                manager_highlights.append(
                    f"Detection·Email·DLP 3종 동시 발생일 {triple_overlap_count:,}일 확인"
                )

            # 과도한 문장형 설명 대신 한눈에 보는 결론 5개만 표시한다.
            y = draw_numbered_card_list(manager_highlights[:5], y, accent=theme["primary"], font_size=7.8)
            y -= 4

            # ═══════════════════════════════════════════════════
            # PAGE 2 — 그래프 (전체 너비) + 3개 테이블 나란히
            # ═══════════════════════════════════════════════════
            y = new_page()

            # 탐지 추이 그래프 — 전체 너비
            graph_path = os.path.join(REPORT_DIR, f"trend_{ts}.png")
            if detection_timeline:
                saved = self.create_report_trend_graph(detection_timeline, graph_path, font_name=rf)
                if saved:
                    c.setFont(rf, 13)
                    c.drawString(MARGIN, y, "탐지 추이")
                    y -= 8
                    GH = 220
                    c.drawImage(saved, MARGIN, y - GH, width=CONTENT_W, height=GH)
                    y -= GH + 20

            # 3개 테이블 나란히 (Rules | Hosts | Files)
            top_rules = metrics.get("top_rules", [])
            top_hosts = metrics.get("top_hosts", [])
            top_files = metrics.get("top_files", [])
            cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
            overlap_day_count = metrics.get("overlap_day_count", 0)
            triple_overlap_count = metrics.get("triple_overlap_count", 0)
            repeated_cross_count = metrics.get("repeated_cross_host_count", 0)

            TW = (CONTENT_W - 16) / 3   # 각 테이블 전체 너비
            CNT_W = 30                   # Count 열 너비
            NAME_W = TW - CNT_W          # 이름 열 너비

            table_defs = [
                ("Top Rules",  top_rules, ["Rule",     "Cnt"], [NAME_W, CNT_W]),
                ("Top Hosts",  top_hosts, ["Hostname", "Cnt"], [NAME_W, CNT_W]),
                ("Top Files",  top_files, ["File",     "Cnt"], [NAME_W, CNT_W]),
            ]

            ty = y
            for ti, (title, data, hdrs, cws) in enumerate(table_defs):
                tx = MARGIN + ti * (TW + 8)
                c.setFont(rf, 11)
                c.drawString(tx, ty, title)
                rows = [(name, str(cnt)) for name, cnt in data] if data else [("No Data", "-")]
                mini_table(tx, ty - 10, hdrs, rows, cws, font_size=8)

            # 페이지 2 하단 상관분석 요약
            info_y = ty - 128

            c.setFillColorRGB(0.95, 0.97, 1.0)
            c.roundRect(MARGIN, info_y - 18, CONTENT_W, 22, 5, fill=1, stroke=0)
            c.setFillColorRGB(0.18, 0.32, 0.56)
            c.setFont(rf, 8)
            c.drawString(
                MARGIN + 8,
                info_y - 11,
                f"상관분석 요약 ①  Detection + DLP 교차 비율 {cross_host_ratio}% / 동시 발생일 {overlap_day_count}일"
            )

            c.setFillColorRGB(0.96, 0.97, 0.99)
            c.roundRect(MARGIN, info_y - 46, CONTENT_W, 22, 5, fill=1, stroke=0)
            c.setFillColorRGB(0.28, 0.38, 0.56)
            c.setFont(rf, 8)
            c.drawString(
                MARGIN + 8,
                info_y - 39,
                f"상관분석 요약 ②  3종 동시 발생일 {triple_overlap_count}일 / 반복 교차 호스트 {repeated_cross_count}개"
            )
            c.setFillGray(0)

            # ═══════════════════════════════════════════════════
            # PAGE 3 — 위험도 + 인사이트 + 권장 조치
            # ═══════════════════════════════════════════════════
            y = new_page()

            # 위험도 평가
            y = section_bar("위험도 평가", y)
            y = draw_risk_score_card(y)

            risk_factors = risk.get("factors", [])
            if risk_factors:
                c.setFont(rf, 9)
                c.setFillColor(theme["primary_dark"])
                c.drawString(MARGIN + 6, y, "핵심 위험 요인")
                c.setFillColor(theme["text"])
                y -= 14
                y = draw_numbered_card_list(risk_factors, y, accent=colors.HexColor("#f59e0b"), font_size=7.8)
                y -= 16

            # 점수 산정 기준
            if score_breakdown:
                y = self.check_page(c, y, threshold=145, font_name=rf, font_size=8)
                c.setFont(rf, 9)
                c.setFillColor(theme["primary_dark"])
                c.drawString(MARGIN + 6, y, f"점수 산정 기준 (선택 기간 {selected_days}일 기준)")
                c.setFillColor(theme["text"])
                y -= 12

                score_rows = []
                for item in score_breakdown:
                    label = str(item.get("label", ""))
                    item_score = item.get("score", 0)
                    max_score = item.get("max_score", "")
                    score_display = str(item.get("score_display", "") or (f"{item_score}/{max_score}" if max_score else f"+{item_score}"))
                    detail = str(item.get("detail", ""))
                    interpretation = str(item.get("interpretation", "") or "")
                    detail_text = f"{detail}\n→ {interpretation}" if interpretation else detail
                    score_rows.append([label, score_display, detail_text])

                y = mini_table_multiline(
                    MARGIN,
                    y,
                    ["평가 영역", "점수", "근거 및 해석"],
                    score_rows,
                    [118, 42, CONTENT_W - 160],
                    font_size=7.0,
                    line_height=8
                )
                y -= 8

            # 주요 인사이트는 별도 페이지에서 시작해 섹션 경계를 명확히 한다.
            y = new_page()
            y = section_bar("주요 인사이트", y)
            y = draw_numbered_card_list(insight_lines, y, accent=theme["primary"], font_size=7.8)

            # 권장 조치도 별도 페이지에서 시작한다.
            y = new_page()
            y = section_bar("권장 조치", y)
            y = draw_numbered_card_list(action_items, y, accent=colors.HexColor("#16a3a3"), font_size=7.8)

            # ═══════════════════════════════════════════════════
            # PAGE Detection — Detection 부서별 분석
            # ═══════════════════════════════════════════════════
            # Detection 전체 현황은 권장 조치 다음 새 페이지에서 시작한다.
            if det_dept_rank:
                y = new_page()

                # Detection 전체 현황 요약
                y = section_bar("Detection 전체 현황", y)
                c.setFont(rf, 10)
                total_det_cnt  = metrics.get("endpoint_detection_count", 0)
                unique_hosts   = metrics.get("unique_host_count", 0)
                unique_rules   = metrics.get("unique_rule_count", 0)
                unique_files   = metrics.get("unique_file_count", 0)
                c.drawString(
                    MARGIN + 6, y,
                    f"Endpoint Detection 총 {total_det_cnt:,}건  /  탐지 호스트 {unique_hosts}개  "
                    f"/  탐지 룰 {unique_rules}종  /  연관 파일 {unique_files}종"
                )
                y -= 18
                y = draw_distribution_card(
                    "Detection 부서 Top 5 시각화",
                    det_dept_rank,
                    y,
                    subtitle="탐지건수 기준 / 상위 부서 합계",
                )

                # Detection 부서별 현황 테이블
                y = section_bar("Detection 부서별 현황", y)

                det_summary_rows = []
                for item in det_dept_rank[:5]:
                    det_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("host_count", 0)),
                        str(item.get("user_count", 0)),
                    ])

                y = mini_table(
                    MARGIN, y,
                    ["부서", "탐지건수", "호스트수", "사용자수"],
                    det_summary_rows,
                    [220, 100, 100, 85],
                    font_size=8
                )
                y -= 10

                y = section_bar("Detection 상위 부서 상세", y)

                for di, item in enumerate(det_dept_rank[:5], start=1):
                    dept_name  = item.get("dept_name", "미분류")
                    total      = item.get("total", 0)
                    host_count = item.get("host_count", 0)
                    user_count = item.get("user_count", 0)
                    top_rules  = item.get("top_rules", [])
                    top_files  = item.get("top_files", [])
                    hosts_prev = item.get("hosts_preview", [])

                    y = self.check_page(c, y, threshold=160, font_name=rf, font_size=8)

                    y = draw_rank_header(
                        di,
                        dept_name,
                        f"탐지 {total:,}건 · 호스트 {host_count:,}개 · 사용자 {user_count:,}명",
                        y,
                    )

                    # Top Rules 미니 테이블
                    rule_rows = [
                        [r, str(cnt)]
                        for r, cnt in top_rules
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 탐지 룰", "건수"],
                        rule_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # Top Files 미니 테이블
                    file_rows = [
                        [f, str(cnt)]
                        for f, cnt in top_files
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 연관 파일", "건수"],
                        file_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # 호스트 미리보기
                    if hosts_prev:
                        c.setFont(rf, 7.5)
                        c.setFillColor(colors.HexColor("#374151"))
                        preview_text = "주요 호스트: " + ", ".join(hosts_prev)
                        c.drawString(MARGIN + 6, y, preview_text)
                        y -= 14

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE XDR — Email - XDR 부서별 분석
            # ═══════════════════════════════════════════════════
            if xdr_dept_rank:
                y = new_page()

                y = section_bar("Email - XDR 전체 현황", y)
                c.setFont(rf, 10)
                total_xdr_cnt = len(xdr_detections_report)
                c.drawString(
                    MARGIN + 6, y,
                    f"Email - XDR 총 {total_xdr_cnt:,}건  /  부서 {len(xdr_dept_rank)}개"
                )
                y -= 18
                y = draw_distribution_card(
                    "Email - XDR 부서 Top 5 시각화",
                    xdr_dept_rank,
                    y,
                    subtitle="탐지건수 기준 / 상위 부서 합계",
                )

                y = section_bar("Email - XDR 부서별 현황", y)

                xdr_summary_rows = []
                for item in xdr_dept_rank[:5]:
                    xdr_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("mailbox_count", 0)),
                        str(item.get("user_count", 0)),
                    ])

                y = mini_table(
                    MARGIN, y,
                    ["부서", "탐지건수", "메일박스수", "사용자수"],
                    xdr_summary_rows,
                    [220, 100, 100, 85],
                    font_size=8
                )
                y -= 10

                y = section_bar("Email - XDR 상위 부서 상세", y)

                for xi, item in enumerate(xdr_dept_rank[:5], start=1):
                    dept_name     = item.get("dept_name", "미분류")
                    total         = item.get("total", 0)
                    mailbox_count = item.get("mailbox_count", 0)
                    user_count    = item.get("user_count", 0)
                    top_rules     = item.get("top_rules", [])
                    top_iocs      = item.get("top_iocs", [])
                    mb_preview    = item.get("mailboxes_preview", [])

                    y = self.check_page(c, y, threshold=200, font_name=rf, font_size=8)

                    y = draw_rank_header(
                        xi,
                        dept_name,
                        f"탐지 {total:,}건 · 메일박스 {mailbox_count:,}개 · 사용자 {user_count:,}명",
                        y,
                    )

                    # Top Rules
                    rule_rows = [
                        [r, str(cnt)]
                        for r, cnt in top_rules
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 탐지 룰", "건수"],
                        rule_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # Top IOCs
                    if top_iocs:
                        ioc_rows = [
                            [ioc_val, str(cnt)]
                            for ioc_val, cnt in top_iocs
                        ]
                        y = mini_table_multiline(
                            MARGIN, y,
                            ["주요 IOC", "건수"],
                            ioc_rows,
                            [430, 75],
                            font_size=6.8,
                            line_height=9
                        )
                        y -= 4

                    # 메일박스 미리보기
                    if mb_preview:
                        c.setFont(rf, 7.5)
                        c.setFillColor(colors.HexColor("#374151"))
                        c.drawString(MARGIN + 6, y, "주요 메일박스: " + ", ".join(mb_preview))
                        y -= 14

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE Outbound Mail — MailScreen 부서/결재 분석
            # ═══════════════════════════════════════════════════
            if outbound_rows:
                y = new_page()

                y = section_bar("Outbound Mail 전체 현황", y)
                c.setFont(rf, 10)
                outbound_total_count = len(outbound_rows)
                approval_total = sum(int(x.get("total", 0) or 0) for x in outbound_approval_rows)
                c.drawString(
                    MARGIN + 6,
                    y,
                    f"Outbound Mail 총 {outbound_total_count:,}건  /  성공 {outbound_success_count:,}건  "
                    f"/  실패 {outbound_fail_count:,}건  /  결재 {approval_total:,}건"
                )
                y -= 18

                y = draw_distribution_card(
                    "Outbound Mail 부서 Top 5 시각화",
                    outbound_dept_rank,
                    y,
                    subtitle="발송건수 기준 / 상위 부서 합계",
                )

                if outbound_approval_rows:
                    y = draw_distribution_card(
                        "Outbound Mail 결재 처리 현황",
                        outbound_approval_rows,
                        y,
                        label_key="status",
                        value_key="total",
                        subtitle="승인·반려·취소 건수",
                    )

                y = section_bar("Outbound Mail 부서별 현황", y)

                outbound_summary_rows = []
                for item in outbound_dept_rank[:5]:
                    outbound_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("success", 0)),
                        str(item.get("fail", 0)),
                        str(item.get("approved", 0)),
                        str(item.get("rejected", 0)),
                        str(item.get("canceled", 0)),
                    ])

                y = mini_table(
                    MARGIN,
                    y,
                    ["부서", "총건수", "성공", "실패", "승인", "반려", "취소"],
                    outbound_summary_rows,
                    [160, 62, 56, 56, 56, 56, 59],
                    font_size=7.3
                )
                y -= 10

                y = section_bar("Outbound Mail 결재 인사이트", y)
                approval_summary_rows = [[
                    "결재(승인)",
                    str(sum(int(x.get("approved", 0) or 0) for x in outbound_dept_rank)),
                    "승인 절차를 거쳐 외부 발송된 정책 대상 메일",
                ], [
                    "결재(반려)",
                    str(sum(int(x.get("rejected", 0) or 0) for x in outbound_dept_rank)),
                    "승인 단계에서 외부 발송이 반려된 메일",
                ], [
                    "결재(취소)",
                    str(sum(int(x.get("canceled", 0) or 0) for x in outbound_dept_rank)),
                    "요청 후 취소되어 실제 발송으로 이어지지 않은 메일",
                ]]
                y = mini_table_multiline(
                    MARGIN,
                    y,
                    ["결재 상태", "건수", "해석"],
                    approval_summary_rows,
                    [95, 50, CONTENT_W - 145],
                    font_size=7.2,
                    line_height=9
                )
                y -= 10

                y = section_bar("Outbound Mail 상위 부서 상세", y)

                for oi, item in enumerate(outbound_dept_rank[:5], start=1):
                    dept_name = item.get("dept_name", "미분류")
                    total = item.get("total", 0)
                    success = item.get("success", 0)
                    fail = item.get("fail", 0)
                    approved = item.get("approved", 0)
                    rejected = item.get("rejected", 0)
                    canceled = item.get("canceled", 0)

                    y = self.check_page(c, y, threshold=185, font_name=rf, font_size=8)
                    y = draw_rank_header(
                        oi,
                        dept_name,
                        f"총 {total:,}건 · 성공 {success:,}건 · 실패 {fail:,}건 · 승인 {approved:,}건 · 반려 {rejected:,}건 · 취소 {canceled:,}건",
                        y,
                    )

                    policy_rows = [[name, str(cnt)] for name, cnt in item.get("top_policies", [])] or [["-", "0"]]
                    y = mini_table(
                        MARGIN,
                        y,
                        ["주요 정책", "건수"],
                        policy_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    receiver_rows = [[name, str(cnt)] for name, cnt in item.get("top_receivers", [])] or [["-", "0"]]
                    y = mini_table(
                        MARGIN,
                        y,
                        ["주요 수신 도메인", "건수"],
                        receiver_rows,
                        [430, 75],
                        font_size=7
                    )

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE 4 — DLP 부서 분석
            # ═══════════════════════════════════════════════════
            if dlp_dept_rank:
                y = new_page()

                # =========================
                # DLP 전체 상위 3개 분석
                # =========================
                y = section_bar("DLP 전체 유형 분석", y)

                c.setFont(rf, 10)
                c.drawString(
                    MARGIN + 6,
                    y,
                    f"DLP 전체 총 건수 : {dlp_total_count:,}건 (차단 {dlp_blocked_pct}%, 탐지 {dlp_allowed_pct}%)"
                )
                y -= 18

                overall_dlp_lines = self.build_dlp_overall_insight_lines(dlp_allowed_rows)
                y = draw_insight_block_cards(overall_dlp_lines, y, accent=theme["primary"])
                y -= 8

                # 목적지별 인사이트를 DLP 상세 앞쪽에 배치해, 주요 유출 경로를 먼저 확인하도록 구성한다.
                y = new_page()
                y = section_bar("DLP 목적지별 인사이트", y)
                dlp_destination_rows = self.build_dlp_destination_insight_rows(
                    dlp_rows,
                    dept_resolver=report_identity_resolver,
                )
                perf.mark("dlp destination insights build")
                y = self.draw_dlp_destination_insights(c, y, dlp_destination_rows, rf, MARGIN, CONTENT_W)
                perf.mark("dlp destination insights render")

                y = new_page()
                y = section_bar("DLP 부서별 현황", y)
                c.setFont(rf, 9)
                c.setFillColor(colors.HexColor("#374151"))
                c.drawString(MARGIN + 6, y, "DLP 이벤트가 집중된 상위 부서를 시각화하고, 허용/차단 및 사용자·PC 분포를 함께 확인합니다.")
                y -= 18
                y = draw_distribution_card(
                    "DLP 부서 Top 5 시각화",
                    dlp_dept_rank,
                    y,
                    subtitle="총건수 기준 / 허용·차단 포함",
                )

                dept_rows = []
                for item in dlp_dept_rank[:5]:
                    dept_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("blocked", 0)),
                        f"{item.get('block_ratio', 0.0)}%",
                        str(item.get("user_count", 0)),
                        str(item.get("machine_count", 0)),
                    ])

                y = mini_table(
                    MARGIN,
                    y,
                    ["부서", "총건수", "차단", "차단율", "사용자수", "PC수"],
                    dept_rows,
                    [180, 70, 55, 65, 70, 65],
                    font_size=8
                )

                y -= 10
                y = section_bar("DLP 상위 부서 상세", y)

                inner_x = MARGIN
                inner_w = CONTENT_W

                # 부서명 바와 표 폭 완전히 동일
                detail_col_widths = [205, 120, inner_w - 205 - 120 - 36, 36]

                for dept_idx, item in enumerate(dlp_dept_rank[:5], start=1):
                    dept_name = item.get("dept_name", "미분류")
                    total = item.get("total", 0)
                    blocked = item.get("blocked", 0)
                    block_ratio = item.get("block_ratio", 0.0)
                    top_dest_group_rows = item.get("top_dest_group_rows", [])

                    y = self.check_page(c, y, threshold=150, font_name=rf, font_size=8)

                    allowed = max(total - blocked, 0)
                    y = draw_rank_header(
                        dept_idx,
                        dept_name,
                        f"총 {total:,}건 · 허용 {allowed:,}건 · 차단 {blocked:,}건 · 차단율 {block_ratio}% · 상세목록 허용 기준",
                        y,
                    )

                    dept_rows = []
                    if not top_dest_group_rows:
                        dept_rows.append(["-", "-", "-", "0"])
                    else:
                        for group_row in top_dest_group_rows[:3]:
                            dept_rows.append([
                                str(group_row.get("source_text", "-")),
                                str(group_row.get("target_text", "-")),
                                str(group_row.get("dest_detail", "-")),
                                str(group_row.get("count", 0)),
                            ])

                    y = mini_table_multiline(
                        inner_x,
                        y,
                        ["소스", "분류/대상유형", "목적지 세부정보", "건수"],
                        dept_rows,
                        detail_col_widths,
                        font_size=6.8,
                        line_height=8
                    )

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 26

                # DLP 상위 부서 상세 종료 후 인사이트/부록 페이지로 넘김
                y = new_page()

                y = section_bar("DLP 부서 분석 인사이트", y)
                dlp_insight_lines = self.build_dlp_dept_insight_lines(dlp_dept_rank, metrics)
                y = draw_insight_block_cards(dlp_insight_lines, y, accent=theme["primary"])

                if unclassified_user_counts:
                    y = self.check_page(c, y - 8, threshold=170, font_name=rf, font_size=8)
                    y = section_bar("DLP 미분류 사용자", y)

                    compact_rows = []
                    preview_users = unclassified_user_counts[:16]
                    for i in range(0, len(preview_users), 2):
                        left_name, left_cnt = preview_users[i]
                        left = f"{i + 1}. {left_name} ({left_cnt}건)"
                        right = ""
                        if i + 1 < len(preview_users):
                            right_name, right_cnt = preview_users[i + 1]
                            right = f"{i + 2}. {right_name} ({right_cnt}건)"
                        compact_rows.append([left, right])

                    y = mini_table_multiline(
                        MARGIN,
                        y,
                        ["미분류 사용자/호스트", "미분류 사용자/호스트"],
                        compact_rows,
                        [CONTENT_W / 2, CONTENT_W / 2],
                        font_size=7.2,
                        line_height=9
                    )

                    c.setFont(rf, 8)
                    c.setFillColor(colors.HexColor("#6b7280"))
                    if len(unclassified_user_counts) > len(preview_users):
                        c.drawString(
                            MARGIN,
                            y,
                            f"외 {len(unclassified_user_counts) - len(preview_users)}명 추가"
                        )
                        y -= 12
                    c.setFillColor(colors.black)


            draw_page_footer()
            c.save()
            perf.mark("pdf save")
            progress("저장 완료")
            perf.finish()
            return pdf_path

        except Exception:
            log.exception("generate_security_report_v2 failed")
            raise

    def normalize_logical_tab_name(self, tab_name):
        return self.logical_tab_aliases.get(str(tab_name or ""), str(tab_name or ""))

    def hide_all_subtab_bars(self):
        for bar in getattr(self, "group_subtab_bars", {}).values():
            if bar.graphicsEffect():
                bar.graphicsEffect().setEnabled(False)
            bar.hide()

    def is_child_of_widget(self, widget, parent):
        while widget is not None:
            if widget is parent:
                return True
            widget = widget.parentWidget() if hasattr(widget, "parentWidget") else None
        return False

    def eventFilter(self, obj, event):
        if event.type() == QEvent.MouseButtonPress:
            visible_bars = [
                bar for bar in getattr(self, "group_subtab_bars", {}).values()
                if bar.isVisible()
            ]
            if visible_bars and isinstance(obj, QWidget):
                tab_bar = self.tabs.tabBar() if hasattr(self, "tabs") else None
                clicked_subtab = any(self.is_child_of_widget(obj, bar) for bar in visible_bars)
                clicked_top_tab = tab_bar is not None and self.is_child_of_widget(obj, tab_bar)
                if not clicked_subtab and not clicked_top_tab:
                    self.hide_all_subtab_bars()
        return super().eventFilter(obj, event)

    def fade_subtab_bar(self, bar, show):
        if not bar:
            return
        effect = bar.graphicsEffect()
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(bar)
            bar.setGraphicsEffect(effect)
        effect.setEnabled(True)

        anim = QPropertyAnimation(effect, b"opacity", bar)
        anim.setDuration(130 if show else 90)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.setStartValue(0.0 if show else effect.opacity())
        anim.setEndValue(1.0 if show else 0.0)

        if show:
            bar.move(0, 0)
            bar.raise_()
            effect.setOpacity(0.0)
            bar.show()
        else:
            def finish_hide():
                bar.hide()
                effect.setOpacity(1.0)
                effect.setEnabled(False)
            anim.finished.connect(finish_hide)

        bar._subtab_fade_animation = anim
        anim.start()

    def set_subtab_bar_visible(self, parent_idx, visible):
        bar = getattr(self, "group_subtab_bars", {}).get(parent_idx)
        if not bar:
            return
        if visible:
            self.hide_all_subtab_bars()
            self.sync_group_subtab_buttons(parent_idx)
            self.fade_subtab_bar(bar, True)
        else:
            self.fade_subtab_bar(bar, False)

    def sync_group_subtab_buttons(self, parent_idx):
        active_child_idx = None
        for _logical_name, location in getattr(self, "logical_tab_locations", {}).items():
            _parent_tabs, location_parent_idx, stack, child_idx = location
            if location_parent_idx == parent_idx and stack is not None:
                active_child_idx = stack.currentIndex()
                break
        bar = getattr(self, "group_subtab_bars", {}).get(parent_idx)
        if bar is None or active_child_idx is None:
            return
        buttons = bar.findChildren(QPushButton)
        for idx, btn in enumerate(buttons):
            btn.setChecked(idx == active_child_idx)

    def on_top_tab_clicked(self, index):
        self.set_subtab_bar_visible(index, index in getattr(self, "group_subtab_bars", {}))

    def on_top_tab_changed(self, index):
        self.set_subtab_bar_visible(index, index in getattr(self, "group_subtab_bars", {}))
        self.update_range_label()

    def select_group_child_tab(self, parent_idx, child_idx, logical_name, hide_subtabs=True):
        location = getattr(self, "logical_tab_locations", {}).get(logical_name)
        if not location:
            return
        _parent_tabs, _parent_idx, stack, _child_idx = location
        if stack is not None:
            stack.setCurrentIndex(child_idx)
        self.sync_group_subtab_buttons(parent_idx)
        if hide_subtabs:
            self.set_subtab_bar_visible(parent_idx, False)
        self.update_range_label()


    def current_logical_tab_name(self):
        current_index = self.tabs.currentIndex()
        for logical_name, location in getattr(self, "logical_tab_locations", {}).items():
            parent_tabs, parent_idx, child_tabs, child_idx = location
            if parent_tabs is not self.tabs or parent_idx != current_index:
                continue
            if child_tabs is None:
                return logical_name
            if child_tabs.currentIndex() == child_idx:
                return logical_name
        return self.tabs.tabText(current_index)

    def logical_tab_widget(self, tab_name):
        tab_name = self.normalize_logical_tab_name(tab_name)
        return getattr(self, "logical_tab_widgets", {}).get(tab_name)

    def select_logical_tab(self, tab_name):
        tab_name = self.normalize_logical_tab_name(tab_name)
        location = getattr(self, "logical_tab_locations", {}).get(tab_name)
        if not location:
            return None
        parent_tabs, parent_idx, child_stack, child_idx = location
        parent_tabs.setCurrentIndex(parent_idx)
        if child_stack is not None:
            self.select_group_child_tab(parent_idx, child_idx, tab_name, hide_subtabs=True)
        else:
            self.hide_all_subtab_bars()
        return self.logical_tab_widget(tab_name)

    def apply_date_range(self):

        log.info("=== APPLY CLICK ===")

        if self.start_date_edit.date() > self.end_date_edit.date():
            QMessageBox.warning(self, "날짜 오류", "시작일이 종료일보다 늦습니다.")
            return

        start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
        end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

        current_tab = self.current_logical_tab_name()

        if current_tab == "Dashboard":
            self.dashboard_detections = load_endpoint_detections_by_range(start_date, end_date)
            self.dashboard_xdr_detections = load_xdr_email_detections_by_range(start_date, end_date)

            self.dashboard_emails = load_emails_by_range(start_date, end_date)
            self.dlp_rows = load_dlp_by_range(start_date, end_date)
            self.mailscreen_rows = load_mailscreen_by_range(start_date, end_date)
            self.dlp_range = f"{start_date} ~ {end_date}"
            self.mailscreen_range = f"{start_date} ~ {end_date}"

            # =========================
            # 비교용 추가 범위 로드
            # 종료일 기준 전일 / 전월 계산용
            # =========================
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            compare_start_dt = end_dt - relativedelta(months=1)
            compare_start = compare_start_dt.strftime("%Y-%m-%d")
            self.dashboard_compare_dlp = load_dlp_by_range(compare_start, end_date)
            self.dashboard_compare_mailscreen = load_mailscreen_by_range(compare_start, end_date)

            self.dashboard_compare_detections = load_endpoint_detections_by_range(compare_start, end_date)
            self.dashboard_compare_xdr_detections = load_xdr_email_detections_by_range(compare_start, end_date)

            self.dashboard_compare_emails = load_emails_by_range(compare_start, end_date)

            self.dashboard_range = f"{start_date} ~ {end_date}"
            self.refresh_dashboard()

        elif current_tab == "Detection - XDR":
            self.detection_detections = load_endpoint_detections_by_range(start_date, end_date)
            self.detection_range = f"{start_date} ~ {end_date}"
            self._refresh_detection()

        elif current_tab == "Email - XDR":
            self.xdr_detections = load_xdr_email_detections_by_range(start_date, end_date)

            self.xdr_range = f"{start_date} ~ {end_date}"
            self._refresh_detection_xdr()

        elif current_tab == "Email":
            self.email_emails = load_emails_by_range(start_date, end_date)
            self.email_range = f"{start_date} ~ {end_date}"
            self._refresh_email()

        elif current_tab == "Outbound Mail":
            self.mailscreen_rows = load_mailscreen_by_range(start_date, end_date)
            self.mailscreen_range = f"{start_date} ~ {end_date}"
            if hasattr(self, "_refresh_outbound_mail"):
                self._refresh_outbound_mail()

        elif current_tab == "File":
            self.dlp_rows = load_dlp_by_range(start_date, end_date)
            self.dlp_range = f"{start_date} ~ {end_date}"

            if hasattr(self, "_refresh_dlp"):
                self._refresh_dlp()

        elif current_tab == "Sensitive Files":
            if hasattr(self, "_refresh_sensitive_files"):
                self._refresh_sensitive_files()

        elif current_tab == "Sensitive Sites":
            if hasattr(self, "_refresh_sensitive_sites"):
                self._refresh_sensitive_sites()

        elif current_tab == "Timeline":
            # Timeline은 날짜 선택과 무관하게 검색 시점에 전체 캐시를 비동기로 스캔한다.
            self.timeline_range = "전체 캐시"

        # 🔥 적용 후 현재 탭 기준으로 표시
        self.update_range_label()


    def update_range_label(self):

        tab_name = self.current_logical_tab_name()

        if tab_name == "Dashboard":
            text = self.dashboard_range

        elif tab_name == "Detection - XDR":
            text = self.detection_range

        elif tab_name == "Email - XDR":
            text = self.xdr_range

        elif tab_name == "Email":
            text = self.email_range

        elif tab_name == "Outbound Mail":
            text = self.mailscreen_range

        elif tab_name == "File":
            text = self.dlp_range

        elif tab_name == "Sensitive Files":
            text = getattr(self, "sensitive_files_range", "")

        elif tab_name == "Sensitive Sites":
            text = getattr(self, "sensitive_sites_range", "")

        elif tab_name == "Timeline":
            text = getattr(self, "timeline_range", "")

        else:
            text = ""

        self.range_label.setText(text)

    def update_time_range_label(self, tab_name):
        self.range_label.setText("")

    def _create_dashboard_card(self, title):

        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #f2f2f2;
                border: 1px solid #cccccc;
                border-radius: 6px;
            }
        """)

        vbox = QVBoxLayout(frame)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        vbox.addWidget(title_label)

        value_label = QLabel("")
        value_label.setStyleSheet("font-size: 16px;")
        value_label.setWordWrap(True)

        vbox.addWidget(value_label)

        frame.value_label = value_label
        return frame

    def save_response_results_to_file(self, results):
        try:
            output_dir = os.path.join(BASE_DIR, "output")
            os.makedirs(output_dir, exist_ok=True)

            ts = datetime.now().strftime('%Y%m%d_%H%M%S')

            txt_path = os.path.join(output_dir, f"firewall_response_{ts}.txt")
            csv_path = os.path.join(output_dir, f"firewall_response_{ts}.csv")

            normalized_rows = []

            for item in results:
                if not isinstance(item, dict):
                    continue

                firewall = str(item.get("firewall", "Unknown"))
                target = str(item.get("target", item.get("ip", "")))
                name = str(item.get("name", ""))
                response_text = str(item.get("response", ""))
                error = str(item.get("error", ""))

                parsed = parse_firewall_api_response(response_text)
                status_code = str(parsed.get("code", ""))
                message = str(parsed.get("message", ""))

                if status_code == "200":
                    result_text = "SUCCESS"
                elif status_code in ("502", "503"):
                    result_text = "EXISTS"
                else:
                    result_text = "FAIL"

                normalized_rows.append({
                    "Firewall": firewall,
                    "Target": target,
                    "Object Name": name,
                    "Result": result_text,
                    "Status Code": status_code,
                    "Message": message,
                    "Error": error,
                    "Raw Response": response_text,
                })

            with open(txt_path, "w", encoding="utf-8") as f:
                for row in normalized_rows:
                    f.write(
                        f"firewall={row['Firewall']} | "
                        f"target={row['Target']} | "
                        f"name={row['Object Name']} | "
                        f"result={row['Result']} | "
                        f"status_code={row['Status Code']} | "
                        f"message={row['Message']} | "
                        f"error={row['Error']}\n"
                    )

            df = pd.DataFrame(normalized_rows)
            df.to_csv(csv_path, index=False, encoding="utf-8-sig")

            log.info(f"[FIREWALL RESPONSE UI] result txt saved: {txt_path}")
            log.info(f"[FIREWALL RESPONSE UI] result csv saved: {csv_path}")

        except Exception as e:
            log.exception(f"[FIREWALL RESPONSE UI] result file save fail: {e}")



    def on_response_mode_changed(self, mode: str):
        mode = str(mode or "").strip()

        if mode == "DOMAIN":
            self.btn_response_run.setText("도메인 객체 생성")
            self.response_input.setPlaceholderText(
                "현재 DOMAIN 모드는 준비만 된 상태입니다.\n\n"
                "예시:\n"
                "example.com\n"
                "malicious-domain.com"
            )
        else:
            self.btn_response_run.setText("IP 객체 생성")
            self.response_input.setPlaceholderText(
                "차단할 IP를 한 줄에 하나씩 입력하세요.\n\n"
                "예시:\n"
                "104.238.194.12\n"
                "45.205.1.18\n"
                "89.248.163.168"
            )



    # ==================================================
    # Status / Spinner
    # ==================================================
    def _spin_tick(self):
        self._spin_phase = (self._spin_phase + 1) % 4
        dots = "." * self._spin_phase
        self.status_label.setText(f"{self._spin_base}{dots}")

    def set_status(self, text, color="gray", spinning=False):
        palette = {
            "gray": (UI_THEME["gray_bg"], UI_THEME["gray_text"], UI_THEME["gray_border"]),
            "green": (UI_THEME["success_bg"], UI_THEME["status_success_text"], UI_THEME["success_border"]),
            "red": (UI_THEME["danger_bg"], UI_THEME["status_fail_text"], UI_THEME["danger_border"]),
            "blue": (UI_THEME["status_blue_bg"], UI_THEME["status_blue_text"], UI_THEME["status_blue_border"]),
        }
        bg, fg, border = palette.get(str(color).lower(), (UI_THEME["accent_soft"], str(color), UI_THEME["border"]))
        self.status_label.setStyleSheet(f"""
            QLabel#statusPill {{
                background: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 12px;
                padding: 6px 12px;
                font-weight: 700;
                min-height: 20px;
            }}
        """)
        self._spin_timer.stop()
        if spinning:
            self._spin_base = text
            self._spin_phase = 0
            self._spin_timer.start(350)
        else:
            self.status_label.setText(text)

    def open_log_folder(self):
        try:
            os.startfile(LOG_DIR)
        except Exception:
            QMessageBox.warning(self, "실패", "로그 폴더를 열 수 없습니다.")

    # ==================================================
    # Refresh logic
    # ==================================================
    def refresh_current_tab(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        tab_name = self.current_logical_tab_name()

        self.running = True
        self.set_status(f"{tab_name} refresh", color="blue", spinning=True)

        if tab_name in ("Detection - XDR", "Email - XDR"):
            start_date = self.det_start_date.date().toString("yyyy-MM-dd")
            end_date = self.det_end_date.date().toString("yyyy-MM-dd")

            self.worker = RefreshWorker(
                job_name="Detection",
                date_str=f"{start_date}|{end_date}"
            )

        elif tab_name == "Email":
            start_date = self.mail_start_date.date().toString("yyyy-MM-dd")
            end_date = self.mail_end_date.date().toString("yyyy-MM-dd")

            self.worker = RefreshWorker(
                job_name=tab_name,
                date_str=f"{start_date}|{end_date}"
            )

        else:
            self.worker = RefreshWorker(job_name=tab_name)

        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.progress.connect(self._on_refresh_progress)
        self.worker.start()


    def run_refresh(self, job_name):

        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        self.running = True
        self.set_status(f"{job_name} refresh", color="blue", spinning=True)

        if job_name == "Detection":
            start_qdate = self.det_start_date.date()
            end_qdate = self.det_end_date.date()

            if start_qdate > end_qdate:
                self.running = False
                self.set_status("Idle", color="gray", spinning=False)
                QMessageBox.warning(self, "날짜 오류", "시작일이 종료일보다 늦습니다.")
                return

            start_date = start_qdate.toString("yyyy-MM-dd")
            end_date = end_qdate.toString("yyyy-MM-dd")

            self.worker = RefreshWorker(
                job_name=job_name,
                date_str=f"{start_date}|{end_date}"
            )

        elif job_name == "Email":
            start_qdate = self.mail_start_date.date()
            end_qdate = self.mail_end_date.date()

            if start_qdate > end_qdate:
                self.running = False
                self.set_status("Idle", color="gray", spinning=False)
                QMessageBox.warning(self, "날짜 오류", "시작일이 종료일보다 늦습니다.")
                return

            start_date = start_qdate.toString("yyyy-MM-dd")
            end_date = end_qdate.toString("yyyy-MM-dd")

            self.worker = RefreshWorker(
                job_name=job_name,
                date_str=f"{start_date}|{end_date}"
            )

        else:
            self.worker = RefreshWorker(job_name=job_name)

        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.start()

    def run_refresh_dlp(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        date_str = self.dlp_refresh_date.date().toString("yyyy-MM-dd")

        self.running = True
        self.set_status("DLP refresh", color="blue", spinning=True)

        self.worker = RefreshWorker(job_name="DLP", date_str=date_str)
        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.progress.connect(self._on_refresh_progress)
        self.worker.start()

    def run_refresh_mailscreen(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        # 버튼 클릭 직전에 직접 입력한 날짜가 아직 QDateEdit 값으로 commit되지 않은 경우가 있어
        # 현재 표시/입력 중인 텍스트를 먼저 해석한 뒤 선택 날짜를 읽는다.
        self.mailscreen_refresh_date.interpretText()
        date_str = self.mailscreen_refresh_date.date().toString("yyyy-MM-dd")

        self.running = True
        self.set_status("MailScreen refresh", color="blue", spinning=True)

        self.worker = RefreshWorker(job_name="MailScreen", date_str=date_str)
        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.progress.connect(self._on_refresh_progress)
        self.worker.start()

    def run_refresh_detection_range(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        start_date = self.det_start_date.date().toString("yyyy-MM-dd")
        end_date = self.det_end_date.date().toString("yyyy-MM-dd")

        self.running = True
        self.set_status("Detection refresh", color="blue", spinning=True)

        self.worker = RefreshWorker(
            job_name="Detection",
            date_str=f"{start_date}|{end_date}"
        )

        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.start()

    def run_refresh_email_range(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 최신화가 진행 중입니다.")
            return

        start_qdate = self.mail_start_date.date()
        end_qdate = self.mail_end_date.date()

        if start_qdate > end_qdate:
            QMessageBox.warning(self, "날짜 오류", "시작일이 종료일보다 늦습니다.")
            return

        start_date = start_qdate.toString("yyyy-MM-dd")
        end_date = end_qdate.toString("yyyy-MM-dd")

        self.running = True
        self.set_status("Inbound Mail refresh", color="blue", spinning=True)

        self.worker = RefreshWorker(
            job_name="Email",
            date_str=f"{start_date}|{end_date}"
        )

        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.start()

    def _on_refresh_progress(self, tab_name, message):
        if tab_name in ("DLP", "MailScreen"):
            self.set_status(str(message), color="blue", spinning=True)

    def _on_refresh_ok(self, tab_name):

        self.running = False
        self._spin_timer.stop()

        self.set_status(f"{tab_name} OK", color="green", spinning=False)

        if tab_name in ("Endpoint", "Organization", "User"):
            reload_all_data()
            self.refresh_all_tables()

        if tab_name == "DLP":
            start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

            self.dlp_rows = load_dlp_by_range(start_date, end_date)
            self.dlp_range = f"{start_date} ~ {end_date}"

            if hasattr(self, "_refresh_dlp"):
                self._refresh_dlp()
        self.apply_date_range()

        # 🔥 자동 상태 표시 추가
        if tab_name in ("Detection", "Email", "DLP", "MailScreen"):
            self.update_auto_status(tab_name, True)
            auto_logger.info(f"[{tab_name}] AUTO REFRESH SUCCESS")

        # 🔥 자동 대기 작업 처리
        if self.auto_index_after_refresh:
            if self.auto_pending:
                self.run_next_auto_pending()
                return

            self.auto_index_after_refresh = False
            self.auto_continue_after_index = False
            self.run_data_index()
            return

        self.run_next_auto_pending()


    def _on_refresh_fail(self, tab_name, err):

        self.running = False
        self._spin_timer.stop()
        self.set_status(f"{tab_name} FAIL", color="red")

        if tab_name in ("Detection", "Email", "DLP", "MailScreen"):
            self.update_auto_status(tab_name, False)
            auto_logger.error(f"[{tab_name}] AUTO REFRESH FAIL - {err}")

        if self.auto_index_after_refresh:
            self.auto_index_after_refresh = False
            self.auto_continue_after_index = False
            self.run_next_auto_pending()

    # ==================================================
    # Context menu (right click)
    # ==================================================
    def enable_context_menu(self, table, column_map):
        table.setContextMenuPolicy(Qt.CustomContextMenu)

        def open_menu(pos):
            item = table.itemAt(pos)
            if not item:
                return

            value = item.text()
            col = item.column()
            menu = QMenu()

            current_tab = self.current_logical_tab_name()

            # 기본 Search
            for name in ["Detection - XDR", "Email", "Endpoint", "Organization"]:
                menu.addAction(
                    f"Search in {name}",
                    lambda v=value, t=name: self.search_other_tab(t, v)
                )

            # VT
            if col in column_map:
                kind = column_map[col]
                if kind == "sha256":
                    menu.addAction(
                        "Search SHA256 in VirusTotal",
                        lambda v=value: webbrowser.open(
                            f"https://www.virustotal.com/gui/search/{v}"
                        ),
                    )
                elif kind == "ip":
                    menu.addAction(
                        "Search IP in VirusTotal",
                        lambda v=value: webbrowser.open(
                            f"https://www.virustotal.com/gui/ip-address/{v}"
                        ),
                    )

            # GPT Rule 분석
            if col == 6:
                def open_gpt(rule=value):
                    prompt = f"""{rule} 룰 경우 Sophos 탐지 룰 이벤트 명입니다.
    해당 룰에 대해 설명이 필요합니다.
    탐지 조건은 무엇이며 위험도는 무엇인지 항목별로 나누어서 설명해주세요."""
                    encoded = urllib.parse.quote(prompt)
                    url = f"https://chat.openai.com/?q={encoded}"
                    webbrowser.open(url)

                menu.addSeparator()
                menu.addAction("Search Rule in ChatGPT", open_gpt)

            # 🔥 Detection 탭에서만 Raw GPT 분석 추가
            raw_gpt_action = None
            if current_tab == "Detection - XDR":
                def open_raw_gpt():

                    row = item.row()
                    time_item = table.item(row, 0)

                    if not time_item:
                        return

                    raw = time_item.data(Qt.UserRole)

                    if not raw:
                        return

                    prompt = f"""
Sophos Endpoint 보안 탐지 이벤트 분석 요청

아래 Raw Detection Event 데이터를 기반으로 보안 분석 보고서를 작성해주세요.

Raw Detection Event Data :
{json.dumps(raw, indent=2, ensure_ascii=False)}

반드시 아래 형식과 동일하게 작성해주세요.

탐지 시간 :
Raw 데이터에서 이벤트 발생 시간을 확인하여 작성

액션 :
해당 이벤트가 탐지(Detection)인지 차단(Blocked)인지 판단하여 작성

룰 명 :
탐지 룰 이름 작성

룰 설명 :
해당 Sophos 탐지 룰이 어떤 행위 또는 공격 기법을 탐지하는지 설명

탐지된 사용자 :
Raw 데이터에서 확인 가능한 사용자 계정 또는 로그인 사용자 작성

분석 내용 :
실제 이벤트 데이터를 기반으로 다음과 같은 흐름 형태로 분석

예시 형식

회사 PC 접속
↓
특정 프로그램 실행
↓
관련 프로세스 동작
↓
의심 행위 발생
↓
Sophos 탐지 룰 트리거

Raw 데이터에 포함된 프로세스 실행 흐름(Process Lineage)이 있다면 이를 기반으로 분석

영향도 :
만약 해당 행위가 실제 악성 행위일 경우 발생할 수 있는 보안 영향 설명

예시
- 악성 코드 실행 가능성
- 내부 시스템 접근 시도
- 권한 상승 가능성
- 데이터 유출 가능성

탐지 조건 :
Raw 데이터 기반으로 탐지 조건을 정리

다음 항목 기준으로 작성

Detection Name :
Process Name :
Process Path :
Process SHA256 :
Parent Process :
Command Line :

추가 요구 사항

1. 보안 분석 보고서 스타일로 작성
2. 불필요한 설명 없이 항목별로 정리
3. 가능하면 MITRE ATT&CK 관점에서 행위 설명
4. 실제 SOC(Security Operation Center) 분석 보고서 수준으로 작성
"""

                    encoded = urllib.parse.quote(prompt)
                    url = f"https://chat.openai.com/?q={encoded}"
                    webbrowser.open(url)

                raw_gpt_action = menu.addAction("Analyze RawData in ChatGPT")

            # 🔥 항상 맨 아래
            menu.addSeparator()
            detail_action = menu.addAction("View Raw Detail")

            # 실행
            action = menu.exec_(table.viewport().mapToGlobal(pos))

            # Raw GPT 실행
            if raw_gpt_action and action == raw_gpt_action:
                open_raw_gpt()

            # Raw Detail
            elif action == detail_action:

                row = item.row()
                log.info(f"[DETAIL] Clicked Row = {row}")

                time_item = table.item(row, 0)

                if not time_item:
                    log.info("[DETAIL] time_item is NONE")
                    return

                raw = time_item.data(Qt.UserRole)

                log.info(f"[DETAIL] raw type = {type(raw)}")

                if not raw:
                    log.info("[DETAIL] raw is NONE or empty")
                    return

                log.info("[DETAIL] Opening dialog")
                self.show_raw_dialog(raw)

        table.customContextMenuRequested.connect(open_menu)

    def show_firewall_group_dialog(self, data: dict):
        if not isinstance(data, dict):
            QMessageBox.warning(self, "조회 오류", "조회 결과 데이터가 올바르지 않습니다.")
            return

        firewall_name = str(data.get("firewall", "Unknown"))

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Firewall Group View - {firewall_name}")
        dialog.resize(1100, 720)

        layout = QVBoxLayout(dialog)

        title = QLabel(f"Firewall : {firewall_name}")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #1f2937;")
        layout.addWidget(title)

        tab = QTabWidget()
        layout.addWidget(tab)

        ip_group = data.get("ip_group", {}) if isinstance(data.get("ip_group"), dict) else {}
        fqdn_group = data.get("fqdn_group", {}) if isinstance(data.get("fqdn_group"), dict) else {}

        ip_widget = self.build_firewall_group_tab_widget(ip_group, "IP")
        fqdn_widget = self.build_firewall_group_tab_widget(fqdn_group, "DOMAIN")

        tab.addTab(ip_widget, "IP Host Group")
        tab.addTab(fqdn_widget, "Domain Host Group")

        btn_row = QHBoxLayout()

        btn_copy_all = QPushButton("전체 복사")
        btn_close = QPushButton("닫기")

        def copy_all():
            lines = []
            for group_key in ["ip_group", "fqdn_group"]:
                group = data.get(group_key, {})
                if not isinstance(group, dict):
                    continue

                group_type = str(group.get("group_type", ""))
                group_name = str(group.get("group_name", ""))
                members = group.get("members", [])
                if not isinstance(members, list):
                    members = []

                lines.append(f"[{group_type}] {group_name}")
                for m in members:
                    if not isinstance(m, dict):
                        continue
                    lines.append(f"{m.get('object_name', '')}\t{m.get('value', '')}")
                lines.append("")

            QApplication.clipboard().setText("\n".join(lines).strip())
            QMessageBox.information(dialog, "Copy", "조회 결과를 복사했습니다.")

        btn_copy_all.clicked.connect(copy_all)
        btn_close.clicked.connect(dialog.accept)

        btn_row.addStretch()
        btn_row.addWidget(btn_copy_all)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)

        dialog.exec_()

    def build_firewall_group_tab_widget(self, group_data: dict, display_type: str):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        group_name = str(group_data.get("group_name", "") or "")
        status_code = str(group_data.get("status_code", "") or "")
        error = str(group_data.get("error", "") or "")
        raw = str(group_data.get("raw", "") or "")

        members = group_data.get("members", [])
        if not isinstance(members, list):
            members = []

        # =========================
        # 상단 요약 라인
        # =========================
        summary = QLabel(
            f"Group Name : {group_name or '-'}    "
            f"Count : {len(members)}    "
            f"Status : {status_code or '-'}"
        )
        summary.setStyleSheet("""
            QLabel {
                font-weight: 700;
                color: #374151;
                padding: 4px 2px;
            }
        """)
        layout.addWidget(summary)

        # 에러만 별도 표시
        if error:
            err_label = QLabel(f"Error : {error}")
            err_label.setWordWrap(True)
            err_label.setStyleSheet("""
                QLabel {
                    color: #dc2626;
                    font-weight: 700;
                    padding: 4px;
                    background-color: #fee2e2;
                    border: 1px solid #fecaca;
                    border-radius: 4px;
                }
            """)
            layout.addWidget(err_label)

        # =========================
        # 멤버 리스트 테이블
        # =========================
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels([
            "No",
            "Object Name",
            "Value"
        ])

        table.setRowCount(0)

        for idx, member in enumerate(members, start=1):
            if not isinstance(member, dict):
                continue

            row = table.rowCount()
            table.insertRow(row)

            item_no = QTableWidgetItem(str(idx))
            item_name = QTableWidgetItem(str(member.get("object_name", "")))
            item_value = QTableWidgetItem(str(member.get("value", "")))

            item_no.setTextAlignment(Qt.AlignCenter)

            table.setItem(row, 0, item_no)
            table.setItem(row, 1, item_name)
            table.setItem(row, 2, item_value)

        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setAlternatingRowColors(True)

        # 리스트가 많을 때 스크롤 표시
        table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # 컬럼 폭
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

        # 모달 안에서 테이블이 최대한 크게 보이게
        table.setMinimumHeight(520)
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                gridline-color: #e5e7eb;
                border: 1px solid #d1d5db;
                selection-background-color: #EEF5FF;
                selection-color: #111827;
            }

            QTableWidget::item {
                padding: 4px;
            }

            QHeaderView::section {
                background-color: #f3f4f6;
                color: #111827;
                font-weight: 700;
                border: 1px solid #d1d5db;
                padding: 5px;
            }
        """)

        layout.addWidget(table, 1)

        # =========================
        # 하단 버튼
        # =========================
        btn_row = QHBoxLayout()

        btn_copy = QPushButton(f"{display_type} 목록 복사")
        btn_raw = QPushButton("Raw Response 보기")
        btn_raw.setToolTip("필요할 때만 원본 XML 응답을 별도 창으로 확인합니다.")

        def copy_list():
            lines = []
            for member in members:
                if not isinstance(member, dict):
                    continue
                lines.append(f"{member.get('object_name', '')}\t{member.get('value', '')}")

            QApplication.clipboard().setText("\n".join(lines))
            QMessageBox.information(root, "Copy", f"{display_type} 목록을 복사했습니다.")

        def open_raw_response():
            raw_dialog = QDialog(root)
            raw_dialog.setWindowTitle(f"{display_type} Raw Response")
            raw_dialog.resize(1000, 650)

            raw_layout = QVBoxLayout(raw_dialog)

            raw_text = QTextEdit()
            raw_text.setReadOnly(True)
            raw_text.setPlainText(raw)
            raw_text.setLineWrapMode(QTextEdit.NoWrap)

            raw_layout.addWidget(raw_text)

            close_btn = QPushButton("닫기")
            close_btn.clicked.connect(raw_dialog.accept)
            raw_layout.addWidget(close_btn)

            raw_dialog.exec_()

        btn_copy.clicked.connect(copy_list)
        btn_raw.clicked.connect(open_raw_response)

        btn_row.addWidget(btn_copy)
        btn_row.addWidget(btn_raw)
        btn_row.addStretch()

        layout.addLayout(btn_row)

        return root

    def show_raw_dialog(self, data):

        if not data:
            QMessageBox.warning(self, "Error", "No Raw Data")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Raw Detection Data")
        dialog.resize(1000, 700)

        layout = QVBoxLayout(dialog)

        # 🔹 검색바 영역
        search_layout = QHBoxLayout()

        search_box = QLineEdit()
        search_box.setPlaceholderText("Find... (Ctrl+F)")

        btn_prev = QPushButton("Prev")
        btn_next = QPushButton("Next")


        search_layout.addWidget(search_box)
        search_layout.addWidget(btn_prev)
        search_layout.addWidget(btn_next)

        layout.addLayout(search_layout)

        # 🔹 텍스트 영역
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(data, indent=4, ensure_ascii=False))

        layout.addWidget(text)

        # 🔹 닫기 버튼
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        # =========================
        # 🔥 검색 기능
        # =========================
        def find_next():
            keyword = search_box.text()
            if keyword:
                found = text.find(keyword)
                if not found:
                    text.moveCursor(text.textCursor().Start)
                    text.find(keyword)

        def find_prev():
            keyword = search_box.text()
            if keyword:
                from PyQt5.QtGui import QTextDocument
                found = text.find(keyword, QTextDocument.FindBackward)
                if not found:
                    text.moveCursor(text.textCursor().End)
                    text.find(keyword, QTextDocument.FindBackward)

        btn_next.clicked.connect(find_next)
        btn_prev.clicked.connect(find_prev)

        def highlight_all():
            keyword = search_box.text().strip()
            text.setExtraSelections([])

            if not keyword:
                return

            extra_selections = []

            cursor = QTextCursor(text.document())
            cursor.movePosition(QTextCursor.Start)

            fmt = QTextCharFormat()
            fmt.setBackground(QColor("#ffeb3b"))
            fmt.setForeground(QColor("#000000"))

            while True:
                cursor = text.document().find(keyword, cursor)

                if cursor.isNull():
                    break

                selection = QTextEdit.ExtraSelection()
                selection.cursor = cursor
                selection.format = fmt
                extra_selections.append(selection)

            text.setExtraSelections(extra_selections)

            # 🔥 기본 selection 완전 제거
            clean = QTextCursor(text.document())
            clean.clearSelection()
            text.setTextCursor(clean)


        search_box.textChanged.connect(highlight_all)

        # 🔹 Ctrl+F 단축키
        def focus_search():
            search_box.setFocus()


        dialog.shortcut = QShortcut(QKeySequence("Ctrl+F"), dialog)
        dialog.shortcut.activated.connect(focus_search)

        dialog.exec_()

    def search_other_tab(self, tab_name, value):
        widget = self.select_logical_tab(tab_name)
        if not widget:
            return
        box = widget.findChild(QLineEdit)
        if box:
            box.setText(value)
            box.returnPressed.emit()

    # ==================================================
    # Tab rendering helpers
    # ==================================================
    def refresh_all_tables(self):
        self.refresh_tab_table("Dashboard")
        self.refresh_tab_table("Detection - XDR")
        self.refresh_tab_table("Email - XDR")
        self.refresh_tab_table("Email")
        self.refresh_tab_table("Outbound Mail")
        self.refresh_tab_table("File")
        self.refresh_tab_table("Sensitive Files")
        self.refresh_tab_table("Sensitive Sites")
        self.refresh_tab_table("Endpoint")
        self.refresh_tab_table("Organization")
        self.refresh_tab_table("Timeline")
        current_tab = self.current_logical_tab_name()
        self.update_time_range_label(current_tab)

    def refresh_tab_table(self, tab_name):
        tab_name = self.normalize_logical_tab_name(tab_name)
        if tab_name == "Dashboard" and hasattr(self, "_refresh_dashboard"):
            self._refresh_dashboard()
        elif tab_name == "Detection - XDR" and hasattr(self, "_refresh_detection"):
            self._refresh_detection()
        elif tab_name == "Email - XDR" and hasattr(self, "_refresh_detection_xdr"):
            self._refresh_detection_xdr()
        elif tab_name == "Email" and hasattr(self, "_refresh_email"):
            self._refresh_email()
        elif tab_name == "Outbound Mail" and hasattr(self, "_refresh_outbound_mail"):
            self._refresh_outbound_mail()
        elif tab_name == "Endpoint" and hasattr(self, "_refresh_endpoint"):
            self._refresh_endpoint()
        elif tab_name == "Organization" and hasattr(self, "_refresh_org"):
            self._refresh_org()
        elif tab_name == "File" and hasattr(self, "_refresh_dlp"):
            self._refresh_dlp()
        elif tab_name == "Sensitive Files" and hasattr(self, "_refresh_sensitive_files"):
            self._refresh_sensitive_files()
        elif tab_name == "Sensitive Sites" and hasattr(self, "_refresh_sensitive_sites"):
            self._refresh_sensitive_sites()
        elif tab_name == "Timeline" and hasattr(self, "_refresh_timeline"):
            self._refresh_timeline()

    # ==================================================
    # Dashboard Tab
    # ==================================================
    def tab_dashboard(self):
        root = QWidget()
        root.setObjectName("dashboardRoot")
        root.setStyleSheet("""
            QWidget#dashboardRoot {
                background: #FFFFFF;
                border-radius: 18px;
            }
        """)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # -------------------------
        # 🔥 TOP CARD AREA
        # -------------------------
        top_layout = QHBoxLayout()
        top_layout.setSpacing(15)

        # 왼쪽 첫 칸: Endpoints + Organization 세로 배치
        left_stack = QVBoxLayout()
        left_stack.setSpacing(12)

        self.card_endpoint = self.make_stat_card("Endpoints", "")
        self.card_org = self.make_stat_card("Organization", "")

        left_stack.addWidget(self.card_endpoint, 1)
        left_stack.addWidget(self.card_org, 1)

        top_layout.addLayout(left_stack, 1)

        # 나머지 상단 카드
        self.card_file_top = self.make_stat_card("Top File", "")
        self.card_hash_top = self.make_stat_card("Top Hash", "")
        self.card_summary = self.make_stat_card("Folder Usage", "")

        top_layout.addWidget(self.card_file_top, 1)
        top_layout.addWidget(self.card_hash_top, 1)
        top_layout.addWidget(self.card_summary, 1)

        layout.addLayout(top_layout)

        # -------------------------
        # 🔥 GRAPH AREA (카드화)
        # -------------------------

        graph_card, graph_layout = self.make_card("Threat Trend")

        container = QHBoxLayout()
        container.setSpacing(15)

        # 그래프
        self.figure = Figure(figsize=(10, 4), facecolor="#ffffff")
        self.canvas = FigureCanvas(self.figure)
        graph_left = QVBoxLayout()
        graph_left.setContentsMargins(0, 0, 0, 0)
        graph_left.setSpacing(6)

        trend_toggle_row = QHBoxLayout()
        trend_toggle_row.setContentsMargins(0, 0, 0, 0)
        trend_toggle_row.setSpacing(10)
        self.trend_checkboxes = {}
        for label in ["Detection - XDR", "Email - XDR", "Inbound Mail", "Outbound Mail", "File"]:
            chk = QCheckBox(label)
            chk.setChecked(self.trend_visibility.get(label, True))
            chk.setStyleSheet(f"color:{UI_THEME['text_soft']}; font-weight:800; background:transparent;")
            chk.toggled.connect(lambda checked, name=label: self.set_trend_series_visible(name, checked))
            self.trend_checkboxes[label] = chk
            trend_toggle_row.addWidget(chk)
        trend_toggle_row.addStretch(1)

        graph_left.addLayout(trend_toggle_row)
        graph_left.addWidget(self.canvas, 1)
        container.addLayout(graph_left, 4)

        # 퍼센트
        percent_frame = QFrame()
        percent_frame.setMinimumWidth(330)
        percent_frame.setMaximumWidth(380)
        percent_frame.setMinimumHeight(210)
        percent_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        percent_layout = QVBoxLayout(percent_frame)
        percent_layout.setContentsMargins(0, 0, 0, 0)
        percent_layout.setSpacing(0)
        self.percent_label = QLabel("")
        self.percent_label.setAlignment(Qt.AlignTop)
        self.percent_label.setStyleSheet(f"""
            background: {UI_THEME['surface']};
            border: 1px solid {UI_THEME['border']};
            border-radius: 14px;
            color: {UI_THEME['text']};
            font-size: 13px;
            font-weight: 800;
            padding: 14px;
        """)
        self.percent_label.setWordWrap(True)
        self.percent_label.setMinimumHeight(190)
        self.percent_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        percent_layout.addWidget(self.percent_label)
        percent_layout.addStretch()

        container.addWidget(percent_frame, 0)

        graph_layout.addLayout(container)
        layout.addWidget(graph_card)

        # -------------------------
        # 🔥 BOTTOM AREA (좌/우 2분할)
        # -------------------------

        bottom_container = QHBoxLayout()
        bottom_container.setSpacing(15)

        # -------------------------
        # 왼쪽 : Top Analysis
        # -------------------------
        top_card, top_layout = self.make_card("Top Analysis")

        self.top_table = QTableWidget()
        self.top_table.verticalHeader().setDefaultSectionSize(24)
        self.top_table.setMinimumHeight(220)
        self.top_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.top_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.top_table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.top_table.setColumnCount(3)
        self.top_table.setHorizontalHeaderLabels(
            ["Top Hostname", "Top Rule", "Top Sender IP"]
        )
        self.top_table.setStyleSheet(self.top_table_stylesheet())
        self.top_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        top_layout.addWidget(self.top_table, 1)

        bottom_container.addWidget(top_card, 1)

        # -------------------------
        # 오른쪽 : Detection / XDR / Inbound Mail Summary
        # -------------------------
        right_box = QGridLayout()
        right_box.setSpacing(15)

        self.card_det_summary = self.make_scroll_stat_card("Detection - XDR Summary", "")
        self.card_xdr_summary = self.make_scroll_stat_card("Email - XDR Summary", "")
        self.card_email_summary = self.make_scroll_stat_card("Inbound Mail Summary", "")
        self.card_file_summary = self.make_scroll_stat_card("File Summary", "")

        right_box.addWidget(self.card_det_summary, 0, 0)
        right_box.addWidget(self.card_xdr_summary, 0, 1)
        right_box.addWidget(self.card_email_summary, 1, 0)
        right_box.addWidget(self.card_file_summary, 1, 1)

        bottom_container.addLayout(right_box, 1)

        layout.addLayout(bottom_container, stretch=1)

        self._refresh_dashboard = self.refresh_dashboard


        return root

    def make_stat_card(self, title, value):
        frame = QFrame()
        frame.setObjectName("statCard")
        frame.setStyleSheet(self.card_style("statCard", accent=True))
        self.apply_soft_shadow(frame)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        self.add_card_title(layout, title)

        value_label = QLabel(value)
        value_label.setStyleSheet("""
            background: transparent;
            border: none;
            font-size:13px;
            font-weight:700;
            color:#111827;
            line-height: 150%;
        """)

        value_label.setWordWrap(True)
        value_label.setTextFormat(Qt.RichText)

        layout.addWidget(value_label)
        layout.addStretch()

        frame.value_label = value_label
        return frame

    def make_scroll_stat_card(self, title, value):
        frame = QFrame()
        frame.setObjectName("scrollStatCard")
        frame.setStyleSheet(self.card_style("scrollStatCard", accent=True))
        self.apply_soft_shadow(frame, blur=24, y_offset=10, alpha=80)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        self.add_card_title(layout, title)

        value_label = QTextEdit()
        value_label.setReadOnly(True)
        value_label.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        value_label.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        value_label.setStyleSheet("""
            QTextEdit {
                border: none;
                background: transparent;
                font-size: 13px;
                font-weight: 700;
                color: #111827;
            }
        """)
        value_label.setHtml(value)

        layout.addWidget(value_label)

        frame.value_label = value_label
        return frame

    def set_trend_series_visible(self, series_name, visible):
        self.trend_visibility[str(series_name)] = bool(visible)
        if hasattr(self, "figure"):
            self.refresh_dashboard()

    def refresh_dashboard(self):
        log.info(">>> ENTER refresh_dashboard()")
        log.info(f"Canvas ID → {id(self.canvas) if hasattr(self,'canvas') else 'NO CANVAS'}")

        if not hasattr(self, "figure"):
            return

        start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
        end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

        DETECTIONS = self.dashboard_detections or []
        XDR_DETECTIONS = self.dashboard_xdr_detections or []
        EMAILS = self.dashboard_emails or []
        FILES = self.dlp_rows or []
        OUTBOUND_MAILS = self.mailscreen_rows or []

        COMPARE_DETECTIONS = self.dashboard_compare_detections or []
        COMPARE_XDR_DETECTIONS = self.dashboard_compare_xdr_detections or []
        COMPARE_EMAILS = self.dashboard_compare_emails or []
        COMPARE_FILES = self.dashboard_compare_dlp or []
        COMPARE_OUTBOUND_MAILS = self.dashboard_compare_mailscreen or []

        log.info(f"DETECTIONS LENGTH → {len(DETECTIONS)}")
        log.info(f"XDR DETECTIONS LENGTH → {len(XDR_DETECTIONS)}")
        log.info(f"EMAILS LENGTH → {len(EMAILS)}")
        log.info(f"FILES LENGTH → {len(FILES)}")
        log.info(f"OUTBOUND MAILS LENGTH → {len(OUTBOUND_MAILS)}")
        log.info(f"COMPARE DETECTIONS LENGTH → {len(COMPARE_DETECTIONS)}")
        log.info(f"COMPARE XDR DETECTIONS LENGTH → {len(COMPARE_XDR_DETECTIONS)}")
        log.info(f"COMPARE EMAILS LENGTH → {len(COMPARE_EMAILS)}")
        log.info(f"COMPARE FILES LENGTH → {len(COMPARE_FILES)}")
        log.info(f"COMPARE OUTBOUND MAILS LENGTH → {len(COMPARE_OUTBOUND_MAILS)}")

        log.info(f"DASHBOARD LOAD → {start_date} ~ {end_date}")
        log.info(f"DASHBOARD DET COUNT → {len(DETECTIONS)}")


        # ==============================
        # 🔥 엔드포인트 집계
        # ==============================
        pc_count = 0
        server_count = 0

        for e in ENDPOINTS:
            if not isinstance(e, dict):
                continue
            if e.get("type") == "computer":
                pc_count += 1
            elif e.get("type") == "server":
                server_count += 1

        endpoint_html = self.metric_table_html([
            ("PC", f"{pc_count} 대", UI_THEME["accent"]),
            ("Server", f"{server_count} 대", UI_THEME["accent"]),
        ])
        self.card_endpoint.value_label.setText(endpoint_html)

        # ==============================
        # 🔥 Organization 집계
        # DeptCode 중복 제거 + User None 제외
        # ==============================
        valid_dept_codes = set()
        valid_users = set()

        for d in ORGS:
            if not isinstance(d, dict):
                continue

            code = str(d.get("deptCode", "")).strip()
            if not code:
                continue

            users = d.get("users", [])
            if not isinstance(users, list):
                users = []

            real_users = []
            for u in users:
                if isinstance(u, dict):
                    uname = str(u.get("name", "")).strip()
                else:
                    uname = str(u).strip()

                if uname and uname.lower() != "none":
                    real_users.append(uname)
                    valid_users.add(uname)

            if real_users:
                valid_dept_codes.add(code)

        org_count = len(valid_dept_codes)
        user_count = len(valid_users)

        org_html = self.metric_table_html([
            ("조직부서", f"{org_count} 개", UI_THEME["accent"]),
            ("사원 수", f"{user_count} 명", UI_THEME["accent"]),
        ])
        self.card_org.value_label.setText(org_html)

        # ==============================
        # 🔥 파일 Top6
        # ==============================
        file_counter = Counter()

        for d in DETECTIONS:
            raw = d.get("rawData", {})
            name, _ = get_display_file_and_sha(raw)
            if name and name != "None":
                file_counter[name] += 1

        top_files = file_counter.most_common(6)

        # 🔥 HTML 링크 방식으로 교체 (layout addWidget 제거)
        links = []
        for name, cnt in top_files:
            links.append(
                f"<tr>"
                f"<td style='padding:2px 12px 2px 0;'>"
                f"<a href='{name}' style='text-decoration:none; color:#111827; font-weight:700;'>{name}</a>"
                f"</td>"
                f"<td align='right' style='padding:2px 0; color:#111827; font-weight:700;'>({cnt})</td>"
                f"</tr>"
            )

        html = "".join(links)
        html = f"<table width='100%' cellspacing='0' cellpadding='0' style='line-height:22px; font-size:13px;'>{html}</table>"

        self.card_file_top.value_label.setText(html)
        self.card_file_top.value_label.setTextFormat(Qt.RichText)
        self.card_file_top.value_label.setOpenExternalLinks(False)

        # 기존 연결이 여러 번 붙는 것 방지
        try:
            self.card_file_top.value_label.linkActivated.disconnect()
        except:
            pass

        self.card_file_top.value_label.linkActivated.connect(self.jump_to_detection)

        log.info("STEP 1 OK - FILE TOP3 DONE")

        # ==============================
        # 🔥 해시 Top6
        # ==============================
        hash_counter = Counter()

        for d in DETECTIONS:
            raw = d.get("rawData", {})
            _, sha = get_display_file_and_sha(raw)
            if sha and sha != "None":
                hash_counter[sha] += 1

        top_hash = hash_counter.most_common(6)

        # 🔥 HTML 링크 방식 (layout addWidget 제거)
        links = []
        for sha, cnt in top_hash:
            short_sha = sha[:20] + "..."
            links.append(
                f"<tr>"
                f"<td style='padding:2px 12px 2px 0;'>"
                f"<a href='{sha}' style='text-decoration:none; color:#111111; font-weight:600;'>{short_sha}</a>"
                f"</td>"
                f"<td align='right' style='padding:2px 0; color:#111827; font-weight:700;'>({cnt})</td>"
                f"</tr>"
            )

        html = "".join(links)
        html = f"<table width='100%' cellspacing='0' cellpadding='0' style='line-height:22px; font-size:13px;'>{html}</table>"


        self.card_hash_top.value_label.setText(html)
        self.card_hash_top.value_label.setTextFormat(Qt.RichText)
        self.card_hash_top.value_label.setOpenExternalLinks(False)

        # 중복 connect 방지
        try:
            self.card_hash_top.value_label.linkActivated.disconnect()
        except:
            pass

        self.card_hash_top.value_label.linkActivated.connect(self.jump_to_detection)

        log.info("STEP 2 OK - HASH TOP3 DONE")

        # ==============================
        # 🔥 폴더 용량
        # ==============================
        logs_size = format_size_text(get_dir_size_bytes(LOG_DIR))
        cache_size = format_size_text(get_dir_size_bytes(CACHE_DIR))
        export_size = format_size_text(get_dir_size_bytes(EXPORT_DIR))
        report_size = format_size_text(get_dir_size_bytes(REPORT_DIR))
        env_size = format_size_text(get_dir_size_bytes(ENV_DIR))

        folder_html = f"""
        <table width='100%' cellspacing='0' cellpadding='0' style='line-height:22px; font-size:13px;'>
            <tr><td>Logs</td><td align='right'>{logs_size}</td></tr>
            <tr><td>Cache</td><td align='right'>{cache_size}</td></tr>
            <tr><td>Exports</td><td align='right'>{export_size}</td></tr>
            <tr><td>Reports</td><td align='right'>{report_size}</td></tr>
            <tr><td>Env</td><td align='right'>{env_size}</td></tr>
        </table>
        """

        self.card_summary.value_label.setText(folder_html)
        self.card_summary.value_label.setTextFormat(Qt.RichText)


        # ==============================
        # 🔥 날짜 생성
        # ==============================
        start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
        end_date = self.end_date_edit.date().toString("yyyy-MM-dd")
        log.info(f"그래프 날짜범위: {self.start_date_edit.date().toString('yyyy-MM-dd')} ~ {self.end_date_edit.date().toString('yyyy-MM-dd')}")
        log.info(f"DETECTIONS: {len(DETECTIONS)}")

        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")

        date_list = []
        current = start_dt
        while current <= end_dt:
            date_list.append(current.strftime("%Y-%m-%d"))
            current += timedelta(days=1)

        if not date_list:
            QMessageBox.warning(self, "날짜 오류", "시작일이 종료일보다 늦습니다.")
            return

        x_dates = [datetime.strptime(d, "%Y-%m-%d") for d in date_list]

        det_counts = defaultdict(int)
        xdr_counts = defaultdict(int)
        mail_counts = defaultdict(int)
        outbound_mail_counts = defaultdict(int)
        file_counts = defaultdict(int)

        # -------------------------
        # 🔥 Detection 집계 (KST 기준)
        # -------------------------
        for d in DETECTIONS:
            t = d.get("time")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                det_counts[kst.strftime("%Y-%m-%d")] += 1
            except:
                continue

        # -------------------------
        # 🔥 Email - XDR 집계 (KST 기준)
        # -------------------------
        for d in XDR_DETECTIONS:
            t = d.get("time")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                xdr_counts[kst.strftime("%Y-%m-%d")] += 1
            except:
                continue

        # -------------------------
        # 🔥 Email 집계 (KST 기준)
        # -------------------------
        for m in EMAILS:
            t = m.get("receivedAt")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                mail_counts[kst.strftime("%Y-%m-%d")] += 1   # ← 여기 mail_counts!!!
            except:
                continue

        # -------------------------
        # 🔥 Outbound Mail 집계 (MailScreen 날짜 기준)
        # -------------------------
        for m in OUTBOUND_MAILS:
            if not isinstance(m, dict):
                continue
            t = str(m.get("date", "") or "").strip()
            if len(t) >= 10:
                outbound_mail_counts[t[:10]] += 1

        # -------------------------
        # 🔥 File 집계 (KST 기준)
        # -------------------------
        for f in FILES:
            if not isinstance(f, dict):
                continue

            t = str(f.get("eventtimelocal", "")).strip()
            if len(t) >= 10:
                day = t[:10]
                file_counts[day] += 1

        det_values = [det_counts[d] for d in date_list]
        xdr_values = [xdr_counts[d] for d in date_list]
        mail_values = [mail_counts[d] for d in date_list]
        outbound_mail_values = [outbound_mail_counts[d] for d in date_list]
        file_values = [file_counts[d] for d in date_list]


        # =========================
        # 🔥 비교용 집계 (선택 범위 밖 날짜 포함)
        # =========================
        compare_det_counts = defaultdict(int)
        compare_xdr_counts = defaultdict(int)
        compare_mail_counts = defaultdict(int)
        compare_outbound_mail_counts = defaultdict(int)
        compare_file_counts = defaultdict(int)

        for d in COMPARE_DETECTIONS:
            t = d.get("time")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                compare_det_counts[kst.strftime("%Y-%m-%d")] += 1
            except:
                continue

        for d in COMPARE_XDR_DETECTIONS:
            t = d.get("time")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                compare_xdr_counts[kst.strftime("%Y-%m-%d")] += 1
            except:
                continue

        for m in COMPARE_EMAILS:
            t = m.get("receivedAt")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                compare_mail_counts[kst.strftime("%Y-%m-%d")] += 1
            except:
                continue

        for m in COMPARE_OUTBOUND_MAILS:
            if not isinstance(m, dict):
                continue
            t = str(m.get("date", "") or "").strip()
            if len(t) >= 10:
                compare_outbound_mail_counts[t[:10]] += 1

        for f in COMPARE_FILES:
            if not isinstance(f, dict):
                continue

            t = str(f.get("eventtimelocal", "")).strip()
            if len(t) >= 10:
                day = t[:10]
                compare_file_counts[day] += 1

        # =========================
        # 🔥 오늘 기준 전일 / 전월 계산
        # =========================


        today_str = self.end_date_edit.date().toString("yyyy-MM-dd")   # 선택한 종료일 기준

        # 그래프용 map
        day_map_det = dict(zip(date_list, det_values))
        day_map_xdr = dict(zip(date_list, xdr_values))
        day_map_mail = dict(zip(date_list, mail_values))
        day_map_outbound_mail = dict(zip(date_list, outbound_mail_values))
        day_map_file = dict(zip(date_list, file_values))

        # 비교용 map (선택 범위 밖 날짜 포함)
        compare_day_map_det = dict(compare_det_counts)
        compare_day_map_xdr = dict(compare_xdr_counts)
        compare_day_map_mail = dict(compare_mail_counts)
        compare_day_map_outbound_mail = dict(compare_outbound_mail_counts)
        compare_day_map_file = dict(compare_file_counts)

        def calc_percent(prev, last):
            if prev <= 0:
                return None
            return ((last - prev) / prev) * 100

        def format_block(title, percent):
            if percent is None:
                return "No Data", "#6b7280"

            if percent > 0:
                arrow = "▲"
                color = "#16a34a"  # 초록
            elif percent < 0:
                arrow = "▼"
                color = "#dc2626"  # 빨강
            else:
                arrow = "■"
                color = "#6b7280"  # 회색

            return f"{arrow} {percent:+.1f}%", color


        # ---- 전일 대비 ----
        last_dt = datetime.strptime(today_str, "%Y-%m-%d")
        yesterday = (last_dt - timedelta(days=1)).strftime("%Y-%m-%d")

        det_daily = None
        xdr_daily = None
        mail_daily = None
        outbound_mail_daily = None
        file_daily = None

        det_daily = calc_percent(compare_day_map_det.get(yesterday, 0), compare_day_map_det.get(today_str, 0))
        xdr_daily = calc_percent(compare_day_map_xdr.get(yesterday, 0), compare_day_map_xdr.get(today_str, 0))
        mail_daily = calc_percent(compare_day_map_mail.get(yesterday, 0), compare_day_map_mail.get(today_str, 0))
        outbound_mail_daily = calc_percent(compare_day_map_outbound_mail.get(yesterday, 0), compare_day_map_outbound_mail.get(today_str, 0))
        file_daily = calc_percent(compare_day_map_file.get(yesterday, 0), compare_day_map_file.get(today_str, 0))

        daily_det_text, daily_det_color = format_block("Detection - XDR", det_daily)
        daily_xdr_text, daily_xdr_color = format_block("Email - XDR", xdr_daily)
        daily_mail_text, daily_mail_color = format_block("Inbound Mail", mail_daily)
        daily_outbound_mail_text, daily_outbound_mail_color = format_block("Outbound Mail", outbound_mail_daily)
        daily_file_text, daily_file_color = format_block("File", file_daily)

        # ---- 전월 대비 ----
        one_month_ago = (last_dt - relativedelta(months=1)).strftime("%Y-%m-%d")

        det_month = None
        xdr_month = None
        mail_month = None
        outbound_mail_month = None
        file_month = None

        det_month = calc_percent(compare_day_map_det.get(one_month_ago, 0), compare_day_map_det.get(today_str, 0))
        xdr_month = calc_percent(compare_day_map_xdr.get(one_month_ago, 0), compare_day_map_xdr.get(today_str, 0))
        mail_month = calc_percent(compare_day_map_mail.get(one_month_ago, 0), compare_day_map_mail.get(today_str, 0))
        outbound_mail_month = calc_percent(compare_day_map_outbound_mail.get(one_month_ago, 0), compare_day_map_outbound_mail.get(today_str, 0))
        file_month = calc_percent(compare_day_map_file.get(one_month_ago, 0), compare_day_map_file.get(today_str, 0))

        monthly_det_text, monthly_det_color = format_block("Detection - XDR", det_month)
        monthly_xdr_text, monthly_xdr_color = format_block("Email - XDR", xdr_month)
        monthly_mail_text, monthly_mail_color = format_block("Inbound Mail", mail_month)
        monthly_outbound_mail_text, monthly_outbound_mail_color = format_block("Outbound Mail", outbound_mail_month)
        monthly_file_text, monthly_file_color = format_block("File", file_month)


        # ==============================
        # 🔥 그래프
        # ==============================
        log.info("STEP 7 - BEFORE CLEAR FIGURE")

        self.figure.clf()
        ax = self.figure.add_subplot(111)

        trend_series = [
            {
                "name": "Detection - XDR",
                "values": det_values,
                "color": self.trend_colors.get("Detection - XDR", UI_THEME["accent"]),
                "offset": (-14, 8),
                "ha": "right",
                "va": "bottom",
            },
            {
                "name": "Email - XDR",
                "values": xdr_values,
                "color": self.trend_colors.get("Email - XDR", UI_THEME["accent_light"]),
                "offset": (14, 8),
                "ha": "left",
                "va": "bottom",
            },
            {
                "name": "Inbound Mail",
                "values": mail_values,
                "color": self.trend_colors.get("Email", "#14b8a6"),
                "offset": (-14, -12),
                "ha": "right",
                "va": "top",
            },
            {
                "name": "Outbound Mail",
                "values": outbound_mail_values,
                "color": self.trend_colors.get("Outbound Mail", "#ec4899"),
                "offset": (14, -16),
                "ha": "left",
                "va": "top",
            },
            {
                "name": "File",
                "values": file_values,
                "color": self.trend_colors.get("File", "#f59e0b"),
                "offset": (0, 0),
                "ha": "center",
                "va": "center",
            },
        ]
        active_series = [s for s in trend_series if self.trend_visibility.get(s["name"], True)]

        for series in active_series:
            ax.plot(
                x_dates,
                series["values"],
                marker='o',
                linewidth=2.8,
                color=series["color"],
                label=series["name"],
            )

        # 🔥 tick 강제 고정
        ax.set_xticks(x_dates)
        ax.set_xticklabels([d.strftime("%m-%d") for d in x_dates])

        # 🔥 범위 정확히 시작~끝
        ax.set_xlim(
            x_dates[0] - timedelta(days=0.3),
            x_dates[-1] + timedelta(days=0.3)
        )

        self.figure.autofmt_xdate()

        self.figure.patch.set_facecolor("#ffffff")
        ax.set_facecolor("#ffffff")
        ax.grid(True, linestyle="--", linewidth=0.8, color=UI_THEME["border_soft"], alpha=0.9)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color(UI_THEME["border"])
        ax.spines["bottom"].set_color(UI_THEME["border"])
        ax.tick_params(axis="both", colors=UI_THEME["text_soft"], labelsize=10)
        # The card header already displays the chart title; avoid a duplicate
        # matplotlib title because it can render with broken-looking spacing.
        ax.set_title("")

        if active_series:
            legend = ax.legend(
                loc="upper center",
                bbox_to_anchor=(0.5, 1.16),
                ncol=min(5, len(active_series)),
                frameon=False,
                columnspacing=1.4,
                handlelength=1.8,
            )
            for text in legend.get_texts():
                text.set_color(UI_THEME["text_soft"])
                text.set_fontsize(10)

        max_y = max([max(series["values"] or [0]) for series in active_series] + [1])
        ax.set_ylim(0, max_y * 1.8)

        # 🔥 숫자 표시
        for series in active_series:
            dx, dy = series["offset"]
            for i, x in enumerate(x_dates):
                value = series["values"][i]
                txt = ax.annotate(
                    str(value),
                    xy=(x, value),
                    xytext=(dx, dy),
                    textcoords="offset points",
                    fontsize=9,
                    fontweight="bold",
                    color=series["color"],
                    ha=series["ha"],
                    va=series["va"],
                    zorder=5
                )
                txt.set_path_effects([
                    path_effects.Stroke(linewidth=2, foreground='white'),
                    path_effects.Normal()
                ])

        self.figure.subplots_adjust(
            left=0.10,
            right=0.98,
            top=0.78,
            bottom=0.25
        )


        # ==============================
        # 🔥 전일 대비 (오른쪽 표시용)
        # ==============================
        percent_html = f"""
        <table width='100%' cellspacing='0' cellpadding='0' style='font-size:12px; line-height:18px;'>
            <tr>
                <td width='38%'></td>
                <td width='31%' align='center' style='color:#6b7280; font-size:11px; font-weight:900;'>전일 대비</td>
                <td width='31%' align='right' style='color:#6b7280; font-size:11px; font-weight:900;'>전월 대비</td>
            </tr>
            <tr><td colspan='3' style='height:4px; border-bottom:1px solid #e5e7eb;'></td></tr>
            <tr>
                <td style='padding-top:4px; color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;'>Detection - XDR</td>
                <td align='center' style='padding-top:4px; color:{daily_det_color}; font-size:12px; font-weight:900;'>{daily_det_text}</td>
                <td align='right' style='padding-top:4px; color:{monthly_det_color}; font-size:12px; font-weight:900;'>{monthly_det_text}</td>
            </tr>
            <tr><td colspan='3' style='height:4px; border-bottom:1px solid #e5e7eb;'></td></tr>
            <tr>
                <td style='padding-top:4px; color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;'>Email - XDR</td>
                <td align='center' style='padding-top:4px; color:{daily_xdr_color}; font-size:12px; font-weight:900;'>{daily_xdr_text}</td>
                <td align='right' style='padding-top:4px; color:{monthly_xdr_color}; font-size:12px; font-weight:900;'>{monthly_xdr_text}</td>
            </tr>
            <tr><td colspan='3' style='height:4px; border-bottom:1px solid #e5e7eb;'></td></tr>
            <tr>
                <td style='padding-top:4px; color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;'>Inbound Mail</td>
                <td align='center' style='padding-top:4px; color:{daily_mail_color}; font-size:12px; font-weight:900;'>{daily_mail_text}</td>
                <td align='right' style='padding-top:4px; color:{monthly_mail_color}; font-size:12px; font-weight:900;'>{monthly_mail_text}</td>
            </tr>
            <tr><td colspan='3' style='height:4px; border-bottom:1px solid #e5e7eb;'></td></tr>
            <tr>
                <td style='padding-top:4px; color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;'>Outbound Mail</td>
                <td align='center' style='padding-top:4px; color:{daily_outbound_mail_color}; font-size:12px; font-weight:900;'>{daily_outbound_mail_text}</td>
                <td align='right' style='padding-top:4px; color:{monthly_outbound_mail_color}; font-size:12px; font-weight:900;'>{monthly_outbound_mail_text}</td>
            </tr>
            <tr><td colspan='3' style='height:4px; border-bottom:1px solid #e5e7eb;'></td></tr>
            <tr>
                <td style='padding-top:4px; color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;'>File</td>
                <td align='center' style='padding-top:4px; color:{daily_file_color}; font-size:12px; font-weight:900;'>{daily_file_text}</td>
                <td align='right' style='padding-top:4px; color:{monthly_file_color}; font-size:12px; font-weight:900;'>{monthly_file_text}</td>
            </tr>
        </table>
"""

        self.percent_label.setText(percent_html)
        self.percent_label.setTextFormat(Qt.RichText)


        # ==============================
        # 🔥 하단 Top10
        # ==============================
        TOP_N = 10
        self.top_table.setRowCount(TOP_N)

        hostname_counter = Counter()
        rule_counter = Counter()
        sender_counter = Counter()

        for d in DETECTIONS:
            raw = d.get("rawData", {})
            hostname = raw.get("meta_hostname")
            if hostname:
                hostname_counter[hostname] += 1

            dd = d.get("detectionDescription", {})
            if isinstance(dd, dict):
                rule = dd.get("createdReasonId")
                if rule:
                    rule_counter[rule] += 1

        for m in EMAILS:
            ip = m.get("clientIp")
            if ip:
                sender_counter[ip] += 1

        top_host = hostname_counter.most_common(TOP_N)
        top_rule = rule_counter.most_common(TOP_N)
        top_sender = sender_counter.most_common(TOP_N)

        while len(top_host) < TOP_N:
            top_host.append(("None", 0))
        while len(top_rule) < TOP_N:
            top_rule.append(("None", 0))
        while len(top_sender) < TOP_N:
            top_sender.append(("None", 0))

        self.top_table.setRowCount(TOP_N)

        for i in range(TOP_N):
            self.top_table.setItem(i, 0,
                QTableWidgetItem(f"{top_host[i][0]} ({top_host[i][1]})"))
            self.top_table.setItem(i, 1,
                QTableWidgetItem(f"{top_rule[i][0]} ({top_rule[i][1]})"))
            self.top_table.setItem(i, 2,
                QTableWidgetItem(f"{top_sender[i][0]} ({top_sender[i][1]})"))

        # ==============================
        # 🔥 오른쪽 Summary 카드
        # ==============================

        # Detection - XDR Summary
        det_host_counter = Counter()
        det_rule_counter = Counter()
        det_file_counter = Counter()

        for d in DETECTIONS:
            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                continue

            host = raw.get("meta_hostname")
            if host:
                det_host_counter[host] += 1

            dd = d.get("detectionDescription", {})
            rule = dd.get("createdReasonId") if isinstance(dd, dict) else None
            if rule:
                det_rule_counter[rule] += 1

            file_name, _ = get_display_file_and_sha(raw)
            if file_name and file_name != "None":
                det_file_counter[file_name] += 1

        det_host = det_host_counter.most_common(1)
        det_rule = det_rule_counter.most_common(1)
        det_file = det_file_counter.most_common(1)

        det_html = f"""
        <div style='line-height:22px;'>
        Top Host : {det_host[0][0]} ({det_host[0][1]})<br>
        Top Rule : {det_rule[0][0]} ({det_rule[0][1]})<br>
        Top File : {det_file[0][0]} ({det_file[0][1]})
        </div>
        """ if det_host and det_rule and det_file else """
        <div style='line-height:22px;'>No Data</div>
        """

        self.card_det_summary.value_label.setHtml(det_html)

        # Email - XDR Summary
        xdr_rule_counter = Counter()
        xdr_from_counter = Counter()
        xdr_ip_counter = Counter()

        for d in XDR_DETECTIONS:
            row_data = extract_xdr_email_fields(d)

            if row_data["rule"] and row_data["rule"] != "None":
                xdr_rule_counter[row_data["rule"]] += 1
            if row_data["from"] and row_data["from"] != "None":
                xdr_from_counter[row_data["from"]] += 1
            if row_data["sender_ip"] and row_data["sender_ip"] != "None":
                xdr_ip_counter[row_data["sender_ip"]] += 1

        xdr_rule = xdr_rule_counter.most_common(1)
        xdr_from = xdr_from_counter.most_common(1)
        xdr_ip = xdr_ip_counter.most_common(1)

        xdr_html = f"""
        <div style='line-height:22px;'>
        Top Rule : {xdr_rule[0][0]} ({xdr_rule[0][1]})<br>
        Top From : {xdr_from[0][0]} ({xdr_from[0][1]})<br>
        Top Sender IP : {xdr_ip[0][0]} ({xdr_ip[0][1]})
        </div>
        """ if xdr_rule and xdr_from and xdr_ip else """
        <div style='line-height:22px;'>No Data</div>
        """

        self.card_xdr_summary.value_label.setHtml(xdr_html)

        # Email Summary
        email_ip_counter = Counter()
        email_reason_counter = Counter()
        email_to_counter = Counter()

        for m in EMAILS:
            ip = m.get("clientIp")
            reason = m.get("reason")

            if ip:
                email_ip_counter[str(ip)] += 1
            if reason:
                email_reason_counter[str(reason)] += 1

            to_list = [email_addr(x) for x in (m.get("to", []) or []) if isinstance(x, dict)]
            for to in to_list:
                if to:
                    email_to_counter[to] += 1

        email_ip = email_ip_counter.most_common(1)
        email_reason = email_reason_counter.most_common(1)
        email_to = email_to_counter.most_common(1)

        email_html = f"""
        <div style='line-height:22px;'>
        Top Sender IP : {email_ip[0][0]} ({email_ip[0][1]})<br>
        Top Reason : {email_reason[0][0]} ({email_reason[0][1]})<br>
        Top To : {email_to[0][0]} ({email_to[0][1]})
        </div>
        """ if email_ip and email_reason and email_to else """
        <div style='line-height:22px;'>No Data</div>
        """

        self.card_email_summary.value_label.setText(email_html)

        # File Summary
        file_machine_counter = Counter()
        file_source_counter = Counter()
        file_dest_counter = Counter()

        for r in self.dlp_rows:
            if not isinstance(r, dict):
                continue

            machine = str(r.get("machine_name", "None"))
            source = str(r.get("filename", "None"))
            dest = str(r.get("destination", "None"))

            if machine and machine != "None":
                file_machine_counter[machine] += 1
            if source and source != "None":
                file_source_counter[source] += 1
            if dest and dest != "None":
                file_dest_counter[dest] += 1

        file_machine = file_machine_counter.most_common(1)
        file_source = file_source_counter.most_common(1)
        file_dest = file_dest_counter.most_common(1)

        file_html = f"""
        <div style='line-height:22px;'>
        Top Machine : {file_machine[0][0]} ({file_machine[0][1]})<br>
        Top Source : {file_source[0][0]} ({file_source[0][1]})<br>
        Top Destination : {file_dest[0][0]} ({file_dest[0][1]})
        </div>
        """ if file_machine and file_source and file_dest else """
        <div style='line-height:22px;'>No Data</div>
        """

        self.card_file_summary.value_label.setHtml(file_html)

        log.info(">>> DRAW CANVAS")
        self.canvas.draw_idle()
        log.info(">>> EXIT refresh_dashboard()")

    def on_file_click(self, event):
        text = self.card_file_top.value_label.text()
        if not text:
            return

        first_line = text.split("\n")[0]
        keyword = first_line.split(" (")[0]

        self.go_to_detection_with_filter(keyword)


    def on_hash_click(self, event):
        text = self.card_hash_top.value_label.text()
        if not text:
            return

        first_line = text.split("\n")[0]
        keyword = first_line.split(" (")[0]

        self.go_to_detection_with_filter(keyword)


    def go_to_detection_with_filter(self, keyword):
        widget = self.select_logical_tab("Detection - XDR")
        if not widget:
            return

        search_box = widget.findChild(QLineEdit)
        if search_box:
            search_box.setText(keyword)
            search_box.returnPressed.emit()

    def jump_to_detection(self, keyword):
        tab = self.select_logical_tab("Detection - XDR")
        if not tab:
            return

        search_box = tab.findChild(QLineEdit)
        combo = tab.findChild(QComboBox)

        if combo:
            combo.setCurrentText("ALL")

        if search_box:
            search_box.setText(keyword)
            search_box.returnPressed.emit()


    # ==================================================
    # Detection Tab
    # ==================================================
    def tab_detection_xdr(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # ===============================
        # 🔎 Multi Search UI (wrapper)
        # ===============================
        search_wrapper = QWidget()
        search_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        search_v = QVBoxLayout(search_wrapper)
        search_v.setContentsMargins(0, 0, 0, 4)
        search_v.setSpacing(6)

        self.search_container = QVBoxLayout()
        self.search_container.setContentsMargins(0, 0, 0, 0)
        self.search_container.setSpacing(6)
        search_v.addLayout(self.search_container)

        # ===============================
        # Table
        # ===============================
        table = QTableWidget()
        headers = [
            "Time",
            "Hostname",
            "Dept",
            "Username",
            "Private IP",
            "Public IP",
            "File",
            "SHA256",
            "Rule",
            "Lineage",
        ]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {4: "ip", 5: "ip", 7: "sha256"})

        # ===============================
        # refresh (먼저 정의)
        # ===============================
        def refresh():
            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            data = self.detection_detections or []


            # ✅ AND 조건 수집 (row는 QWidget로 add됨)
            search_conditions = []
            for i in range(self.search_container.count()):
                item = self.search_container.itemAt(i)
                row = item.widget() if item else None
                if not row:
                    continue
                row_layout = row.layout()
                if not row_layout or row_layout.count() < 2:
                    continue

                combo = row_layout.itemAt(0).widget()
                edit = row_layout.itemAt(1).widget()
                if not combo or not edit:
                    continue

                v = edit.text().strip().lower()
                if v:
                    search_conditions.append((combo.currentText(), v))

            start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

            for d in data:
                if not isinstance(d, dict):
                    continue

                event_time = d.get("time")
                if not event_time:
                    continue

                event_date = kst_time(event_time)[:10]
                if event_date < start_date or event_date > end_date:
                    continue

                sensor = d.get("sensor", {})
                if not isinstance(sensor, dict) or sensor.get("type") != "endpoint":
                    continue

                raw = d.get("rawData", {}) if isinstance(d.get("rawData"), dict) else {}

                hostname = raw.get("meta_hostname", "None")
                identity = resolve_identity_by_hostname(hostname)
                dept_name = identity["dept_name"]
                user_name = identity["user_name"]

                private_ip = raw.get("meta_ip_address") or "None"
                public_ip = raw.get("meta_public_ip") or "None"

                file_name, sha = get_display_file_and_sha(raw)

                rule = "None"
                dd = d.get("detectionDescription", {})
                if isinstance(dd, dict):
                    rule = dd.get("createdReasonId", "None") or "None"
                if rule == "None":
                    rule = d.get("rule", "None") or "None"

                lineage = "None"
                assoc = raw.get("associated_lineages", [])
                if isinstance(assoc, list):
                    for l in assoc:
                        if not isinstance(l, dict):
                            continue
                        names = [
                            x.get("name")
                            for x in (l.get("lineage", []) or [])
                            if isinstance(x, dict) and x.get("name")
                        ]
                        if names:
                            lineage = " -> ".join(reversed(names))
                            break

                raw_str = json.dumps(d, ensure_ascii=False).lower()

                matched = True
                for field, key in search_conditions:
                    if field == "ALL":
                        row_text = " ".join([
                            str(hostname),
                            str(dept_name),
                            str(user_name),
                            str(private_ip),
                            str(public_ip),
                            str(file_name),
                            str(sha),
                            str(rule),
                            str(lineage),
                        ]).lower()
                        if key not in row_text:
                            matched = False
                            break
                    elif field == "RawData":
                        if key not in raw_str:
                            matched = False
                            break
                    elif field == "Hostname" and key not in str(hostname).lower():
                        matched = False; break
                    elif field == "부서" and key not in str(dept_name).lower():
                        matched = False; break
                    elif field == "사용자명" and key not in str(user_name).lower():
                        matched = False; break
                    elif field == "Private IP" and key not in str(private_ip).lower():
                        matched = False; break
                    elif field == "Public IP" and key not in str(public_ip).lower():
                        matched = False; break
                    elif field == "File" and key not in str(file_name).lower():
                        matched = False; break
                    elif field == "SHA256" and key not in str(sha).lower():
                        matched = False; break
                    elif field == "Rule" and key not in str(rule).lower():
                        matched = False; break
                    elif field == "Lineage" and key not in str(lineage).lower():
                        matched = False; break

                if not matched:
                    continue

                r = table.rowCount()
                table.insertRow(r)

                time_item = QTableWidgetItem(kst_time(event_time))
                time_item.setData(Qt.UserRole, d)

                table.setItem(r, 0, time_item)
                table.setItem(r, 1, QTableWidgetItem(str(hostname)))
                table.setItem(r, 2, QTableWidgetItem(str(dept_name)))
                table.setItem(r, 3, QTableWidgetItem(str(user_name)))
                table.setItem(r, 4, QTableWidgetItem(str(private_ip)))
                table.setItem(r, 5, QTableWidgetItem(str(public_ip)))
                table.setItem(r, 6, QTableWidgetItem(str(file_name)))
                table.setItem(r, 7, QTableWidgetItem(str(sha)))
                table.setItem(r, 8, QTableWidgetItem(str(rule)))
                table.setItem(r, 9, QTableWidgetItem(str(lineage)))

            table.setSortingEnabled(True)
            if sort_column >= 0:
                table.sortItems(sort_column, sort_order)

        # ===============================
        # 🔥 검색줄 생성 (크기/폰트/엔터/버튼 통일)
        # ===============================
        FIELD_W = SEARCH_FIELD_W
        BTN_W = SEARCH_BTN_W
        ROW_H = SEARCH_ROW_H

        def add_search_row(default_field="ALL", default_value="", removable=True, first=False):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            combo = QComboBox()
            combo.addItems([
                "ALL",
                "Hostname",
                "Dept",
                "Username",
                "Private IP",
                "Public IP",
                "File",
                "SHA256",
                "Rule",
                "Lineage",
                "RawData",
            ])
            combo.setCurrentText(default_field)
            combo.setFixedWidth(FIELD_W)
            combo.setFixedHeight(ROW_H)

            # ✅ 폰트/드롭다운 폰트 통일 (스타일시트로 폰트 안 건드림)
            default_font = QApplication.font()

            combo.setFont(default_font)
            combo.view().setFont(default_font)

            edit = QLineEdit()
            edit.setPlaceholderText("Search...")
            edit.setText(default_value)
            edit.setFixedHeight(ROW_H)
            edit.setFont(default_font)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

            row_layout.addWidget(combo, 0)
            row_layout.addWidget(edit, 1)

            if first:
                btn = QPushButton("+")
                btn.setFixedSize(BTN_W, ROW_H)
                btn.clicked.connect(lambda: add_search_row(removable=True, first=False))
                row_layout.addWidget(btn, 0)
            elif removable:
                btn = QPushButton("-")
                btn.setFixedSize(BTN_W, ROW_H)

                def remove_row():
                    row.deleteLater()
                    refresh()

                btn.clicked.connect(remove_row)
                row_layout.addWidget(btn, 0)

            # ✅ 엔터/변경 즉시 검색 (람다 금지, direct)
            edit.returnPressed.connect(refresh)
            combo.currentIndexChanged.connect(refresh)

            self.search_container.addWidget(row)

        # 첫 줄(삭제 불가) + 버튼
        add_search_row(removable=False, first=True)

        layout.addWidget(search_wrapper, 0)
        layout.addWidget(table, 1)

        # expose
        self._refresh_detection = refresh
        refresh()
        return root

    # ==================================================
    # Detection_xdr Tab (Detection과 동일 구조)
    # ==================================================
    def tab_email_xdr(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        search_wrapper = QWidget()
        search_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        search_v = QVBoxLayout(search_wrapper)
        search_v.setContentsMargins(0, 0, 0, 4)
        search_v.setSpacing(6)

        self.xdr_search_container = QVBoxLayout()
        self.xdr_search_container.setContentsMargins(0, 0, 0, 0)
        self.xdr_search_container.setSpacing(6)
        search_v.addLayout(self.xdr_search_container)

        table = QTableWidget()
        headers = [
            "Time", "Rule",
            "Mailbox", "User ID", "User", "Dept",
            "From", "To", "Subject",
            "Sender IP", "IOC", "IOC SHA256", "Detail"
        ]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {9: "ip", 11: "sha256"})

        def refresh():
            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            data = self.xdr_detections or []

            search_conditions = []
            for i in range(self.xdr_search_container.count()):
                item = self.xdr_search_container.itemAt(i)
                row = item.widget() if item else None
                if not row:
                    continue

                row_layout = row.layout()
                if not row_layout or row_layout.count() < 2:
                    continue

                combo = row_layout.itemAt(0).widget()
                edit = row_layout.itemAt(1).widget()
                if not combo or not edit:
                    continue

                v = edit.text().strip().lower()
                if v:
                    search_conditions.append((combo.currentText(), v))

            start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

            for d in data:
                if not isinstance(d, dict):
                    continue

                event_time = d.get("time")
                if not event_time:
                    continue

                event_date = kst_time(event_time)[:10]
                if event_date < start_date or event_date > end_date:
                    continue

                row_data = extract_xdr_email_fields(d)

                raw_str = json.dumps(d, ensure_ascii=False).lower()

                matched = True
                for field, key in search_conditions:
                    if field == "ALL":
                        identity = resolve_identity_by_mailbox(row_data["mailbox"])

                        row_text = " ".join([
                            row_data["rule"],
                            row_data["mailbox"],
                            identity["user_id"],
                            identity["user_name"],
                            identity["dept_name"],
                            row_data["from"],
                            row_data["to"],
                            row_data["subject"],
                            row_data["sender_ip"],
                            row_data["ioc"],
                            row_data["ioc_sha"],
                            row_data["detail"],
                        ]).lower()
                        if key not in row_text:
                            matched = False
                            break

                    elif field == "RawData":
                        if key not in raw_str:
                            matched = False
                            break

                    elif field == "Rule" and key not in row_data["rule"].lower():
                        matched = False
                        break
                    elif field == "Mailbox" and key not in row_data["mailbox"].lower():
                        matched = False
                        break
                    elif field == "User ID":
                        identity = resolve_identity_by_mailbox(row_data["mailbox"])
                        if key not in identity["user_id"].lower():
                            matched = False
                            break
                    elif field == "User":
                        identity = resolve_identity_by_mailbox(row_data["mailbox"])
                        if key not in identity["user_name"].lower():
                            matched = False
                            break
                    elif field == "Dept":
                        identity = resolve_identity_by_mailbox(row_data["mailbox"])
                        if key not in identity["dept_name"].lower():
                            matched = False
                            break
                    elif field == "From" and key not in row_data["from"].lower():
                        matched = False
                        break
                    elif field == "To" and key not in row_data["to"].lower():
                        matched = False
                        break
                    elif field == "Subject" and key not in row_data["subject"].lower():
                        matched = False
                        break
                    elif field == "Sender IP" and key not in row_data["sender_ip"].lower():
                        matched = False
                        break
                    elif field == "IOC" and key not in row_data["ioc"].lower():
                        matched = False
                        break
                    elif field == "IOC SHA256" and key not in row_data["ioc_sha"].lower():
                        matched = False
                        break
                    elif field == "Detail" and key not in row_data["detail"].lower():
                        matched = False
                        break

                if not matched:
                    continue

                identity = resolve_identity_by_mailbox(row_data["mailbox"])

                r = table.rowCount()
                table.insertRow(r)

                time_item = QTableWidgetItem(row_data["time"])
                time_item.setData(Qt.UserRole, row_data["raw"])

                table.setItem(r, 0, time_item)
                table.setItem(r, 1, QTableWidgetItem(row_data["rule"]))
                table.setItem(r, 2, QTableWidgetItem(row_data["mailbox"]))
                table.setItem(r, 3, QTableWidgetItem(identity["user_id"]))
                table.setItem(r, 4, QTableWidgetItem(identity["user_name"]))
                table.setItem(r, 5, QTableWidgetItem(identity["dept_name"]))
                table.setItem(r, 6, QTableWidgetItem(row_data["from"]))
                table.setItem(r, 7, QTableWidgetItem(row_data["to"]))
                table.setItem(r, 8, QTableWidgetItem(row_data["subject"]))
                table.setItem(r, 9, QTableWidgetItem(row_data["sender_ip"]))
                table.setItem(r, 10, QTableWidgetItem(row_data["ioc"]))
                table.setItem(r, 11, QTableWidgetItem(row_data["ioc_sha"]))
                table.setItem(r, 12, QTableWidgetItem(row_data["detail"]))

            table.setSortingEnabled(True)
            if sort_column >= 0:
                table.sortItems(sort_column, sort_order)

        FIELD_W = SEARCH_FIELD_W
        BTN_W = SEARCH_BTN_W
        ROW_H = SEARCH_ROW_H

        def add_search_row(default_field="ALL", removable=True, first=False):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            combo = QComboBox()
            combo.addItems([
                "ALL",
                "Rule",
                "Mailbox",
                "User ID",
                "User",
                "Dept",
                "From",
                "To",
                "Subject",
                "Sender IP",
                "IOC",
                "IOC SHA256",
                "Detail",
                "RawData",
            ])
            combo.setCurrentText(default_field)
            combo.setFixedWidth(FIELD_W)
            combo.setFixedHeight(ROW_H)

            default_font = QApplication.font()
            combo.setFont(default_font)
            combo.view().setFont(default_font)

            edit = QLineEdit()
            edit.setPlaceholderText("Search...")
            edit.setFixedHeight(ROW_H)
            edit.setFont(default_font)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

            row_layout.addWidget(combo, 0)
            row_layout.addWidget(edit, 1)

            if first:
                btn = QPushButton("+")
                btn.setFixedSize(BTN_W, ROW_H)
                btn.clicked.connect(lambda: add_search_row(removable=True, first=False))
                row_layout.addWidget(btn, 0)
            elif removable:
                btn = QPushButton("-")
                btn.setFixedSize(BTN_W, ROW_H)

                def remove_row():
                    row.deleteLater()
                    refresh()

                btn.clicked.connect(remove_row)
                row_layout.addWidget(btn, 0)

            edit.returnPressed.connect(refresh)
            combo.currentIndexChanged.connect(refresh)

            self.xdr_search_container.addWidget(row)

        add_search_row(removable=False, first=True)

        layout.addWidget(search_wrapper, 0)
        layout.addWidget(table, 1)

        self._refresh_detection_xdr = refresh
        refresh()

        return root


    # ==================================================
    # Email Tab (Detection과 동일 구조)
    # ==================================================
    def tab_email(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # ===============================
        # 🔎 Multi Search UI
        # ===============================
        search_wrapper = QWidget()
        search_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        search_v = QVBoxLayout(search_wrapper)
        search_v.setContentsMargins(0, 0, 0, 4)
        search_v.setSpacing(6)

        self.email_search_container = QVBoxLayout()
        self.email_search_container.setContentsMargins(0, 0, 0, 0)
        self.email_search_container.setSpacing(6)
        search_v.addLayout(self.email_search_container)

        # ===============================
        # Table
        # ===============================
        table = QTableWidget()
        headers = ["Received", "From", "To", "CC", "Subject", "Reason", "Sender IP"]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {6: "ip"})

        # ===============================
        # 🔥 refresh
        # ===============================
        def refresh():
            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            data = self.email_emails or []

            # 🔎 AND 검색 조건 수집
            search_conditions = []
            for i in range(self.email_search_container.count()):
                item = self.email_search_container.itemAt(i)
                row = item.widget() if item else None
                if not row:
                    continue

                row_layout = row.layout()
                combo = row_layout.itemAt(0).widget()
                edit = row_layout.itemAt(1).widget()

                v = edit.text().strip().lower()
                if v:
                    search_conditions.append((combo.currentText(), v))

            for m in data:

                start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
                end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

                event_time = m.get("receivedAt")
                if not event_time:
                    continue

                event_date = kst_time(event_time)[:10]
                if event_date < start_date or event_date > end_date:
                    continue

                if not isinstance(m, dict):
                    continue

                from_addr = email_addr(m.get("from"))
                to_list = [email_addr(x) for x in (m.get("to", []) or []) if isinstance(x, dict)]
                cc_list = [email_addr(x) for x in (m.get("cc", []) or []) if isinstance(x, dict)]

                subject = str(m.get("subject", ""))
                reason = str(m.get("reason", "None"))
                cip = str(m.get("clientIp", ""))

                # 🔥 AND 조건 적용
                matched = True
                for field, key in search_conditions:

                    if field == "ALL":
                        row_text = (
                            from_addr +
                            ",".join(to_list) +
                            ",".join(cc_list) +
                            subject +
                            reason +
                            cip
                        ).lower()

                        if key not in row_text:
                            matched = False
                            break

                    elif field == "From" and key not in from_addr.lower():
                        matched = False; break

                    elif field == "To" and key not in ",".join(to_list).lower():
                        matched = False; break

                    elif field == "CC" and key not in ",".join(cc_list).lower():
                        matched = False; break

                    elif field == "Subject" and key not in subject.lower():
                        matched = False; break

                    elif field == "Reason" and key not in reason.lower():
                        matched = False; break

                    elif field == "Sender IP" and key not in cip.lower():
                        matched = False; break

                if not matched:
                    continue

                if not to_list:
                    continue

                for to in to_list:
                    r = table.rowCount()
                    table.insertRow(r)

                    time_item = QTableWidgetItem(kst_time(event_time))
                    time_item.setData(Qt.UserRole, m)

                    table.setItem(r, 0, time_item)
                    table.setItem(r, 1, QTableWidgetItem(from_addr))
                    table.setItem(r, 2, QTableWidgetItem(to))
                    table.setItem(r, 3, QTableWidgetItem(join_list(cc_list)))
                    table.setItem(r, 4, QTableWidgetItem(subject or "None"))
                    table.setItem(r, 5, QTableWidgetItem(str(m.get("reason", "None"))))
                    table.setItem(r, 6, QTableWidgetItem(cip or "None"))

            table.setSortingEnabled(True)
            if sort_column >= 0:
                table.sortItems(sort_column, sort_order)

        # ===============================
        # 🔥 검색줄 생성
        # ===============================
        FIELD_W = SEARCH_FIELD_W
        BTN_W = SEARCH_BTN_W
        ROW_H = SEARCH_ROW_H

        def add_search_row(default_field="ALL", removable=True, first=False):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            combo = QComboBox()
            combo.addItems([
                "ALL", "From", "To", "CC", "Subject", "Reason", "Sender IP"
            ])

            default_font = QApplication.font()

            combo.setFont(default_font)
            combo.view().setFont(default_font)
            combo.setCurrentText(default_field)
            combo.setFixedWidth(FIELD_W)
            combo.setFixedHeight(ROW_H)

            edit = QLineEdit()
            edit.setPlaceholderText("Search...")
            edit.setFixedHeight(ROW_H)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            edit.setFont(default_font)

            row_layout.addWidget(combo, 0)
            row_layout.addWidget(edit, 1)

            if first:
                btn = QPushButton("+")
                btn.setFixedSize(BTN_W, ROW_H)
                btn.clicked.connect(lambda: add_search_row(removable=True, first=False))
                row_layout.addWidget(btn, 0)
            elif removable:
                btn = QPushButton("-")
                btn.setFixedSize(BTN_W, ROW_H)

                def remove_row():
                    row.deleteLater()
                    refresh()

                btn.clicked.connect(remove_row)
                row_layout.addWidget(btn, 0)

            # 🔥 direct 연결 (람다 없음)
            edit.returnPressed.connect(refresh)
            combo.currentIndexChanged.connect(refresh)

            self.email_search_container.addWidget(row)

        # 첫 줄
        add_search_row(removable=False, first=True)

        layout.addWidget(search_wrapper, 0)
        layout.addWidget(table, 1)

        self._refresh_email = refresh
        refresh()

        return root

    # ==================================================
    # Outbound Mail Tab (MailScreen)
    # ==================================================
    def tab_outbound_mail(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        search_wrapper = QWidget()
        search_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        search_v = QVBoxLayout(search_wrapper)
        search_v.setContentsMargins(0, 0, 0, 4)
        search_v.setSpacing(6)

        self.outbound_search_container = QVBoxLayout()
        self.outbound_search_container.setContentsMargins(0, 0, 0, 0)
        self.outbound_search_container.setSpacing(6)
        search_v.addLayout(self.outbound_search_container)

        table = QTableWidget()
        headers = ["날짜", "메일 처리", "전송 결과", "제목", "발신자 (이메일)", "발신자 명", "소속", "수신자", "크기", "적용 정책", "첨부"]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {})

        def match_text(value, keyword, mode):
            text = str(value or "").lower()
            if mode == "제외":
                return keyword not in text
            return keyword in text

        def refresh():
            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            search_conditions = []
            for i in range(self.outbound_search_container.count()):
                item = self.outbound_search_container.itemAt(i)
                row = item.widget() if item else None
                if not row:
                    continue
                row_layout = row.layout()
                if not row_layout or row_layout.count() < 3:
                    continue
                combo = row_layout.itemAt(0).widget()
                mode_combo = row_layout.itemAt(1).widget()
                edit = row_layout.itemAt(2).widget()
                if not combo or not mode_combo or not edit:
                    continue
                keyword = edit.text().strip().lower()
                if keyword:
                    search_conditions.append((combo.currentText(), mode_combo.currentText(), keyword))

            start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

            for row_data in self.mailscreen_rows or []:
                if not isinstance(row_data, dict):
                    continue
                row_data = enrich_mailscreen_sender_fields(row_data)

                event_date = str(row_data.get("date", ""))[:10]
                if event_date and (event_date < start_date or event_date > end_date):
                    continue

                raw_str = json.dumps(row_data, ensure_ascii=False).lower()
                values = {
                    "날짜": str(row_data.get("date", "")),
                    "메일 처리": str(row_data.get("mail_process", "")),
                    "전송 결과": str(row_data.get("send_result", "")),
                    "제목": str(row_data.get("subject", "")),
                    "발신자 (이메일)": str(row_data.get("sender_email", "") or row_data.get("sender", "")),
                    "발신자 명": str(row_data.get("sender_name", "")),
                    "발신자 상세": str(row_data.get("sender_detail", "")),
                    "소속": str(row_data.get("sender_dept", "") or row_data.get("dept", "")),
                    "수신자": str(row_data.get("receiver", "")),
                    "수신자 상세": str(row_data.get("receiver_detail", "")),
                    "크기": str(row_data.get("size", "")),
                    "적용 정책": str(row_data.get("policy", "")),
                    "첨부": str(row_data.get("attach", "")),
                    "RawData": raw_str,
                }

                matched = True
                for field, mode, keyword in search_conditions:
                    haystack = " ".join(str(v) for v in values.values()) if field == "ALL" else values.get(field, "")
                    if not match_text(haystack, keyword, mode):
                        matched = False
                        break
                if not matched:
                    continue

                r = table.rowCount()
                table.insertRow(r)

                first_item = QTableWidgetItem(values["날짜"] or "None")
                first_item.setData(Qt.UserRole, row_data)
                table.setItem(r, 0, first_item)
                table.setItem(r, 1, QTableWidgetItem(values["메일 처리"] or "None"))
                table.setItem(r, 2, QTableWidgetItem(values["전송 결과"] or "None"))
                table.setItem(r, 3, QTableWidgetItem(values["제목"] or "None"))
                table.setItem(r, 4, QTableWidgetItem(values["발신자 (이메일)"] or "None"))
                table.setItem(r, 5, QTableWidgetItem(values["발신자 명"] or "None"))
                table.setItem(r, 6, QTableWidgetItem(values["소속"] or "None"))
                table.setItem(r, 7, QTableWidgetItem(values["수신자"] or "None"))
                table.setItem(r, 8, QTableWidgetItem(values["크기"] or "None"))
                table.setItem(r, 9, QTableWidgetItem(values["적용 정책"] or "None"))
                table.setItem(r, 10, QTableWidgetItem(values["첨부"] or ""))

                if "실패" in values["전송 결과"]:
                    for col in range(table.columnCount()):
                        item = table.item(r, col)
                        if item:
                            item.setForeground(QColor(UI_THEME["danger_text"]))

            table.setSortingEnabled(True)
            if sort_column >= 0:
                table.sortItems(sort_column, sort_order)

        FIELD_W = SEARCH_FIELD_W
        BTN_W = SEARCH_BTN_W
        ROW_H = SEARCH_ROW_H

        def add_search_row(default_field="ALL", default_mode="포함", removable=True, first=False):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            combo = QComboBox()
            combo.addItems([
                "ALL", "날짜", "메일 처리", "전송 결과", "제목", "발신자 (이메일)", "발신자 명", "발신자 상세",
                "소속", "수신자", "수신자 상세", "크기", "적용 정책", "첨부", "RawData"
            ])
            combo.setCurrentText(default_field)
            combo.setFixedWidth(FIELD_W)
            combo.setFixedHeight(ROW_H)

            mode_combo = QComboBox()
            mode_combo.addItems(["포함", "제외"])
            mode_combo.setCurrentText(default_mode)
            mode_combo.setFixedWidth(SEARCH_MODE_W)
            mode_combo.setFixedHeight(ROW_H)

            default_font = QApplication.font()
            combo.setFont(default_font)
            combo.view().setFont(default_font)
            mode_combo.setFont(default_font)
            mode_combo.view().setFont(default_font)

            edit = QLineEdit()
            edit.setPlaceholderText("Search...")
            edit.setFixedHeight(ROW_H)
            edit.setFont(default_font)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

            row_layout.addWidget(combo, 0)
            row_layout.addWidget(mode_combo, 0)
            row_layout.addWidget(edit, 1)

            if first:
                btn = QPushButton("+")
                btn.setFixedSize(BTN_W, ROW_H)
                btn.clicked.connect(lambda: add_search_row(removable=True, first=False))
                row_layout.addWidget(btn, 0)
            elif removable:
                btn = QPushButton("-")
                btn.setFixedSize(BTN_W, ROW_H)

                def remove_row():
                    row.deleteLater()
                    refresh()

                btn.clicked.connect(remove_row)
                row_layout.addWidget(btn, 0)

            edit.returnPressed.connect(refresh)
            combo.currentIndexChanged.connect(refresh)
            mode_combo.currentIndexChanged.connect(refresh)

            self.outbound_search_container.addWidget(row)

        add_search_row(default_field="ALL", default_mode="포함", removable=False, first=True)

        layout.addWidget(search_wrapper, 0)
        layout.addWidget(table, 1)

        self._refresh_outbound_mail = refresh
        refresh()

        return root

    # ==================================================
    # Endpoint Tab

    # ==================================================
    def tab_endpoint(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        # -------------------------------
        # Search Bar
        # -------------------------------
        search_bar = QHBoxLayout()

        search_option = QComboBox()
        search_option.addItems([
            "ALL",
            "Hostname",
            "User ID",
            "User",
            "Dept",
            "IP"
        ])
        search_option.setCurrentIndex(0)
        search_bar.addWidget(search_option)

        search = QLineEdit()
        search.setPlaceholderText("Search...")
        search_bar.addWidget(search)

        layout.addLayout(search_bar)

        # -------------------------------
        # Table
        # -------------------------------
        table = QTableWidget()
        headers = ["Hostname", "User ID", "User", "Dept", "IP", "Last Seen"]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {4: "ip"})

        # -------------------------------
        # Refresh
        # -------------------------------
        def refresh():
            key = search.text().lower()
            selected = search_option.currentText()

            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            for e in ENDPOINTS:
                if not isinstance(e, dict):
                    continue

                hostname = str(e.get("hostname", "None"))
                person = e.get("associatedPerson", {}) if isinstance(e.get("associatedPerson"), dict) else {}
                user = str(person.get("name", "None"))
                via = str(person.get("viaLogin", ""))

                uid = via.split("\\")[-1] if "\\" in via else via
                ips = e.get("ipv4Addresses", [])
                ips_str = join_list(ips if isinstance(ips, list) else [])
                dept_name, dept_code = get_dept_by_hostname(hostname)

                if key:
                    if selected == "ALL":
                        row_text = f"{hostname}{user}{uid}{dept_name}{ips_str}".lower()
                        if key not in row_text:
                            continue
                    elif selected == "Hostname" and key not in hostname.lower():
                        continue
                    elif selected == "User ID" and key not in uid.lower():
                        continue
                    elif selected == "User" and key not in user.lower():
                        continue
                    elif selected == "IP" and key not in ips_str.lower():
                        continue
                    elif selected == "Dept" and key not in dept_name.lower():
                        continue

                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(hostname))
                table.setItem(row, 1, QTableWidgetItem(uid or "None"))
                table.setItem(row, 2, QTableWidgetItem(user))
                table.setItem(row, 3, QTableWidgetItem(dept_name))
                table.setItem(row, 4, QTableWidgetItem(ips_str))
                table.setItem(row, 5, QTableWidgetItem(kst_time(e.get("lastSeenAt"))))

            table.setSortingEnabled(True)
            table.sortItems(sort_column, sort_order)

        # 🔥 엔터 / 입력 / 옵션 변경 연결
        search.returnPressed.connect(refresh)
        search.textChanged.connect(refresh)
        search_option.currentIndexChanged.connect(refresh)

        layout.addWidget(table)

        self._refresh_endpoint = refresh
        refresh()

        return root

    # ==================================================
    # Organization Tab
    # ==================================================
    def tab_org(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        search_bar = QHBoxLayout()

        search_option = QComboBox()
        search_option.addItems([
            "ALL",
            "DeptCode",
            "DeptName",
            "User"
        ])
        search_option.setCurrentIndex(0)

        search_bar.addWidget(search_option)

        search = QLineEdit()
        search.setPlaceholderText("Search...")

        search_bar.addWidget(search)

        layout.addLayout(search_bar)

        table = QTableWidget()
        headers = ["DeptCode", "DeptName", "User"]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {})

        def refresh():
            key = search.text().lower()
            selected = search_option.currentText()

            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            for d in ORGS:
                if not isinstance(d, dict):
                    continue

                code = str(d.get("deptCode", "None"))
                name = DEPT_MAP.get(code, str(d.get("deptName", "None")))

                users = d.get("users", [])
                if not isinstance(users, list):
                    users = []

                for u in users:
                    if isinstance(u, dict):
                        uname = str(u.get("name", "")).strip()
                    else:
                        uname = str(u).strip()

                    if not uname:
                        continue
                    if uname.lower() == "none":
                        continue

                    row_text = f"{code}{name}{uname}".lower()
                    if key:
                        if selected == "ALL":
                            row_text = f"{code}{name}{uname}".lower()
                            if key not in row_text:
                                continue

                        elif selected == "DeptCode" and key not in code.lower():
                            continue

                        elif selected == "DeptName" and key not in name.lower():
                            continue

                        elif selected == "User" and key not in uname.lower():
                            continue

                    row = table.rowCount()
                    table.insertRow(row)
                    table.setItem(row, 0, QTableWidgetItem(code))
                    table.setItem(row, 1, QTableWidgetItem(name))
                    table.setItem(row, 2, QTableWidgetItem(uname))

            table.setSortingEnabled(True)
            table.sortItems(sort_column, sort_order)

        search.returnPressed.connect(refresh)
        search.textChanged.connect(refresh)
        search_option.currentIndexChanged.connect(refresh)

        layout.addWidget(search)
        layout.addWidget(table)

        self._refresh_org = refresh
        refresh()
        return root


    # ==================================================
    # Live_discover Tab
    # ==================================================
    def tab_live_discover(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        # ===============================
        # 입력 영역
        # ===============================
        form_layout = QHBoxLayout()

        self.easy_mode_combo = QComboBox()
        self.easy_mode_combo.addItems(["Live", "History"])
        self.easy_mode_combo.setFixedWidth(110)

        self.easy_query_type_combo = QComboBox()
        self.easy_query_type_combo.addItems([
            "Process",
            "Service",
            "Scheduled Task",
            "Installed Program",
            "Network Connection",
            "File Search",
        ])
        self.easy_query_type_combo.setFixedWidth(160)
        self.easy_query_type_combo.currentTextChanged.connect(self.on_easy_query_type_changed)

        self.history_query_combo = QComboBox()
        self.history_query_combo.setFixedWidth(280)
        self.history_query_combo.addItem("이력 쿼리 선택", "")
        for item in self.history_queries_cache:
            query_name = item.get("name", "")
            display_name = HISTORY_QUERY_LABELS.get(query_name, query_name)
            self.history_query_combo.addItem(display_name, query_name)
        self.history_query_combo.setVisible(False)

        self.live_endpoint_input = QLineEdit()
        self.live_endpoint_input.setPlaceholderText("Endpoint Name")

        self.live_program_input = QLineEdit()
        self.live_program_input.setPlaceholderText("Keyword (blank = all, ex. chrome.exe)")

        self.history_variable_input = QLineEdit()
        self.history_variable_input.setPlaceholderText("Variable Value")
        self.history_variable_input.setVisible(False)

        self.btn_live_run = QPushButton("조회")

        form_layout.addWidget(self.easy_mode_combo)
        form_layout.addWidget(self.easy_query_type_combo)
        form_layout.addWidget(self.history_query_combo)
        form_layout.addWidget(self.live_endpoint_input)
        form_layout.addWidget(self.live_program_input)
        form_layout.addWidget(self.history_variable_input)
        form_layout.addWidget(self.btn_live_run)
        layout.addLayout(form_layout)

        # ===============================
        # 세션 목록 테이블
        # ===============================
        self.live_session_table = QTableWidget()
        self.live_session_table.setColumnCount(7)
        self.live_session_table.setHorizontalHeaderLabels([
            "Created At", "Mode", "Type", "Endpoint", "Keyword", "Count", "Session ID"
        ])
        self.live_session_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.live_session_table.setSortingEnabled(False)
        self.live_session_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.live_session_table.setSelectionMode(QTableWidget.SingleSelection)
        self.live_session_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.live_session_table.verticalHeader().setVisible(False)
        self.live_session_table.setAlternatingRowColors(True)
        self.live_session_table.setColumnHidden(6, True)   # Session ID 숨김
        layout.addWidget(self.live_session_table)

        # 버튼 / 엔터 연결
        self.btn_live_run.clicked.connect(self.run_live_discover_query)
        self.live_endpoint_input.returnPressed.connect(self.run_live_discover_query)
        self.live_program_input.returnPressed.connect(self.run_live_discover_query)
        self.history_variable_input.returnPressed.connect(self.run_live_discover_query)
        self.easy_mode_combo.currentTextChanged.connect(self.on_easy_mode_changed)
        self.easy_query_type_combo.currentTextChanged.connect(self.on_easy_query_type_changed)
        self.history_query_combo.currentTextChanged.connect(lambda _: self.on_easy_mode_changed(self.easy_mode_combo.currentText()))
        self.on_easy_query_type_changed(self.easy_query_type_combo.currentText())
        self.on_easy_mode_changed(self.easy_mode_combo.currentText())


        # 세션 테이블 이벤트
        self.live_session_table.cellDoubleClicked.connect(self.open_live_discover_session_detail)
        self.live_session_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.live_session_table.customContextMenuRequested.connect(self.open_live_discover_session_menu)

        # 시작 시 기존 세션 로드
        self.refresh_live_session_table()

        return root

    def refresh_live_session_table(self):
        sessions = load_live_discover_sessions()

        self.live_session_table.setRowCount(0)

        for session in sessions:
            row = self.live_session_table.rowCount()
            self.live_session_table.insertRow(row)

            created_at = str(session.get("created_at", ""))
            query_mode = str(session.get("query_mode", "Live"))
            query_type = str(session.get("query_type", "Process"))
            endpoint_name = str(session.get("endpoint_name", ""))
            program_name = str(session.get("program_name", ""))
            session_id = str(session.get("session_id", ""))

            item_created = QTableWidgetItem(created_at)
            item_mode = QTableWidgetItem(query_mode)
            item_type = QTableWidgetItem(query_type)
            item_endpoint = QTableWidgetItem(endpoint_name)
            item_program = QTableWidgetItem(program_name)
            item_count = QTableWidgetItem()
            item_count.setData(Qt.DisplayRole, int(session.get("result_count", 0)))
            item_session = QTableWidgetItem(session_id)

            # session raw 보관
            item_created.setData(Qt.UserRole, session)

            self.live_session_table.setItem(row, 0, item_created)
            self.live_session_table.setItem(row, 1, item_mode)
            self.live_session_table.setItem(row, 2, item_type)
            self.live_session_table.setItem(row, 3, item_endpoint)
            self.live_session_table.setItem(row, 4, item_program)
            self.live_session_table.setItem(row, 5, item_count)
            self.live_session_table.setItem(row, 6, item_session)

    def open_live_discover_session_detail(self, row, column):
        item = self.live_session_table.item(row, 0)
        if not item:
            return

        session = item.data(Qt.UserRole)
        if not isinstance(session, dict):
            return

        rows = session.get("rows", [])
        endpoint_name = str(session.get("endpoint_name", ""))
        program_name = str(session.get("program_name", ""))
        created_at = str(session.get("created_at", ""))
        result_count = int(session.get("result_count", 0))
        query_mode = str(session.get("query_mode", "Live"))
        query_type = str(session.get("query_type", "Process"))
        display_columns = session.get("display_columns", ["name", "path", "pid"])

        if not isinstance(display_columns, list) or not display_columns:
            display_columns = ["name", "path", "pid"]

        dialog = QDialog(self)
        dialog.setWindowTitle("Easy Query Session Detail")
        dialog.resize(1100, 700)

        layout = QVBoxLayout(dialog)

        info_label = QLabel(
            f"Created At: {created_at}    |    Mode: {query_mode}    |    Type: {query_type}    |    Endpoint: {endpoint_name}    |    Keyword: {program_name}    |    Count: {result_count}"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        table = QTableWidget()
        table.setColumnCount(len(display_columns))
        table.setHorizontalHeaderLabels(display_columns)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setContextMenuPolicy(Qt.CustomContextMenu)

        table.setRowCount(0)

        for row_data in rows:
            if not isinstance(row_data, dict):
                continue

            r = table.rowCount()
            table.insertRow(r)

            for c, col_name in enumerate(display_columns):
                value = row_data.get(col_name, "")

                item_widget = QTableWidgetItem()
                item_widget.setData(Qt.DisplayRole, str(value))
                item_widget.setData(Qt.UserRole, row_data.get("_raw", row_data))
                table.setItem(r, c, item_widget)

        def open_raw_detail():
            current_row = table.currentRow()
            if current_row < 0:
                return

            current_item = table.item(current_row, 0)
            if not current_item:
                return

            raw_data = current_item.data(Qt.UserRole)
            if not raw_data:
                return

            self.show_raw_dialog(raw_data)

        def open_menu(pos):
            item = table.itemAt(pos)
            if not item:
                return

            menu = QMenu()
            action_raw = menu.addAction("View Raw Detail")
            action = menu.exec_(table.viewport().mapToGlobal(pos))

            if action == action_raw:
                raw_data = item.data(Qt.UserRole)
                if raw_data:
                    self.show_raw_dialog(raw_data)

        table.customContextMenuRequested.connect(open_menu)
        table.itemDoubleClicked.connect(lambda _: open_raw_detail())

        layout.addWidget(table)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        layout.addWidget(btn_close)

        dialog.exec_()

    def open_live_discover_session_menu(self, pos):
        item = self.live_session_table.itemAt(pos)
        if not item:
            return

        row = item.row()
        session_item = self.live_session_table.item(row, 0)
        if not session_item:
            return

        session = session_item.data(Qt.UserRole)
        if not isinstance(session, dict):
            return

        session_id = str(session.get("session_id", ""))
        created_at = str(session.get("created_at", ""))
        endpoint_name = str(session.get("endpoint_name", ""))
        program_name = str(session.get("program_name", ""))

        menu = QMenu(self)

        delete_action = menu.addAction("Delete Session")

        action = menu.exec_(self.live_session_table.viewport().mapToGlobal(pos))

        if action == delete_action:
            msg = QMessageBox.question(
                self,
                "Delete Session",
                f"아래 세션을 삭제하시겠습니까?\n\n"
                f"Created At: {created_at}\n"
                f"Endpoint: {endpoint_name}\n"
                f"Program: {program_name}\n"
                f"Session ID: {session_id}",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if msg == QMessageBox.Yes:
                try:
                    delete_live_discover_session(session_id)
                    log.info(f"[LIVE DISCOVER UI] session deleted: {session_id}")
                    self.refresh_live_session_table()
                except Exception as e:
                    QMessageBox.critical(self, "Delete Error", str(e))

    def run_live_discover_query(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 다른 작업이 실행 중입니다.")
            return

        endpoint_name = self.live_endpoint_input.text().strip()
        program_name = self.live_program_input.text().strip()
        mode = self.easy_mode_combo.currentText().strip()
        query_type = self.easy_query_type_combo.currentText().strip()

        if mode == "Live":
            log.info(f"[EASY QUERY UI] query_type={query_type}")

            if not endpoint_name:
                QMessageBox.warning(self, "입력 필요", "엔드포인트명을 입력하세요.")
                return

            self.btn_live_run.setEnabled(False)

            self.running = True
            self.set_status("Live Discover query", color="blue", spinning=True)

            log.info("[EASY QUERY UI] run button clicked")
            log.info(f"[EASY QUERY UI] mode={mode}")
            log.info(f"[EASY QUERY UI] endpoint_name={endpoint_name}")
            log.info(f"[EASY QUERY UI] program_name={program_name}")

            self.live_worker = LiveDiscoverWorker(
                endpoint_name=endpoint_name,
                program_name=program_name,
                query_type=query_type,
                parent=self
            )
            self.live_worker.ok.connect(self._on_live_discover_ok)
            self.live_worker.fail.connect(self._on_live_discover_fail)
            self.live_worker.start()
            return

        selected_query_name = str(self.history_query_combo.currentData() or "").strip()
        if not selected_query_name:
            QMessageBox.warning(self, "입력 필요", "History Query를 선택하세요.")
            return

        selected_query = get_history_query_by_name(selected_query_name)
        if not selected_query:
            QMessageBox.warning(self, "입력 오류", "선택한 History Query 정보를 찾지 못했습니다.")
            return

        history_variable_value = self.history_variable_input.text().strip()
        query_variables = selected_query.get("variables", [])
        if not isinstance(query_variables, list):
            query_variables = []

        if query_variables and not history_variable_value:
            QMessageBox.warning(self, "입력 필요", "해당 쿼리에 필요한 변수 값을 입력하세요.")
            return

        resolved_endpoint_id = ""
        if endpoint_name:
            resolved_endpoint_id = resolve_history_endpoint_id_by_hostname(endpoint_name)
            if not resolved_endpoint_id:
                QMessageBox.warning(
                    self,
                    "입력 오류",
                    "입력한 호스트명과 일치하는 endpoint id를 endpoint cache에서 찾지 못했습니다."
                )
                return

        start_qdate = self.start_date_edit.date().toPyDate()
        end_qdate = self.end_date_edit.date().toPyDate()

        from_iso = datetime(
            start_qdate.year, start_qdate.month, start_qdate.day,
            0, 0, 0,
            tzinfo=timezone(timedelta(hours=9))
        ).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        to_iso = datetime(
            end_qdate.year, end_qdate.month, end_qdate.day,
            23, 59, 59,
            tzinfo=timezone(timedelta(hours=9))
        ).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        query_label = HISTORY_QUERY_LABELS.get(selected_query_name, selected_query_name)
        self.history_pending_context = {
            "endpoint_name": endpoint_name,
            "selected_query_name": selected_query_name,
            "query_label": query_label,
        }

        self.btn_live_run.setEnabled(False)

        self.running = True
        self.set_status("History Query", color="blue", spinning=True)

        log.info("[HISTORY QUERY UI] run button clicked")
        log.info(f"[HISTORY QUERY UI] endpoint_name={endpoint_name}")
        log.info(f"[HISTORY QUERY UI] resolved_endpoint_id={resolved_endpoint_id}")
        log.info(f"[HISTORY QUERY UI] selected_query_name={selected_query_name}")
        log.info(f"[HISTORY QUERY UI] history_variable_value={history_variable_value}")
        log.info(f"[HISTORY QUERY UI] from_iso={from_iso}")
        log.info(f"[HISTORY QUERY UI] to_iso={to_iso}")

        self.history_worker = XdrQueryWorker(
            query_name=selected_query_name,
            endpoint_id=resolved_endpoint_id,
            variable_value=history_variable_value,
            from_iso=from_iso,
            to_iso=to_iso,
            parent=self
        )
        self.history_worker.ok.connect(self._on_history_query_ok)
        self.history_worker.fail.connect(self._on_history_query_fail)
        self.history_worker.start()


    def _on_live_discover_ok(self, rows):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Live Discover OK", color="green", spinning=False)
        self.btn_live_run.setEnabled(True)

        endpoint_name = self.live_endpoint_input.text().strip()
        program_name = self.live_program_input.text().strip()
        query_type = self.easy_query_type_combo.currentText().strip()

        if query_type == "Process":
            display_columns = ["name", "path", "pid"]
        elif query_type == "Service":
            display_columns = ["name", "display_name", "status", "start_type"]
        elif query_type == "Scheduled Task":
            display_columns = ["name", "path", "enabled", "state"]
        elif query_type == "Installed Program":
            display_columns = ["name", "version", "install_location"]
        elif query_type == "Network Connection":
            display_columns = ["pid", "local_address", "local_port", "remote_address", "remote_port", "state"]
        elif query_type == "File Search":
            display_columns = ["path", "filename", "size", "mtime"]
        else:
            display_columns = ["name", "path", "pid"]

        session = create_live_discover_session(
            endpoint_name=endpoint_name,
            program_name=program_name,
            rows=rows,
            query_mode="Live",
            query_type=query_type,
            display_columns=display_columns
        )

        log.info(f"[LIVE DISCOVER UI] session saved: {session.get('session_id')}")

        self.refresh_live_session_table()

        QMessageBox.information(
            self,
            "Live Discover",
            f"세션 저장 완료\nSession ID: {session.get('session_id')}\nResult Count: {session.get('result_count')}"
        )


    def _on_live_discover_fail(self, err):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Live Discover FAIL", color="red", spinning=False)
        self.btn_live_run.setEnabled(True)

        log.error(f"[LIVE DISCOVER UI] fail: {err}")
        QMessageBox.critical(self, "Live Discover Error", err)

    def on_easy_mode_changed(self, mode: str):
        log.info(f"[EASY QUERY UI] mode changed: {mode}")

        is_history = (str(mode).strip() == "History")

        self.easy_query_type_combo.setVisible(not is_history)
        self.history_query_combo.setVisible(is_history)

        if is_history:
            self.live_endpoint_input.setPlaceholderText("Endpoint Name (blank = all)")
            self.live_program_input.setVisible(False)

            selected_name = str(self.history_query_combo.currentData() or "").strip()
            selected_query = get_history_query_by_name(selected_name)

            variables = []
            if isinstance(selected_query, dict):
                variables = selected_query.get("variables", [])
                if not isinstance(variables, list):
                    variables = []

            if variables:
                first_var = variables[0] if isinstance(variables[0], dict) else {}
                var_name = str(first_var.get("name", "value")).strip() or "value"
                self.history_variable_input.setPlaceholderText(var_name)
                self.history_variable_input.setVisible(True)
            else:
                self.history_variable_input.clear()
                self.history_variable_input.setPlaceholderText("Variable Value")
                self.history_variable_input.setVisible(False)

        else:
            self.live_endpoint_input.setPlaceholderText("Endpoint Name")
            self.live_program_input.setVisible(True)
            self.history_variable_input.clear()
            self.history_variable_input.setVisible(False)

    def on_easy_query_type_changed(self, query_type: str):
        log.info(f"[EASY QUERY UI] query type changed: {query_type}")

        if query_type == "Process":
            self.live_program_input.setPlaceholderText("Process Name (blank = all, ex. chrome.exe)")
        elif query_type == "Service":
            self.live_program_input.setPlaceholderText("Service Name (blank = all, ex. Sophos)")
        elif query_type == "Scheduled Task":
            self.live_program_input.setPlaceholderText("Task Name (blank = all, ex. Update)")
        elif query_type == "Installed Program":
            self.live_program_input.setPlaceholderText("Program Name (blank = all, ex. Microsoft)")
        elif query_type == "Network Connection":
            self.live_program_input.setPlaceholderText("IP / Port (blank = all, ex. 443 or 10.0.0.1)")
        elif query_type == "File Search":
            self.live_program_input.setPlaceholderText(
                r"Folder: C:\Windows\System32\   /   File: cmd.exe   /   Full path: C:\Windows\System32\cmd.exe"
            )
        else:
            self.live_program_input.setPlaceholderText("Keyword (blank = all)")

    def _on_history_query_ok(self, rows):
        self.running = False
        self._spin_timer.stop()
        self.set_status("History Query OK", color="green", spinning=False)
        self.btn_live_run.setEnabled(True)

        context = getattr(self, "history_pending_context", {}) or {}
        endpoint_name = str(context.get("endpoint_name", self.live_endpoint_input.text().strip()))
        selected_query_name = str(context.get("selected_query_name", self.history_query_combo.currentData() or "")).strip()
        query_label = str(context.get("query_label", HISTORY_QUERY_LABELS.get(selected_query_name, selected_query_name)))

        normalized_rows = normalize_history_rows(selected_query_name, rows)

        session = create_live_discover_session(
            endpoint_name=endpoint_name,
            program_name=query_label,
            rows=normalized_rows,
            query_mode="History",
            query_type=query_label,
            display_columns=["name", "path", "pid"]
        )

        log.info(f"[HISTORY QUERY UI] session saved: {session.get('session_id')}")

        self.refresh_live_session_table()

        QMessageBox.information(
            self,
            "History Query",
            f"세션 저장 완료\nSession ID: {session.get('session_id')}\nResult Count: {session.get('result_count')}"
        )


    def _on_history_query_fail(self, err):
        self.running = False
        self._spin_timer.stop()
        self.set_status("History Query FAIL", color="red", spinning=False)
        self.btn_live_run.setEnabled(True)

        QMessageBox.critical(self, "History Query Error", err)

    # ==================================================
    # Sensitive Files Tab
    # ==================================================
    def tab_sensitive_files(self):
        root = QWidget()
        root.setObjectName("sensitiveFilesRoot")
        root.setStyleSheet(f"""
            QWidget#sensitiveFilesRoot {{
                background: {UI_THEME['surface']};
            }}
            QTableWidget {{
                background: {UI_THEME['surface']};
                border: 1px solid {UI_THEME['border_soft']};
                border-radius: 12px;
                gridline-color: {UI_THEME['border_soft']};
            }}
            QHeaderView::section {{
                background: {UI_THEME['surface_soft']};
                color: {UI_THEME['text']};
                border: 0;
                padding: 8px;
                font-weight: 900;
            }}
        """)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title_row = QHBoxLayout()
        subtitle = QLabel("민감 파일 후보를 분류별로 모아보고, 선택한 파일의 사용자/경로/원본 이벤트를 확인합니다.")
        subtitle.setStyleSheet(f"color:{UI_THEME['text_muted']}; font-size:12px; font-weight:700;")
        title_row.addWidget(subtitle)
        self.sensitive_files_count_label = QLabel("표시 0건")
        self.sensitive_files_count_label.setStyleSheet(f"color:{UI_THEME['text']}; font-size:12px; font-weight:900;")
        title_row.addWidget(self.sensitive_files_count_label)
        title_row.addStretch(1)

        self.sensitive_files_dlp_chk = QCheckBox("DLP")
        self.sensitive_files_dlp_chk.setChecked(True)
        self.sensitive_files_outbound_chk = QCheckBox("아웃바운드 메일")
        self.sensitive_files_outbound_chk.setChecked(True)
        sensitive_source_checkbox_style = f"""
            QCheckBox {{
                color: {UI_THEME['text']};
                font-weight: 800;
                spacing: 6px;
                background: transparent;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {UI_THEME['accent']};
                border-radius: 4px;
                background: {UI_THEME['surface']};
            }}
            QCheckBox::indicator:checked {{
                background: {UI_THEME['accent']};
                border: 1px solid {UI_THEME['accent']};
            }}
        """
        for chk in (self.sensitive_files_dlp_chk, self.sensitive_files_outbound_chk):
            chk.setMinimumHeight(32)
            chk.setStyleSheet(sensitive_source_checkbox_style)
        title_row.addWidget(self.sensitive_files_dlp_chk)
        title_row.addWidget(self.sensitive_files_outbound_chk)

        self.sensitive_files_reset_btn = QPushButton("새로고침")
        self.sensitive_files_reset_btn.setMinimumHeight(36)
        self.sensitive_files_reset_btn.setStyleSheet(self.button_style("secondary"))
        title_row.addWidget(self.sensitive_files_reset_btn)

        self.sensitive_files_filter = QLineEdit()
        self.sensitive_files_filter.setPlaceholderText("파일명 / 사용자 / 경로 검색")
        self.sensitive_files_filter.setMinimumHeight(36)
        self.sensitive_files_filter.setMaximumWidth(360)
        title_row.addWidget(self.sensitive_files_filter)
        layout.addLayout(title_row)

        splitter = QSplitter(Qt.Horizontal)

        category_table = QTableWidget()
        category_table.setColumnCount(1)
        category_table.setHorizontalHeaderLabels(["분류"])
        category_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        category_table.verticalHeader().setVisible(False)
        category_table.setSelectionBehavior(QTableWidget.SelectRows)
        category_table.setEditTriggers(QTableWidget.NoEditTriggers)
        category_table.setMaximumWidth(280)

        file_table = QTableWidget()
        file_headers = ["파일명", "분류", "탐지 키워드", "사용자", "부서", "시간"]
        file_table.setColumnCount(len(file_headers))
        file_table.setHorizontalHeaderLabels(file_headers)
        file_header = file_table.horizontalHeader()
        file_header.setSectionsClickable(False)
        file_header.setSortIndicatorShown(False)
        file_header.setSectionResizeMode(0, QHeaderView.Stretch)
        for col, width in ((1, 140), (2, 160), (3, 110), (4, 140), (5, 145)):
            file_header.setSectionResizeMode(col, QHeaderView.Interactive)
            file_table.setColumnWidth(col, width)
        file_table.verticalHeader().setVisible(False)
        file_table.setSelectionBehavior(QTableWidget.SelectRows)
        file_table.setEditTriggers(QTableWidget.NoEditTriggers)
        file_table.setSortingEnabled(False)

        more_button = QPushButton("더 보기")
        more_button.setStyleSheet(self.button_style("secondary"))
        more_button.setMinimumHeight(34)
        file_panel = QWidget()
        file_panel_layout = QVBoxLayout(file_panel)
        file_panel_layout.setContentsMargins(0, 0, 0, 0)
        file_panel_layout.setSpacing(6)
        file_panel_layout.addWidget(file_table, 1)
        more_row = QHBoxLayout()
        more_row.addStretch(1)
        more_row.addWidget(more_button)
        more_row.addStretch(1)
        file_panel_layout.addLayout(more_row)

        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setMinimumWidth(360)
        detail.setStyleSheet(f"""
            QTextEdit {{
                background: {UI_THEME['surface']};
                color: {UI_THEME['text']};
                border: 1px solid {UI_THEME['border_soft']};
                border-radius: 12px;
                padding: 10px;
                font-family: {UI_FONT_FAMILY};
                font-size: 12px;
            }}
        """)

        splitter.addWidget(category_table)
        splitter.addWidget(file_panel)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 2)
        splitter.setStretchFactor(2, 1)
        layout.addWidget(splitter, 1)

        raw_button = QPushButton("Raw 보기")
        raw_button.setStyleSheet(self.button_style("secondary"))
        raw_button.setMinimumHeight(36)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(raw_button)
        layout.addLayout(bottom)

        category_specs = SENSITIVE_FILE_CATEGORY_SPECS

        def row_text(row):
            field_text = " ".join(str(row.get(k, "") or "") for k in (
                "filename", "destination", "destination_type", "item_details",
                "destinationDetails", "machine_name", "client_name", "event_id",
            ))
            return f"{field_text} {json.dumps(row, ensure_ascii=False, default=str)}".lower()

        def classify_sensitive_row(row):
            text = row_text(row)
            matched_categories = []
            matched_keywords = []
            for category, keywords in category_specs:
                hits = [kw for kw in keywords if kw.lower() in text]
                if hits:
                    matched_categories.append(category)
                    matched_keywords.extend(hits)
            if not matched_categories:
                return None
            return {
                "category": matched_categories[0],
                "categories": matched_categories,
                "keywords": sorted(set(matched_keywords), key=lambda x: x.lower()),
            }

        def display_file_name(path_text):
            text = str(path_text or "None").strip()
            if not text or text == "None":
                return "None"
            normalized = text.replace("\\", "/").rstrip("/")
            return normalized.rsplit("/", 1)[-1] or text

        def resolve_sensitive_user_name(machine_name, client_name):
            identity = resolve_identity_by_hostname(machine_name)
            user_name = str(identity.get("user_name", "") or "").strip()
            if user_name and user_name != "None":
                return user_name
            directory_info = get_directory_user_info(client_name)
            directory_name = str(directory_info.get("name", "") or "").strip()
            if directory_name:
                return directory_name
            org_name = get_org_user_name_by_user_id(client_name)
            if org_name:
                return org_name
            return str(client_name or "None")

        def make_sensitive_record(row):
            classified = classify_sensitive_row(row)
            if not classified:
                return None
            machine_name = str(row.get("machine_name", "None") or "None")
            client_name = str(row.get("client_name", "None") or "None")
            dept_name, _ = get_dept_by_hostname(machine_name)
            filename = str(row.get("filename", "None") or "None")
            destination = str(row.get("destination", "None") or "None")
            destination_detail = str(row.get("item_details") or row.get("destinationDetails") or "None")
            return {
                "row": row,
                "category": classified["category"],
                "categories": classified["categories"],
                "keywords": classified["keywords"],
                "event_time": str(row.get("eventtimelocal", "") or ""),
                "event": format_dlp_event_id(row.get("event_id", "None")),
                "machine": machine_name,
                "dept": dept_name,
                "user": resolve_sensitive_user_name(machine_name, client_name),
                "user_id": client_name,
                "filename": filename,
                "display_filename": display_file_name(filename),
                "destination": destination,
                "destination_type": str(row.get("destination_type", "None") or "None"),
                "destination_detail": destination_detail,
                "filehash": str(row.get("filehash", "None") or "None"),
            }

        def record_search_text(record):
            return " ".join(str(record.get(k, "") or "") for k in (
                "source", "category", "keywords", "event_time", "event", "machine",
                "dept", "user", "user_id", "filename", "display_filename", "destination", "destination_type",
                "destination_detail", "filehash", "mail_subject", "mail_sender", "mail_receiver", "mail_policy", "mail_attach_raw",
            )).lower()

        def render_detail(record=None):
            if not record:
                detail.setPlainText("파일을 선택하면 상세 정보가 표시됩니다.")
                return
            if record.get("source") == "Outbound Mail":
                detail.setPlainText("\n".join([
                    "출처: Outbound Mail",
                    f"파일명: {record['display_filename']}",
                    f"분류: {', '.join(record['categories'])}",
                    f"탐지 키워드: {', '.join(record['keywords'])}",
                    "",
                    f"사용자: {record['user']}",
                    f"User ID: {record['user_id']}",
                    f"부서: {record['dept']}",
                    "호스트: None",
                    "",
                    f"이벤트: {record['event']}",
                    f"시간: {record['event_time']}",
                    f"대상 유형: {record['destination_type']}",
                    f"수신자: {record.get('mail_receiver', record['destination'])}",
                    f"메일 제목: {record.get('mail_subject', 'None')}",
                    f"발신자: {record.get('mail_sender', 'None')}",
                    f"메일 크기: {record.get('mail_size', 'None')}",
                    f"적용 정책: {record.get('mail_policy', 'None')}",
                    f"메일 처리: {record.get('mail_process', 'None')}",
                    f"전송 결과: {record.get('mail_send_result', 'None')}",
                    f"첨부 원문: {record.get('mail_attach_raw', 'None')}",
                    "파일 해시: None",
                ]))
                return
            detail.setPlainText("\n".join([
                "출처: DLP",
                f"파일명: {record['display_filename']}",
                f"전체 경로: {record['filename']}",
                f"분류: {', '.join(record['categories'])}",
                f"탐지 키워드: {', '.join(record['keywords'])}",
                "",
                f"사용자: {record['user']}",
                f"User ID: {record['user_id']}",
                f"부서: {record['dept']}",
                f"호스트: {record['machine']}",
                "",
                f"이벤트: {record['event']}",
                f"시간: {record['event_time']}",
                f"대상 유형: {record['destination_type']}",
                f"대상: {record['destination']}",
                f"목적지 세부정보: {record['destination_detail']}",
                f"파일 해시: {record['filehash']}",
            ]))

        self.sensitive_file_records = []
        self.sensitive_file_current_category = "전체"
        self.sensitive_file_category_counts = {}
        self.sensitive_files_total = 0
        self.sensitive_files_offset = 0
        self.sensitive_files_loaded = False

        def selected_sources():
            return sensitive_files_index_sources(
                include_dlp=self.sensitive_files_dlp_chk.isChecked(),
                include_outbound=self.sensitive_files_outbound_chk.isChecked(),
            )

        def render_categories():
            counts = getattr(self, "sensitive_file_category_counts", {}) or {}
            categories = ["전체"] + [category for category, _ in category_specs if counts.get(category, 0) > 0]
            signals_were_blocked = category_table.blockSignals(True)
            category_table.setSortingEnabled(False)
            category_table.clearContents()
            category_table.setRowCount(0)
            for category in categories:
                r = category_table.rowCount()
                category_table.insertRow(r)
                item = QTableWidgetItem(category)
                item.setData(Qt.UserRole, category)
                category_table.setItem(r, 0, item)
            category_table.setSortingEnabled(False)
            target_category = getattr(self, "sensitive_file_current_category", "전체")
            selected_row = 0
            for row in range(category_table.rowCount()):
                item = category_table.item(row, 0)
                if item and item.data(Qt.UserRole) == target_category:
                    selected_row = row
                    break
            if category_table.rowCount() > 0:
                category_table.selectRow(selected_row)
            category_table.blockSignals(signals_were_blocked)

        def render_files():
            records = self.sensitive_file_records or []
            total_records = int(getattr(self, "sensitive_files_total", 0) or 0)
            shown_count = int(getattr(self, "sensitive_files_offset", 0) or 0) + len(records)
            shown_count = min(shown_count, total_records)
            selected_category = getattr(self, "sensitive_file_current_category", "전체")
            scope_label = "전체" if selected_category == "전체" else selected_category
            self.sensitive_files_count_label.setText(
                f"표시 {shown_count:,}건 / {scope_label} {total_records:,}건"
            )
            more_button.setEnabled(shown_count < total_records)

            token = getattr(self, "sensitive_file_render_token", 0) + 1
            self.sensitive_file_render_token = token
            batch_size = 150
            file_table.setSortingEnabled(False)
            file_table.setUpdatesEnabled(False)
            file_table.clearContents()
            file_table.setRowCount(len(records))
            render_detail(None)

            def fill_batch(start=0):
                if token != getattr(self, "sensitive_file_render_token", 0):
                    return
                end = min(start + batch_size, len(records))
                for r in range(start, end):
                    record = records[r]
                    values = [
                        record["display_filename"],
                        record["category"],
                        ", ".join(record["keywords"]),
                        record["user"],
                        record["dept"],
                        record["event_time"],
                    ]
                    for c, value in enumerate(values):
                        item = QTableWidgetItem(str(value or "None"))
                        if c == 0:
                            item.setData(Qt.UserRole, record)
                        file_table.setItem(r, c, item)

                if end < len(records):
                    QTimer.singleShot(0, lambda: fill_batch(end))
                    return

                file_table.setUpdatesEnabled(True)
                file_table.setSortingEnabled(False)
                if file_table.rowCount() > 0:
                    file_table.selectRow(0)
                    first = file_table.item(0, 0)
                    render_detail(first.data(Qt.UserRole) if first else None)
                else:
                    render_detail(None)

            fill_batch()

        def on_category_selected():
            selected = category_table.selectedItems()
            if selected:
                category = selected[0].data(Qt.UserRole) or "전체"
                if category == getattr(self, "sensitive_file_current_category", "전체"):
                    return
                self.sensitive_file_current_category = category
                reset_sensitive_filter()

        def on_file_selected():
            selected = file_table.selectedItems()
            if not selected:
                render_detail(None)
                return
            item = file_table.item(selected[0].row(), 0)
            render_detail(item.data(Qt.UserRole) if item else None)

        def open_selected_raw():
            selected = file_table.selectedItems()
            if not selected:
                QMessageBox.information(self, "Sensitive Files", "선택된 파일이 없습니다.")
                return
            item = file_table.item(selected[0].row(), 0)
            record = item.data(Qt.UserRole) if item else None
            if record:
                self.show_raw_dialog(record.get("row"))

        def finish_sensitive_reload(payload):
            payload = payload or {}
            self.sensitive_file_records = payload.get("records") or []
            self.sensitive_file_category_counts = payload.get("category_counts") or {}
            self.sensitive_files_total = int(payload.get("total", 0) or 0)
            self.sensitive_files_offset = int(payload.get("offset", 0) or 0)
            self.sensitive_files_range = "전체 캐시"
            self.sensitive_files_loaded = bool(payload.get("index_ready", True))
            self.update_range_label()
            render_categories()
            render_files()
            self.sensitive_files_reset_btn.setEnabled(True)
            self.sensitive_files_reset_btn.setText("새로고침")
            if payload.get("index_ready", True):
                self.set_status("Sensitive Files refreshed", color="green", spinning=False)
            else:
                self.set_status("Sensitive Files index required", color="orange", spinning=False)
                detail.setPlainText(payload.get("message") or "Sensitive Files 인덱스가 없습니다. Data Index를 먼저 실행하세요.")

        def fail_sensitive_reload(message):
            self.sensitive_files_reset_btn.setEnabled(True)
            self.sensitive_files_reset_btn.setText("새로고침")
            self.set_status("Sensitive Files refresh FAIL", color="red", spinning=False)
            QMessageBox.critical(self, "Sensitive Files", f"새로고침 실패: {message}")

        def reset_sensitive_filter(offset=0, append=False):
            worker = getattr(self, "sensitive_files_worker", None)
            if worker is not None and worker.isRunning():
                return
            if not append:
                self.sensitive_files_offset = 0
            category = getattr(self, "sensitive_file_current_category", "전체")
            keyword = self.sensitive_files_filter.text().strip()
            sources = selected_sources()
            self.sensitive_file_render_token = getattr(self, "sensitive_file_render_token", 0) + 1
            file_table.setUpdatesEnabled(True)
            self.sensitive_files_reset_btn.setEnabled(False)
            self.sensitive_files_reset_btn.setText("새로고침중...")
            self.set_status("Sensitive Files refresh", color="blue", spinning=True)
            self.sensitive_files_worker = DlpAllCacheLoadWorker(
                category=category,
                keyword=keyword,
                sources=sources,
                limit=SENSITIVE_FILES_PAGE_LIMIT,
                offset=offset,
            )
            if append:
                self.sensitive_files_worker.ok.connect(finish_sensitive_append)
            else:
                self.sensitive_files_worker.ok.connect(finish_sensitive_reload)
            self.sensitive_files_worker.fail.connect(fail_sensitive_reload)
            self.sensitive_files_worker.start()

        def finish_sensitive_append(payload):
            payload = payload or {}
            existing = self.sensitive_file_records or []
            self.sensitive_file_records = existing + (payload.get("records") or [])
            self.sensitive_file_category_counts = payload.get("category_counts") or getattr(self, "sensitive_file_category_counts", {})
            self.sensitive_files_total = int(payload.get("total", 0) or getattr(self, "sensitive_files_total", 0) or 0)
            self.sensitive_files_offset = int(payload.get("offset", 0) or 0)
            render_categories()
            render_files()
            self.sensitive_files_reset_btn.setEnabled(True)
            self.sensitive_files_reset_btn.setText("새로고침")
            self.set_status("Sensitive Files more loaded", color="green", spinning=False)

        def refresh():
            if not getattr(self, "sensitive_files_loaded", False):
                reset_sensitive_filter()
                return
            render_categories()
            render_files()

        def on_sensitive_source_changed():
            self.sensitive_file_current_category = "전체"
            reset_sensitive_filter()

        def load_more_sensitive_files():
            offset = int(getattr(self, "sensitive_files_offset", 0) or 0) + len(self.sensitive_file_records or [])
            if offset >= int(getattr(self, "sensitive_files_total", 0) or 0):
                return
            reset_sensitive_filter(offset=offset, append=True)

        filter_timer = QTimer(root)
        filter_timer.setSingleShot(True)
        filter_timer.setInterval(250)
        filter_timer.timeout.connect(lambda: reset_sensitive_filter())

        category_table.itemSelectionChanged.connect(on_category_selected)
        file_table.itemSelectionChanged.connect(on_file_selected)
        self.sensitive_files_filter.textChanged.connect(lambda: filter_timer.start())
        self.sensitive_files_dlp_chk.stateChanged.connect(on_sensitive_source_changed)
        self.sensitive_files_outbound_chk.stateChanged.connect(on_sensitive_source_changed)
        self.sensitive_files_reset_btn.clicked.connect(reset_sensitive_filter)
        more_button.clicked.connect(load_more_sensitive_files)
        raw_button.clicked.connect(open_selected_raw)

        self._refresh_sensitive_files = refresh
        refresh()
        return root

    # ==================================================
    # Sensitive Sites Tab
    # ==================================================
    def tab_sensitive_sites(self):
        root = QWidget()
        root.setObjectName("sensitiveSitesRoot")
        root.setStyleSheet(f"""
            QWidget#sensitiveSitesRoot {{ background: {UI_THEME['surface']}; }}
            QTableWidget {{ background: {UI_THEME['surface']}; border: 1px solid {UI_THEME['border_soft']}; border-radius: 12px; gridline-color: {UI_THEME['border_soft']}; }}
            QHeaderView::section {{ background: {UI_THEME['surface_soft']}; color: {UI_THEME['text']}; border: 0; padding: 8px; font-weight: 900; }}
        """)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title_row = QHBoxLayout()
        subtitle = QLabel("민감 사이트 후보를 분류별로 모아보고, 선택한 사이트의 사용자/목적지/원본 이벤트를 확인합니다.")
        subtitle.setStyleSheet(f"color:{UI_THEME['text_muted']}; font-size:12px; font-weight:700;")
        title_row.addWidget(subtitle)
        self.sensitive_sites_count_label = QLabel("표시 0건")
        self.sensitive_sites_count_label.setStyleSheet(f"color:{UI_THEME['text']}; font-size:12px; font-weight:900;")
        title_row.addWidget(self.sensitive_sites_count_label)
        title_row.addStretch(1)

        self.sensitive_sites_dlp_chk = QCheckBox("DLP")
        self.sensitive_sites_dlp_chk.setChecked(True)
        checkbox_style = f"""
            QCheckBox {{ color: {UI_THEME['text']}; font-weight: 800; spacing: 6px; background: transparent; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {UI_THEME['accent']}; border-radius: 4px; background: {UI_THEME['surface']}; }}
            QCheckBox::indicator:checked {{ background: {UI_THEME['accent']}; border: 1px solid {UI_THEME['accent']}; }}
        """
        self.sensitive_sites_dlp_chk.setMinimumHeight(32)
        self.sensitive_sites_dlp_chk.setStyleSheet(checkbox_style)
        title_row.addWidget(self.sensitive_sites_dlp_chk)

        self.sensitive_sites_reset_btn = QPushButton("새로고침")
        self.sensitive_sites_reset_btn.setMinimumHeight(36)
        self.sensitive_sites_reset_btn.setStyleSheet(self.button_style("secondary"))
        title_row.addWidget(self.sensitive_sites_reset_btn)

        self.sensitive_sites_filter = QLineEdit()
        self.sensitive_sites_filter.setPlaceholderText("사이트 / 사용자 / URL 검색")
        self.sensitive_sites_filter.setMinimumHeight(36)
        self.sensitive_sites_filter.setMaximumWidth(360)
        title_row.addWidget(self.sensitive_sites_filter)
        layout.addLayout(title_row)

        splitter = QSplitter(Qt.Horizontal)
        category_table = QTableWidget()
        category_table.setColumnCount(1)
        category_table.setHorizontalHeaderLabels(["분류"])
        category_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        category_table.verticalHeader().setVisible(False)
        category_table.setSelectionBehavior(QTableWidget.SelectRows)
        category_table.setEditTriggers(QTableWidget.NoEditTriggers)
        category_table.setMaximumWidth(280)

        site_table = QTableWidget()
        site_headers = ["사이트", "분류", "탐지 키워드", "사용자", "부서", "시간"]
        site_table.setColumnCount(len(site_headers))
        site_table.setHorizontalHeaderLabels(site_headers)
        site_header = site_table.horizontalHeader()
        site_header.setSectionsClickable(False)
        site_header.setSortIndicatorShown(False)
        site_header.setSectionResizeMode(0, QHeaderView.Stretch)
        for col, width in ((1, 150), (2, 160), (3, 110), (4, 140), (5, 145)):
            site_header.setSectionResizeMode(col, QHeaderView.Interactive)
            site_table.setColumnWidth(col, width)
        site_table.verticalHeader().setVisible(False)
        site_table.setSelectionBehavior(QTableWidget.SelectRows)
        site_table.setEditTriggers(QTableWidget.NoEditTriggers)
        site_table.setSortingEnabled(False)

        more_button = QPushButton("더 보기")
        more_button.setStyleSheet(self.button_style("secondary"))
        more_button.setMinimumHeight(34)
        site_panel = QWidget()
        site_panel_layout = QVBoxLayout(site_panel)
        site_panel_layout.setContentsMargins(0, 0, 0, 0)
        site_panel_layout.setSpacing(6)
        site_panel_layout.addWidget(site_table, 1)
        more_row = QHBoxLayout()
        more_row.addStretch(1)
        more_row.addWidget(more_button)
        more_row.addStretch(1)
        site_panel_layout.addLayout(more_row)

        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setStyleSheet(f"""
            QTextEdit {{ background: {UI_THEME['surface']}; color: {UI_THEME['text']}; border: 1px solid {UI_THEME['border_soft']}; border-radius: 12px; padding: 10px; font-family: {UI_FONT_FAMILY}; font-size: 12px; }}
        """)

        splitter.addWidget(category_table)
        splitter.addWidget(site_panel)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 2)
        splitter.setStretchFactor(2, 1)
        layout.addWidget(splitter, 1)

        raw_button = QPushButton("Raw 보기")
        raw_button.setStyleSheet(self.button_style("secondary"))
        raw_button.setMinimumHeight(36)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(raw_button)
        layout.addLayout(bottom)

        self.sensitive_site_records = []
        self.sensitive_site_current_category = "전체"
        self.sensitive_site_category_counts = {}
        self.sensitive_sites_total = 0
        self.sensitive_sites_offset = 0
        self.sensitive_sites_loaded = False

        def selected_sources():
            return sensitive_sites_index_sources(include_dlp=self.sensitive_sites_dlp_chk.isChecked())

        def render_detail(record=None):
            if not record:
                detail.setPlainText("사이트를 선택하면 상세 정보가 표시됩니다.")
                return
            lines = [
                f"출처: {record.get('source', 'None')}",
                f"사이트: {record.get('site', 'None')}",
                f"URL/대상: {record.get('url', 'None')}",
                f"분류: {', '.join(record.get('categories', []) or [])}",
                f"탐지 키워드: {', '.join(record.get('keywords', []) or [])}",
                "",
                f"사용자: {record.get('user', 'None')}",
                f"User ID: {record.get('user_id', 'None')}",
                f"부서: {record.get('dept', 'None')}",
                f"호스트: {record.get('machine', 'None')}",
                "",
                f"이벤트: {record.get('event', 'None')}",
                f"시간: {record.get('event_time', 'None')}",
            ]
            if record.get("source") == "Outbound Mail":
                lines.extend([
                    f"메일 제목: {record.get('subject', 'None')}",
                    f"발신자: {record.get('sender', 'None')}",
                    f"수신자: {record.get('receiver', 'None')}",
                    f"적용 정책: {record.get('policy', 'None')}",
                    f"메일 처리: {record.get('mail_process', 'None')}",
                    f"전송 결과: {record.get('mail_send_result', 'None')}",
                ])
            else:
                lines.extend([
                    f"대상: {record.get('destination', 'None')}",
                    f"목적지 세부정보: {record.get('detail', 'None')}",
                    f"파일명: {record.get('filename', 'None')}",
                    f"파일 해시: {record.get('filehash', 'None')}",
                ])
            detail.setPlainText("\n".join(lines))

        def render_categories():
            counts = getattr(self, "sensitive_site_category_counts", {}) or {}
            categories = ["전체"] + [category for category, _ in SENSITIVE_SITE_CATEGORY_SPECS if counts.get(category, 0) > 0]
            signals_were_blocked = category_table.blockSignals(True)
            category_table.clearContents()
            category_table.setRowCount(0)
            for category in categories:
                r = category_table.rowCount()
                category_table.insertRow(r)
                item = QTableWidgetItem(category)
                item.setData(Qt.UserRole, category)
                category_table.setItem(r, 0, item)
            target_category = getattr(self, "sensitive_site_current_category", "전체")
            selected_row = 0
            for row in range(category_table.rowCount()):
                item = category_table.item(row, 0)
                if item and item.data(Qt.UserRole) == target_category:
                    selected_row = row
                    break
            if category_table.rowCount() > 0:
                category_table.selectRow(selected_row)
            category_table.blockSignals(signals_were_blocked)

        def render_sites():
            records = self.sensitive_site_records or []
            total_records = int(getattr(self, "sensitive_sites_total", 0) or 0)
            shown_count = min(int(getattr(self, "sensitive_sites_offset", 0) or 0) + len(records), total_records)
            selected_category = getattr(self, "sensitive_site_current_category", "전체")
            scope_label = "전체" if selected_category == "전체" else selected_category
            self.sensitive_sites_count_label.setText(f"표시 {shown_count:,}건 / {scope_label} {total_records:,}건")
            more_button.setEnabled(shown_count < total_records)

            token = getattr(self, "sensitive_site_render_token", 0) + 1
            self.sensitive_site_render_token = token
            site_table.setSortingEnabled(False)
            site_table.setUpdatesEnabled(False)
            site_table.clearContents()
            site_table.setRowCount(len(records))
            render_detail(None)

            def fill_batch(start=0):
                if token != getattr(self, "sensitive_site_render_token", 0):
                    return
                end = min(start + 150, len(records))
                for r in range(start, end):
                    record = records[r]
                    values = [
                        record.get("site", "None"),
                        record.get("category", "None"),
                        ", ".join(record.get("keywords", []) or []),
                        record.get("user", "None"),
                        record.get("dept", "None"),
                        record.get("event_time", "None"),
                    ]
                    for c, value in enumerate(values):
                        item = QTableWidgetItem(str(value or "None"))
                        if c == 0:
                            item.setData(Qt.UserRole, record)
                        site_table.setItem(r, c, item)
                if end < len(records):
                    QTimer.singleShot(0, lambda: fill_batch(end))
                    return
                site_table.setUpdatesEnabled(True)
                if site_table.rowCount() > 0:
                    site_table.selectRow(0)
                    first = site_table.item(0, 0)
                    render_detail(first.data(Qt.UserRole) if first else None)
                else:
                    render_detail(None)
            fill_batch()

        def on_category_selected():
            selected = category_table.selectedItems()
            if selected:
                category = selected[0].data(Qt.UserRole) or "전체"
                if category == getattr(self, "sensitive_site_current_category", "전체"):
                    return
                self.sensitive_site_current_category = category
                reset_sensitive_sites_filter()

        def on_site_selected():
            selected = site_table.selectedItems()
            if not selected:
                render_detail(None)
                return
            item = site_table.item(selected[0].row(), 0)
            render_detail(item.data(Qt.UserRole) if item else None)

        def open_selected_raw():
            selected = site_table.selectedItems()
            if not selected:
                QMessageBox.information(self, "Sensitive Sites", "선택된 사이트가 없습니다.")
                return
            item = site_table.item(selected[0].row(), 0)
            record = item.data(Qt.UserRole) if item else None
            if record:
                self.show_raw_dialog(record.get("row"))

        def finish_reload(payload):
            payload = payload or {}
            self.sensitive_site_records = payload.get("records") or []
            self.sensitive_site_category_counts = payload.get("category_counts") or {}
            self.sensitive_sites_total = int(payload.get("total", 0) or 0)
            self.sensitive_sites_offset = int(payload.get("offset", 0) or 0)
            self.sensitive_sites_range = "전체 캐시"
            self.sensitive_sites_loaded = bool(payload.get("index_ready", True))
            self.update_range_label()
            render_categories()
            render_sites()
            self.sensitive_sites_reset_btn.setEnabled(True)
            self.sensitive_sites_reset_btn.setText("새로고침")
            if payload.get("index_ready", True):
                self.set_status("Sensitive Sites refreshed", color="green", spinning=False)
            else:
                self.set_status("Sensitive Sites index required", color="orange", spinning=False)
                detail.setPlainText(payload.get("message") or "Sensitive Sites 인덱스가 없습니다. Data Index를 먼저 실행하세요.")
            run_pending_sensitive_sites_refresh()

        def finish_append(payload):
            payload = payload or {}
            self.sensitive_site_records = (self.sensitive_site_records or []) + (payload.get("records") or [])
            self.sensitive_site_category_counts = payload.get("category_counts") or getattr(self, "sensitive_site_category_counts", {})
            self.sensitive_sites_total = int(payload.get("total", 0) or getattr(self, "sensitive_sites_total", 0) or 0)
            self.sensitive_sites_offset = int(payload.get("offset", 0) or 0)
            render_categories()
            render_sites()
            self.sensitive_sites_reset_btn.setEnabled(True)
            self.sensitive_sites_reset_btn.setText("새로고침")
            self.set_status("Sensitive Sites more loaded", color="green", spinning=False)
            run_pending_sensitive_sites_refresh()

        def fail_reload(message):
            self.sensitive_sites_reset_btn.setEnabled(True)
            self.sensitive_sites_reset_btn.setText("새로고침")
            self.set_status("Sensitive Sites refresh FAIL", color="red", spinning=False)
            QMessageBox.critical(self, "Sensitive Sites", f"새로고침 실패: {message}")
            run_pending_sensitive_sites_refresh()

        def run_pending_sensitive_sites_refresh():
            pending = getattr(self, "sensitive_sites_pending_refresh", None)
            if not pending:
                return
            self.sensitive_sites_pending_refresh = None
            QTimer.singleShot(0, lambda: reset_sensitive_sites_filter(**pending))

        def reset_sensitive_sites_filter(offset=0, append=False):
            worker = getattr(self, "sensitive_sites_worker", None)
            if worker is not None and worker.isRunning():
                self.sensitive_sites_pending_refresh = {"offset": offset, "append": append}
                return
            if not append:
                self.sensitive_sites_offset = 0
            self.sensitive_site_render_token = getattr(self, "sensitive_site_render_token", 0) + 1
            site_table.setUpdatesEnabled(True)
            self.sensitive_sites_reset_btn.setEnabled(False)
            self.sensitive_sites_reset_btn.setText("새로고침중...")
            self.set_status("Sensitive Sites refresh", color="blue", spinning=True)
            category = getattr(self, "sensitive_site_current_category", "전체")
            keyword = self.sensitive_sites_filter.text().strip()
            sources = selected_sources()
            log.info(
                "Sensitive Sites UI refresh requested category=%s keyword=%r sources=%s limit=%d offset=%d append=%s",
                category, keyword, sources, SENSITIVE_SITES_PAGE_LIMIT, int(offset), bool(append),
            )
            self.sensitive_sites_worker = SensitiveSitesLoadWorker(
                category=category,
                keyword=keyword,
                sources=sources,
                limit=SENSITIVE_SITES_PAGE_LIMIT,
                offset=offset,
            )
            self.sensitive_sites_worker.ok.connect(finish_append if append else finish_reload)
            self.sensitive_sites_worker.fail.connect(fail_reload)
            self.sensitive_sites_worker.start()

        def refresh():
            reset_sensitive_sites_filter()

        def on_source_changed():
            self.sensitive_site_current_category = "전체"
            reset_sensitive_sites_filter()

        def load_more():
            offset = int(getattr(self, "sensitive_sites_offset", 0) or 0) + len(self.sensitive_site_records or [])
            if offset >= int(getattr(self, "sensitive_sites_total", 0) or 0):
                return
            reset_sensitive_sites_filter(offset=offset, append=True)

        filter_timer = QTimer(root)
        filter_timer.setSingleShot(True)
        filter_timer.setInterval(250)
        filter_timer.timeout.connect(lambda: reset_sensitive_sites_filter())
        category_table.itemSelectionChanged.connect(on_category_selected)
        site_table.itemSelectionChanged.connect(on_site_selected)
        self.sensitive_sites_filter.textChanged.connect(lambda: filter_timer.start())
        self.sensitive_sites_dlp_chk.stateChanged.connect(on_source_changed)
        self.sensitive_sites_reset_btn.clicked.connect(reset_sensitive_sites_filter)
        more_button.clicked.connect(load_more)
        raw_button.clicked.connect(open_selected_raw)
        self._refresh_sensitive_sites = refresh
        refresh()
        return root

    # ==================================================
    # DLP File Tab
    # ==================================================
    def tab_dlp_file(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # ===============================
        # 🔎 Multi Search UI
        # ===============================
        search_wrapper = QWidget()
        search_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        search_v = QVBoxLayout(search_wrapper)
        search_v.setContentsMargins(0, 0, 0, 4)
        search_v.setSpacing(6)

        self.dlp_search_container = QVBoxLayout()
        self.dlp_search_container.setContentsMargins(0, 0, 0, 0)
        self.dlp_search_container.setSpacing(6)
        search_v.addLayout(self.dlp_search_container)

        # ===============================
        # Table
        # ===============================
        table = QTableWidget()
        headers = [
            "이벤트",
            "날짜/시간 (클라이언트)",
            "컴퓨터",
            "부서",
            "소스 IP-주소",
            "사용자명",
            "소스",
            "대상",
            "대상 유형",
            "목적지 세부정보",
            "파일 크기",
            "파일 해시",
        ]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSortingEnabled(True)

        self.enable_context_menu(table, {4: "ip", 11: "sha256"})

        # ===============================
        # refresh
        # ===============================
        def refresh():
            header = table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()

            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)

            data = self.dlp_rows or []

            def match_text(value, keyword, mode):
                text = str(value or "").lower()
                if mode == "제외":
                    return keyword not in text
                return keyword in text

            search_conditions = []
            for i in range(self.dlp_search_container.count()):
                item = self.dlp_search_container.itemAt(i)
                row = item.widget() if item else None
                if not row:
                    continue

                row_layout = row.layout()
                if not row_layout or row_layout.count() < 3:
                    continue

                combo = row_layout.itemAt(0).widget()
                mode_combo = row_layout.itemAt(1).widget()
                edit = row_layout.itemAt(2).widget()

                if not combo or not mode_combo or not edit:
                    continue

                v = edit.text().strip().lower()
                if v:
                    search_conditions.append((combo.currentText(), mode_combo.currentText(), v))

            start_date = self.start_date_edit.date().toString("yyyy-MM-dd")
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd")

            for d in data:
                if not isinstance(d, dict):
                    continue

                event_id = format_dlp_event_id(d.get("event_id", "None"))
                event_time = str(d.get("eventtimelocal", "")).strip()
                event_date = event_time[:10] if len(event_time) >= 10 else ""

                if event_date:
                    if event_date < start_date or event_date > end_date:
                        continue

                machine_name = str(d.get("machine_name", "None"))
                ip = str(d.get("ip", "None"))
                client_name = str(d.get("client_name", "None"))
                source_value = str(d.get("filename", "None"))
                destination = str(d.get("destination", "None"))
                destination_type = str(d.get("destination_type", "None"))
                destination_detail = str(d.get("item_details") or d.get("destinationDetails") or "None")
                file_size = str(d.get("filesize", "None"))
                file_hash = str(d.get("filehash", "None"))

                dept_name, dept_code = get_dept_by_hostname(machine_name)

                raw_str = json.dumps(d, ensure_ascii=False).lower()

                matched = True
                for field, mode, key in search_conditions:
                    if field == "ALL":
                        row_text = " ".join([
                            event_id,
                            event_time,
                            machine_name,
                            dept_name,
                            ip,
                            client_name,
                            source_value,
                            destination,
                            destination_type,
                            destination_detail,
                            file_size,
                            file_hash,
                            raw_str,
                        ]).lower()

                        if mode == "포함":
                            if key not in row_text:
                                matched = False
                                break
                        else:
                            if key in row_text:
                                matched = False
                                break

                    elif field == "RawData":
                        if not match_text(raw_str, key, mode):
                            matched = False
                            break

                    elif field == "이벤트":
                        if not match_text(event_id, key, mode):
                            matched = False
                            break

                    elif field == "컴퓨터":
                        if not match_text(machine_name, key, mode):
                            matched = False
                            break

                    elif field == "부서":
                        if not match_text(dept_name, key, mode):
                            matched = False
                            break

                    elif field == "소스 IP-주소":
                        if not match_text(ip, key, mode):
                            matched = False
                            break

                    elif field == "사용자명":
                        if not match_text(client_name, key, mode):
                            matched = False
                            break

                    elif field == "소스":
                        if not match_text(source_value, key, mode):
                            matched = False
                            break

                    elif field == "대상":
                        if not match_text(destination, key, mode):
                            matched = False
                            break

                    elif field == "대상 유형":
                        if not match_text(destination_type, key, mode):
                            matched = False
                            break

                    elif field == "목적지 세부정보":
                        if not match_text(destination_detail, key, mode):
                            matched = False
                            break

                    elif field == "파일 크기":
                        if not match_text(file_size, key, mode):
                            matched = False
                            break

                    elif field == "파일 해시":
                        if not match_text(file_hash, key, mode):
                            matched = False
                            break

                if not matched:
                    continue

                r = table.rowCount()
                table.insertRow(r)

                first_item = QTableWidgetItem(event_id or "None")
                first_item.setData(Qt.UserRole, d)

                table.setItem(r, 0, first_item)
                table.setItem(r, 1, QTableWidgetItem(event_time or "None"))
                table.setItem(r, 2, QTableWidgetItem(machine_name))
                table.setItem(r, 3, QTableWidgetItem(dept_name))
                table.setItem(r, 4, QTableWidgetItem(ip))
                table.setItem(r, 5, QTableWidgetItem(client_name))
                table.setItem(r, 6, QTableWidgetItem(source_value))
                table.setItem(r, 7, QTableWidgetItem(destination))
                table.setItem(r, 8, QTableWidgetItem(destination_type))
                table.setItem(r, 9, QTableWidgetItem(destination_detail))
                table.setItem(r, 10, QTableWidgetItem(file_size))
                table.setItem(r, 11, QTableWidgetItem(file_hash))

            table.setSortingEnabled(True)
            if sort_column >= 0:
                table.sortItems(sort_column, sort_order)

        # ===============================
        # 검색줄 생성
        # ===============================
        FIELD_W = SEARCH_FIELD_W
        BTN_W = SEARCH_BTN_W
        ROW_H = SEARCH_ROW_H

        def add_search_row(default_field="ALL", default_mode="포함", removable=True, first=False):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            combo = QComboBox()
            combo.addItems([
                "ALL",
                "이벤트",
                "컴퓨터",
                "부서",
                "소스 IP-주소",
                "사용자명",
                "소스",
                "대상",
                "대상 유형",
                "목적지 세부정보",
                "파일 크기",
                "파일 해시",
                "RawData"
            ])
            combo.setCurrentText(default_field)
            combo.setFixedWidth(FIELD_W)
            combo.setFixedHeight(ROW_H)

            mode_combo = QComboBox()
            mode_combo.addItems(["포함", "제외"])
            mode_combo.setCurrentText(default_mode)
            mode_combo.setFixedWidth(SEARCH_MODE_W)
            mode_combo.setFixedHeight(ROW_H)

            default_font = QApplication.font()
            combo.setFont(default_font)
            combo.view().setFont(default_font)
            mode_combo.setFont(default_font)
            mode_combo.view().setFont(default_font)

            edit = QLineEdit()
            edit.setPlaceholderText("Search...")
            edit.setFixedHeight(ROW_H)
            edit.setFont(default_font)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

            row_layout.addWidget(combo, 0)
            row_layout.addWidget(mode_combo, 0)
            row_layout.addWidget(edit, 1)

            if first:
                btn = QPushButton("+")
                btn.setFixedSize(BTN_W, ROW_H)
                btn.clicked.connect(lambda: add_search_row(removable=True, first=False))
                row_layout.addWidget(btn, 0)
            elif removable:
                btn = QPushButton("-")
                btn.setFixedSize(BTN_W, ROW_H)

                def remove_row():
                    row.deleteLater()
                    refresh()

                btn.clicked.connect(remove_row)
                row_layout.addWidget(btn, 0)

            edit.returnPressed.connect(refresh)
            combo.currentIndexChanged.connect(refresh)
            mode_combo.currentIndexChanged.connect(refresh)

            self.dlp_search_container.addWidget(row)

        add_search_row(default_field="ALL", default_mode="포함", removable=False, first=True)

        layout.addWidget(search_wrapper, 0)
        layout.addWidget(table, 1)

        self._refresh_dlp = refresh
        refresh()

        return root


    def tab_timeline(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        top = QHBoxLayout()
        lbl = QLabel("사용자")
        self.timeline_user_input = QLineEdit()
        self.timeline_user_input.setPlaceholderText("사용자명 / User ID / 메일 / Hostname 입력 후 전체 캐시 검색")
        keyword_lbl = QLabel("키워드")
        self.timeline_keyword_input = QLineEdit()
        self.timeline_keyword_input.setPlaceholderText("이벤트명 / 제목 / 파일명 / IP / 해시 / RawData 키워드")
        self.timeline_btn_search = QPushButton("조회")
        self.timeline_btn_search.setProperty("buttonRole", "secondary")
        self.timeline_btn_search.setStyleSheet(self.button_style("secondary"))
        self.timeline_status_label = QLabel("날짜 선택과 무관하게 전체 캐시에서 검색합니다.")
        self.timeline_status_label.setStyleSheet(f"color:{UI_THEME['text_muted']}; font-weight:700;")

        self.timeline_chk_detection = QCheckBox("Detection - XDR")
        self.timeline_chk_xdr = QCheckBox("Email - XDR")
        self.timeline_chk_email = QCheckBox("Inbound Mail")
        self.timeline_chk_outbound_mail = QCheckBox("Outbound Mail")
        self.timeline_chk_file = QCheckBox("File")
        timeline_source_checks = [
            self.timeline_chk_detection,
            self.timeline_chk_xdr,
            self.timeline_chk_email,
            self.timeline_chk_outbound_mail,
            self.timeline_chk_file,
        ]
        for chk in timeline_source_checks:
            chk.setChecked(True)
            chk.setMinimumHeight(32)
            chk.setMinimumWidth(118)
            chk.setStyleSheet(f"""
                QCheckBox {{
                    color: {UI_THEME['text']};
                    font-weight: 800;
                    spacing: 6px;
                    background: transparent;
                }}
                QCheckBox::indicator {{
                    width: 16px;
                    height: 16px;
                    border: 1px solid {UI_THEME['accent']};
                    border-radius: 4px;
                    background: {UI_THEME['surface']};
                }}
                QCheckBox::indicator:checked {{
                    background: {UI_THEME['accent']};
                    border: 1px solid {UI_THEME['accent']};
                }}
            """)

        top.addWidget(lbl)
        top.addWidget(self.timeline_user_input, 1)
        top.addWidget(keyword_lbl)
        top.addWidget(self.timeline_keyword_input, 1)
        top.addWidget(self.timeline_chk_detection)
        top.addWidget(self.timeline_chk_xdr)
        top.addWidget(self.timeline_chk_email)
        top.addWidget(self.timeline_chk_outbound_mail)
        top.addWidget(self.timeline_chk_file)
        top.addWidget(self.timeline_btn_search)

        # ===============================
        # [A안 코드 - ACTIVE] QScrollArea + QWidget 카드 리스트
        # ===============================
        self.timeline_scroll = QScrollArea()
        self.timeline_scroll.setWidgetResizable(True)
        self.timeline_scroll.setFrameShape(QFrame.NoFrame)
        self.timeline_canvas = QWidget()
        self.timeline_result_layout = QVBoxLayout(self.timeline_canvas)
        self.timeline_result_layout.setContentsMargins(10, 10, 10, 10)
        self.timeline_result_layout.setSpacing(10)
        self.timeline_scroll.setWidget(self.timeline_canvas)

        self.timeline_detail_panel = QWidget()
        detail_layout = QVBoxLayout(self.timeline_detail_panel)
        detail_layout.setContentsMargins(8, 0, 0, 0)
        detail_layout.setSpacing(8)
        detail_header = QHBoxLayout()
        detail_header.setContentsMargins(0, 0, 0, 0)
        detail_header.setSpacing(8)
        self.timeline_detail_title = QLabel("타임라인 항목을 클릭하면 상세 이벤트가 표시됩니다.")
        self.timeline_detail_title.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-weight:900;")
        self.timeline_detail_close_btn = QPushButton("닫기")
        self.timeline_detail_close_btn.setFixedWidth(64)
        self.timeline_detail_close_btn.setMinimumHeight(30)
        self.timeline_detail_close_btn.setStyleSheet(self.button_style("secondary"))
        detail_header.addWidget(self.timeline_detail_title, 1)
        detail_header.addWidget(self.timeline_detail_close_btn, 0)
        self.timeline_detail_table = QTableWidget()
        detail_headers = [
            "Time", "Source", "User", "User ID", "Dept", "Asset/Mailbox",
            "Event", "Direction", "Peer", "Summary", "Indicator"
        ]
        self.timeline_detail_table.setColumnCount(len(detail_headers))
        self.timeline_detail_table.setHorizontalHeaderLabels(detail_headers)
        self.timeline_detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.timeline_detail_table.setSortingEnabled(True)
        self.timeline_detail_table.setContextMenuPolicy(Qt.CustomContextMenu)

        def open_timeline_detail_menu(pos):
            item = self.timeline_detail_table.itemAt(pos)
            if not item:
                return

            raw_item = self.timeline_detail_table.item(item.row(), 0)
            if not raw_item:
                return

            payload = raw_item.data(Qt.UserRole)
            if not payload:
                return

            raw = payload.get("raw") if isinstance(payload, dict) else payload
            if not raw and isinstance(payload, dict):
                raw = load_timeline_raw_event(payload.get("cache_file"), payload.get("row_index"))
            if not raw:
                return

            menu = QMenu(self.timeline_detail_table)
            detail_action = menu.addAction("View Raw Detail")
            action = menu.exec_(self.timeline_detail_table.viewport().mapToGlobal(pos))
            if action == detail_action:
                self.show_raw_dialog(raw)

        self.timeline_detail_table.customContextMenuRequested.connect(open_timeline_detail_menu)
        detail_layout.addLayout(detail_header)
        detail_layout.addWidget(self.timeline_detail_table, 1)
        self.timeline_detail_panel.hide()

        self.timeline_splitter = QSplitter(Qt.Horizontal)
        self.timeline_splitter.addWidget(self.timeline_scroll)
        self.timeline_splitter.addWidget(self.timeline_detail_panel)
        self.timeline_splitter.setStretchFactor(0, 2)
        self.timeline_splitter.setStretchFactor(1, 3)

        layout.addLayout(top)
        layout.addWidget(self.timeline_status_label)
        layout.addWidget(self.timeline_splitter, 1)

        self.timeline_groups = []
        self.timeline_worker = None

        def clear_timeline_results():
            self.timeline_load_more_btn = None
            while self.timeline_result_layout.count():
                item = self.timeline_result_layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()

        def add_empty_message(message):
            clear_timeline_results()
            box = QFrame()
            box.setStyleSheet(f"""
                QFrame {{
                    background: {UI_THEME['surface']};
                    border: 1px solid {UI_THEME['border_soft']};
                    border-radius: 14px;
                }}
            """)
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(18, 18, 18, 18)
            label = QLabel(message)
            label.setAlignment(Qt.AlignCenter)
            label.setWordWrap(True)
            label.setStyleSheet(f"color:{UI_THEME['text_muted']}; font-weight:800;")
            box_layout.addWidget(label)
            self.timeline_result_layout.addWidget(box)
            self.timeline_result_layout.addStretch(1)

        def source_color(source):
            return {
                "Detection": "#ef4444",
                "XDR": "#7c3aed",
                "Email": "#0ea5e9",
                "Outbound Mail": "#ec4899",
                "File": "#f59e0b",
            }.get(str(source), UI_THEME["accent"])

        def close_detail_panel():
            self.timeline_detail_table.clearContents()
            self.timeline_detail_table.setRowCount(0)
            self.timeline_detail_title.setText("타임라인 항목을 클릭하면 상세 이벤트가 표시됩니다.")
            self.timeline_detail_panel.hide()

        self.timeline_detail_close_btn.clicked.connect(close_detail_panel)

        def show_group_detail(group):
            items = group.get("items", []) if isinstance(group, dict) else []
            visible_items = sorted(items, key=lambda event: event.get("time", ""), reverse=True)[:TIMELINE_DETAIL_ROW_LIMIT]
            self.timeline_detail_panel.show()
            suffix = "" if len(visible_items) == len(items) else f" / 상위 {len(visible_items):,}건 표시"
            source_label = timeline_source_display_name(group.get("source", "None"))
            self.timeline_detail_title.setText(
                f"{group.get('bucket', 'None')} [{source_label}] {group.get('event', 'None')} - {len(items):,}건{suffix}"
            )
            table = self.timeline_detail_table
            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)
            for event in visible_items:
                r = table.rowCount()
                table.insertRow(r)
                values = [
                    event.get("time", "None"),
                    timeline_source_display_name(event.get("source", "None")),
                    event.get("user", "None"),
                    event.get("user_id", "None"),
                    event.get("dept", "미분류"),
                    event.get("asset", "None"),
                    event.get("event", "None"),
                    event.get("direction", "None"),
                    event.get("peer", "None"),
                    event.get("summary", "None"),
                    event.get("indicator", "None"),
                ]
                for c, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if c == 0:
                        item.setData(Qt.UserRole, event)
                    table.setItem(r, c, item)
            table.setSortingEnabled(True)
            self.timeline_splitter.setSizes([520, 680])

        # ===============================
        # [A안 코드 - ACTIVE] QScrollArea + QWidget 렌더링
        # 대량 검색 결과에서 QWidget 수천 개를 한 번에 만들면 UI가 멈출 수 있어
        # 250개 단위로 점진 렌더링합니다.
        # ===============================
        def remove_load_more_button():
            btn = getattr(self, "timeline_load_more_btn", None)
            self.timeline_load_more_btn = None
            if btn is not None:
                try:
                    self.timeline_result_layout.removeWidget(btn)
                    btn.deleteLater()
                except RuntimeError:
                    pass

        def add_load_more_button():
            remaining = max(0, len(self.timeline_groups) - self.timeline_render_offset)
            if remaining <= 0:
                self.timeline_result_layout.addStretch(1)
                return

            button = QPushButton(f"더 보기 ({min(TIMELINE_RENDER_BATCH_SIZE, remaining):,}개 추가 / 남은 {remaining:,}개)")
            button.setMinimumHeight(38)
            button.setStyleSheet(self.button_style("secondary"))
            button.clicked.connect(render_timeline_batch)
            self.timeline_load_more_btn = button
            self.timeline_result_layout.addWidget(button)

        def render_timeline_batch():
            remove_load_more_button()
            start = getattr(self, "timeline_render_offset", 0)
            end = min(start + TIMELINE_RENDER_BATCH_SIZE, len(self.timeline_groups))
            current_date = getattr(self, "timeline_render_current_date", "")

            for idx in range(start, end):
                group = self.timeline_groups[idx]
                bucket = str(group.get("bucket", ""))
                date_key = bucket[:10] if len(bucket) >= 10 else "Unknown"
                if date_key != current_date:
                    current_date = date_key
                    date_label = QLabel(date_key)
                    date_label.setAlignment(Qt.AlignCenter)
                    date_label.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-size:16px; font-weight:900; margin:12px;")
                    self.timeline_result_layout.addWidget(date_label)

                color = source_color(group.get("source"))
                row = QWidget()
                row_layout = QHBoxLayout(row)
                row_layout.setContentsMargins(0, 0, 0, 0)
                row_layout.setSpacing(10)

                card = TimelineEventCard(group, color)
                card.clicked.connect(show_group_detail)
                card.setMinimumWidth(320)
                card.setMaximumWidth(520)

                marker = QLabel("●\n│")
                marker.setAlignment(Qt.AlignCenter)
                marker.setStyleSheet(f"color:{color}; font-size:22px; font-weight:900;")
                marker.setFixedWidth(36)

                if idx % 2 == 0:
                    row_layout.addWidget(card, 4)
                    row_layout.addWidget(marker, 0)
                    row_layout.addStretch(4)
                else:
                    row_layout.addStretch(4)
                    row_layout.addWidget(marker, 0)
                    row_layout.addWidget(card, 4)

                self.timeline_result_layout.addWidget(row)

            self.timeline_render_offset = end
            self.timeline_render_current_date = current_date
            add_load_more_button()

        def render_timeline(groups):
            self.timeline_groups = groups or []
            self.timeline_render_offset = 0
            self.timeline_render_current_date = ""
            self.timeline_detail_table.clearContents()
            self.timeline_detail_table.setRowCount(0)
            self.timeline_detail_panel.hide()
            clear_timeline_results()

            if not self.timeline_groups:
                add_empty_message("검색 결과가 없습니다. 사용자명/User ID/메일/Hostname을 확인하세요.")
                return

            render_timeline_batch()

        def selected_sources():
            sources = []
            if self.timeline_chk_detection.isChecked():
                sources.append("Detection")
            if self.timeline_chk_xdr.isChecked():
                sources.append("XDR")
            if self.timeline_chk_email.isChecked():
                sources.append("Email")
            if self.timeline_chk_outbound_mail.isChecked():
                sources.append("Outbound Mail")
            if self.timeline_chk_file.isChecked():
                sources.append("File")
            return sources

        def set_search_enabled(enabled):
            self.timeline_btn_search.setEnabled(enabled)
            self.timeline_user_input.setEnabled(enabled)
            self.timeline_keyword_input.setEnabled(enabled)
            for chk in timeline_source_checks:
                chk.setEnabled(enabled)

        def start_search():
            keyword = self.timeline_user_input.text().strip()
            text_keyword = self.timeline_keyword_input.text().strip()
            if not keyword and not text_keyword:
                add_empty_message("사용자 또는 키워드를 입력하세요. Timeline은 전체 캐시 검색이라 빈 검색은 실행하지 않습니다.")
                self.timeline_status_label.setText("검색어를 입력하세요.")
                return

            sources = selected_sources()
            if not sources:
                add_empty_message("검색할 소스를 하나 이상 선택하세요.")
                self.timeline_status_label.setText("검색 소스가 선택되지 않았습니다.")
                return

            if self.timeline_worker and self.timeline_worker.isRunning():
                self.timeline_status_label.setText("이미 검색 중입니다. 잠시만 기다려주세요.")
                return

            set_search_enabled(False)
            clear_timeline_results()
            add_empty_message("전체 캐시 검색 중입니다...")
            self.timeline_status_label.setText("전체 캐시 검색 시작...")
            self.timeline_worker = TimelineSearchWorker(keyword, sources, text_keyword)
            self.timeline_worker.progress.connect(lambda msg: self.timeline_status_label.setText(msg))

            def on_ok(groups, stats):
                set_search_enabled(True)
                render_timeline(groups)
                shown = min(len(groups or []), TIMELINE_RENDER_BATCH_SIZE)
                render_note = f" / 화면 표시 {shown:,}/{len(groups or []):,}그룹" if groups else ""
                self.timeline_status_label.setText(f"{stats.get('message', '검색 완료')}{render_note}")

            def on_fail(message):
                set_search_enabled(True)
                add_empty_message(f"Timeline 검색 실패: {message}")
                self.timeline_status_label.setText(f"검색 실패: {message}")

            self.timeline_worker.ok.connect(on_ok)
            self.timeline_worker.fail.connect(on_fail)
            self.timeline_worker.start()

        self.timeline_btn_search.clicked.connect(start_search)
        self.timeline_user_input.returnPressed.connect(start_search)
        self.timeline_keyword_input.returnPressed.connect(start_search)
        self._refresh_timeline = lambda: None
        add_empty_message("Timeline은 날짜 선택 없이 전체 Detection/XDR/Inbound/Outbound/File 캐시에서 사용자 alias 또는 키워드로 검색합니다.")
        return root


    # ==================================================
    # Response Tab
    # ==================================================
    def tab_firewall(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        # ===============================
        # 입력 영역
        # ===============================
        top_box = QHBoxLayout()

        self.response_input = QTextEdit()
        self.response_input.setPlaceholderText(
            "차단할 IP를 한 줄에 하나씩 입력하세요.\n\n"
            "예시:\n"
            "104.238.194.12\n"
            "45.205.1.18\n"
            "89.248.163.168"
        )
        self.response_input.setMinimumHeight(180)

        right_box = QVBoxLayout()

        self.response_mode_combo = QComboBox()
        self.response_mode_combo.addItems(["IP", "DOMAIN"])
        self.response_mode_combo.setFixedWidth(120)

        self.btn_response_run = QPushButton("IP 객체 생성")
        self.btn_response_run.setFixedHeight(36)

        self.btn_response_clear = QPushButton("입력 초기화")
        self.btn_response_clear.setFixedHeight(36)

        fw_group = QGroupBox("Firewall Target")
        fw_layout = QVBoxLayout(fw_group)

        self.chk_fw_cloud = QCheckBox("Cloud")
        self.chk_fw_seoul = QCheckBox("Seoul")
        self.chk_fw_icheon = QCheckBox("Icheon")
        self.chk_fw_anseong = QCheckBox("Anseong")

        firewall_checkbox_style = f"""
        QCheckBox {{
            color: {UI_THEME['text']};
            font-weight: 700;
            spacing: 6px;
            background: transparent;
        }}
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border: 1px solid {UI_THEME['accent']};
            border-radius: 4px;
            background: {UI_THEME['surface']};
        }}
        QCheckBox::indicator:checked {{
            background: {UI_THEME['accent']};
            border: 1px solid {UI_THEME['accent']};
        }}
        """

        for chk in [
            self.chk_fw_cloud,
            self.chk_fw_seoul,
            self.chk_fw_icheon,
            self.chk_fw_anseong,
        ]:
            chk.setChecked(True)
            chk.setMinimumHeight(28)
            chk.setStyleSheet(firewall_checkbox_style)
            fw_layout.addWidget(chk)

        query_group = QGroupBox("Firewall Group View")
        query_layout = QVBoxLayout(query_group)

        self.btn_query_fw_cloud = QPushButton("Cloud 조회")
        self.btn_query_fw_seoul = QPushButton("Seoul 조회")
        self.btn_query_fw_icheon = QPushButton("Icheon 조회")
        self.btn_query_fw_anseong = QPushButton("Anseong 조회")

        for btn in [
            self.btn_query_fw_cloud,
            self.btn_query_fw_seoul,
            self.btn_query_fw_icheon,
            self.btn_query_fw_anseong,
        ]:
            btn.setFixedHeight(38)
            btn.setMinimumHeight(38)
            btn.setProperty("buttonRole", "secondary")
            btn.setStyleSheet(self.button_style("secondary"))
            query_layout.addWidget(btn)

        right_box.addWidget(self.response_mode_combo)
        right_box.addWidget(fw_group)
        right_box.addWidget(self.btn_response_run)
        right_box.addWidget(self.btn_response_clear)
        right_box.addWidget(query_group)
        right_box.addStretch()

        top_box.addWidget(self.response_input, 1)
        top_box.addLayout(right_box)

        layout.addLayout(top_box)

        # ===============================
        # 결과 테이블
        # ===============================
        self.response_result_table = QTableWidget()
        self.response_result_table.setColumnCount(7)
        self.response_result_table.setHorizontalHeaderLabels([
            "Firewall",
            "Target",
            "Object Name",
            "Result",
            "Status Code",
            "Message",
            "Error"
        ])
        self.response_result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.response_result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.response_result_table.setSelectionMode(QTableWidget.SingleSelection)
        self.response_result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.response_result_table.setAlternatingRowColors(True)
        self.response_result_table.verticalHeader().setVisible(False)

        layout.addWidget(self.response_result_table)

        # ===============================
        # 이벤트 연결
        # ===============================
        self.btn_response_run.clicked.connect(self.run_response_ip_create)
        self.btn_response_clear.clicked.connect(self.response_input.clear)
        self.response_mode_combo.currentTextChanged.connect(self.on_response_mode_changed)

        self.btn_query_fw_cloud.clicked.connect(lambda: self.run_firewall_group_query("Cloud"))
        self.btn_query_fw_seoul.clicked.connect(lambda: self.run_firewall_group_query("Seoul"))
        self.btn_query_fw_icheon.clicked.connect(lambda: self.run_firewall_group_query("Icheon"))
        self.btn_query_fw_anseong.clicked.connect(lambda: self.run_firewall_group_query("Anseong"))

        self.response_result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.response_result_table.customContextMenuRequested.connect(self.open_response_result_menu)

        self.on_response_mode_changed(self.response_mode_combo.currentText())

        return root

    def get_selected_firewall_names(self):
        selected = []

        if hasattr(self, "chk_fw_cloud") and self.chk_fw_cloud.isChecked():
            selected.append("Cloud")

        if hasattr(self, "chk_fw_seoul") and self.chk_fw_seoul.isChecked():
            selected.append("Seoul")

        if hasattr(self, "chk_fw_icheon") and self.chk_fw_icheon.isChecked():
            selected.append("Icheon")

        if hasattr(self, "chk_fw_anseong") and self.chk_fw_anseong.isChecked():
            selected.append("Anseong")

        return selected

    def get_firewall_config_by_name(self, firewall_name: str):
        firewall_name = str(firewall_name or "").strip()

        configs = get_firewall_target_configs(
            FIREWALL_ENV_PATH,
            selected_firewalls=[firewall_name]
        )

        if not configs:
            return None

        return configs[0]

    def set_firewall_query_buttons_enabled(self, enabled: bool):
        for attr in [
            "btn_query_fw_cloud",
            "btn_query_fw_seoul",
            "btn_query_fw_icheon",
            "btn_query_fw_anseong",
        ]:
            btn = getattr(self, attr, None)
            if btn:
                btn.setEnabled(enabled)

    def run_firewall_group_query(self, firewall_name: str):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 다른 작업이 실행 중입니다.")
            return

        firewall_name = str(firewall_name or "").strip()

        env_ok, env_msg = validate_firewall_env_file(
            FIREWALL_ENV_PATH,
            mode="IP",
            selected_firewalls=[firewall_name]
        )

        if not env_ok:
            QMessageBox.critical(self, "환경파일 오류", env_msg)
            return

        fw_config = self.get_firewall_config_by_name(firewall_name)
        if not fw_config:
            QMessageBox.critical(self, "환경파일 오류", f"{firewall_name} 방화벽 설정을 찾을 수 없습니다.")
            return

        self.running = True
        self.set_status(f"{firewall_name} Group Query", color="blue", spinning=True)
        self.set_firewall_query_buttons_enabled(False)

        log.info(f"[FIREWALL GROUP QUERY UI] clicked firewall={firewall_name}")

        self.firewall_group_worker = FirewallGroupQueryWorker(
            firewall_config=fw_config,
            parent=self
        )
        self.firewall_group_worker.ok.connect(self._on_firewall_group_query_ok)
        self.firewall_group_worker.fail.connect(self._on_firewall_group_query_fail)
        self.firewall_group_worker.start()

    def _on_firewall_group_query_ok(self, data: dict):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Firewall Group Query OK", color="green", spinning=False)
        self.set_firewall_query_buttons_enabled(True)

        self.show_firewall_group_dialog(data)

    def _on_firewall_group_query_fail(self, err: str):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Firewall Group Query FAIL", color="red", spinning=False)
        self.set_firewall_query_buttons_enabled(True)

        QMessageBox.critical(self, "조회 실패", err)


    def run_response_ip_create(self):
        if self.running:
            QMessageBox.warning(self, "진행 중", "이미 다른 작업이 실행 중입니다.")
            return

        mode = self.response_mode_combo.currentText().strip()
        raw_text = self.response_input.toPlainText().strip()

        selected_firewalls = self.get_selected_firewall_names()

        if not selected_firewalls:
            QMessageBox.warning(self, "방화벽 선택 필요", "작업 대상 방화벽을 1개 이상 선택하세요.")
            return

        env_ok, env_msg = validate_firewall_env_file(
            FIREWALL_ENV_PATH,
            mode=mode,
            selected_firewalls=selected_firewalls
        )
        if not env_ok:
            QMessageBox.critical(self, "환경파일 오류", env_msg)
            return

        firewall_configs = get_firewall_target_configs(
            FIREWALL_ENV_PATH,
            selected_firewalls=selected_firewalls
        )

        if not firewall_configs:
            QMessageBox.warning(self, "방화벽 선택 필요", "작업 가능한 방화벽 설정이 없습니다.")
            return

        if mode == "DOMAIN":
            target_list = parse_multiline_domains(raw_text)

            if not target_list:
                QMessageBox.warning(self, "입력 필요", "도메인을 한 줄에 하나씩 입력하세요.")
                return

            domain_ok, invalid_domains = validate_domain_list(target_list)
            if not domain_ok:
                QMessageBox.warning(
                    self,
                    "입력 오류",
                    "아래 값은 올바른 도메인 형식이 아닙니다.\n\n" + "\n".join(invalid_domains)
                )
                return

        else:
            target_list = parse_multiline_ips(raw_text)

            if not target_list:
                QMessageBox.warning(self, "입력 필요", "IP를 한 줄에 하나씩 입력하세요.")
                return

            ip_ok, invalid_ips = validate_ipv4_list(target_list)
            if not ip_ok:
                QMessageBox.warning(
                    self,
                    "입력 오류",
                    "아래 값은 올바른 IPv4 형식이 아닙니다.\n\n" + "\n".join(invalid_ips)
                )
                return

        self.btn_response_run.setEnabled(False)
        self.running = True
        self.set_status("Firewall Response", color="blue", spinning=True)

        log.info("[FIREWALL RESPONSE UI] run button clicked")
        log.info(f"[FIREWALL RESPONSE UI] mode={mode}")
        log.info(f"[FIREWALL RESPONSE UI] selected_firewalls={selected_firewalls}")
        log.info(f"[FIREWALL RESPONSE UI] target_count={len(target_list)}")
        log.info(f"[FIREWALL RESPONSE UI] target_list={target_list}")

        self.response_worker = FirewallResponseWorker(
            mode=mode,
            target_list=target_list,
            firewall_configs=firewall_configs,
            parent=self
        )
        self.response_worker.ok.connect(self._on_response_ip_create_ok)
        self.response_worker.fail.connect(self._on_response_ip_create_fail)
        self.response_worker.start()


    def _on_response_ip_create_ok(self, results):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Firewall Response OK", color="green", spinning=False)
        self.btn_response_run.setEnabled(True)

        self.response_result_table.setRowCount(0)

        success_count = 0
        exists_count = 0
        fail_count = 0

        for item in results:
            if not isinstance(item, dict):
                continue

            firewall = str(item.get("firewall", "Unknown"))
            target = str(item.get("target", item.get("ip", "")))
            name = str(item.get("name", ""))
            success = bool(item.get("success", False))
            error = str(item.get("error", ""))
            response_text = str(item.get("response", ""))

            parsed = parse_firewall_api_response(response_text)
            status_code = str(parsed.get("code", ""))
            message = str(parsed.get("message", ""))

            if status_code == "200":
                success_count += 1
                result_text = "SUCCESS"

            elif status_code in ("502", "503"):
                exists_count += 1
                result_text = "EXISTS"

            else:
                fail_count += 1
                result_text = "FAIL"

            row = self.response_result_table.rowCount()
            self.response_result_table.insertRow(row)

            item_firewall = QTableWidgetItem(firewall)
            item_target = QTableWidgetItem(target)
            item_name = QTableWidgetItem(name)
            item_result = QTableWidgetItem(result_text)
            item_code = QTableWidgetItem(status_code)
            item_message = QTableWidgetItem(message)
            item_error = QTableWidgetItem(error)

            raw_data = {
                "firewall": firewall,
                "target": target,
                "ip": target,
                "name": name,
                "success": success,
                "result": result_text,
                "status_code": status_code,
                "message": message,
                "error": error,
                "response": response_text,
            }

            item_firewall.setData(Qt.UserRole, raw_data)

            if result_text == "SUCCESS":
                item_result.setBackground(QColor("#dcfce7"))
                item_result.setForeground(QColor("#166534"))
                item_code.setBackground(QColor("#dcfce7"))
                item_code.setForeground(QColor("#166534"))

            elif result_text == "EXISTS":
                item_result.setBackground(QColor("#fef9c3"))
                item_result.setForeground(QColor("#854d0e"))
                item_code.setBackground(QColor("#fef9c3"))
                item_code.setForeground(QColor("#854d0e"))

            else:
                item_result.setBackground(QColor("#fee2e2"))
                item_result.setForeground(QColor("#991b1b"))
                item_code.setBackground(QColor("#fee2e2"))
                item_code.setForeground(QColor("#991b1b"))

            self.response_result_table.setItem(row, 0, item_firewall)
            self.response_result_table.setItem(row, 1, item_target)
            self.response_result_table.setItem(row, 2, item_name)
            self.response_result_table.setItem(row, 3, item_result)
            self.response_result_table.setItem(row, 4, item_code)
            self.response_result_table.setItem(row, 5, item_message)
            self.response_result_table.setItem(row, 6, item_error)

        self.save_response_results_to_file(results)

        QMessageBox.information(
            self,
            "Firewall Response",
            f"작업 완료\n성공: {success_count}\n중복: {exists_count}\n실패: {fail_count}"
        )


    def _on_response_ip_create_fail(self, err):
        self.running = False
        self._spin_timer.stop()
        self.set_status("Firewall Response FAIL", color="red", spinning=False)
        self.btn_response_run.setEnabled(True)

        log.error(f"[FIREWALL RESPONSE UI] fail: {err}")
        QMessageBox.critical(self, "Firewall Response Error", err)

    def get_response_success_items(self):
        results = []

        for row in range(self.response_result_table.rowCount()):
            item_fw = self.response_result_table.item(row, 0)
            if not item_fw:
                continue

            raw_data = item_fw.data(Qt.UserRole)
            if not isinstance(raw_data, dict):
                continue

            if raw_data.get("result") != "SUCCESS":
                continue

            results.append(raw_data)

        return results

    def open_response_result_menu(self, pos):
        item = self.response_result_table.itemAt(pos)

        menu = QMenu(self)

        action_view = None
        if item:
            action_view = menu.addAction("View Raw Response")

        menu.addSeparator()
        action_copy_success_targets = menu.addAction("Copy Success Targets")
        action_copy_success_names = menu.addAction("Copy Success Object Names")

        action = menu.exec_(self.response_result_table.viewport().mapToGlobal(pos))

        if action_view and action == action_view:
            raw_item = self.response_result_table.item(item.row(), 0)
            if not raw_item:
                return

            raw_data = raw_item.data(Qt.UserRole)
            if not raw_data:
                return

            self.show_raw_dialog(raw_data)

        elif action == action_copy_success_targets:
            success_items = self.get_response_success_items()
            if not success_items:
                QMessageBox.information(self, "Copy", "성공한 대상이 없습니다.")
                return

            text = "\n".join([
                f"{x.get('firewall', '')}\t{x.get('target', x.get('ip', ''))}"
                for x in success_items
                if str(x.get("target", x.get("ip", ""))).strip()
            ])
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copy", "성공한 대상 목록을 복사했습니다.")

        elif action == action_copy_success_names:
            success_items = self.get_response_success_items()
            if not success_items:
                QMessageBox.information(self, "Copy", "성공한 객체명이 없습니다.")
                return

            text = "\n".join([
                f"{x.get('firewall', '')}\t{x.get('name', '')}"
                for x in success_items
                if str(x.get("name", "")).strip()
            ])
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copy", "성공한 객체명 목록을 복사했습니다.")


    # ==================================================
    # Config Tab / Data Index actions
    # - Handles the Index Data card button and status labels.
    # - Uses DataIndexWorker to update app_cache.db and timeline_index.db without blocking the UI.
    # ==================================================
    def run_data_index(self):
        if getattr(self, "data_index_worker", None) and self.data_index_worker.isRunning():
            self.set_status("Data index running", color="blue", spinning=True)
            return

        self.btn_data_index.setEnabled(False)
        self.set_status("Data index", color="blue", spinning=True)
        self.lbl_index_status.setText("Status: RUNNING")
        self.data_index_worker = DataIndexWorker()
        self.data_index_worker.progress.connect(self._on_data_index_progress)
        self.data_index_worker.ok.connect(self._on_data_index_ok)
        self.data_index_worker.fail.connect(self._on_data_index_fail)
        self.data_index_worker.start()

    def _on_data_index_progress(self, message):
        self.lbl_index_status.setText(f"Status: {message}")
        self.set_status(str(message), color="blue", spinning=True)

    def _on_data_index_ok(self, stats):
        self.btn_data_index.setEnabled(True)
        self._spin_timer.stop()
        self.set_status("Data index OK", color="green", spinning=False)
        built_at = stats.get("built_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.lbl_index_last.setText(f"Last Build: {built_at}")
        self.lbl_index_status.setText(
            f"Status: OK (Data {int(stats.get('data_indexed', 0)):,} indexed / {int(stats.get('data_skipped', 0)):,} skipped, Timeline {int(stats.get('indexed', 0)):,} indexed / {int(stats.get('skipped', 0)):,} skipped, Sensitive Files {int(stats.get('sensitive_index_rows', 0)):,} records, Sensitive Sites {int(stats.get('sensitive_sites_index_rows', 0)):,} records)"
        )
        self.lbl_index_rows.setText(f"Data Rows: {int(stats.get('data_total_rows', stats.get('data_rows', 0))):,}")
        self.lbl_index_events.setText(f"Timeline Events: {int(stats.get('events', 0)):,}")
        self.lbl_index_tokens.setText(f"Search Tokens: {int(stats.get('tokens', 0)):,}")
        self.lbl_index_files.setText(f"Cache Files: {int(stats.get('data_total_files', stats.get('files', 0))):,}")
        self.sensitive_files_loaded = False
        self.sensitive_sites_loaded = False
        if self.current_logical_tab_name() == "Sensitive Files" and hasattr(self, "_refresh_sensitive_files"):
            self._refresh_sensitive_files()
        if self.current_logical_tab_name() == "Sensitive Sites" and hasattr(self, "_refresh_sensitive_sites"):
            self._refresh_sensitive_sites()

        if self.auto_continue_after_index:
            self.auto_continue_after_index = False
            self.run_next_auto_pending()

    def _on_data_index_fail(self, err):
        self.btn_data_index.setEnabled(True)
        self._spin_timer.stop()
        self.set_status("Data index FAIL", color="red", spinning=False)
        self.lbl_index_status.setText(f"Status: FAIL - {err}")
        self.auto_continue_after_index = False
        QMessageBox.critical(self, "Data Index 실패", err)

    def queue_auto_refresh_job(self, job_name):
        pending = self.auto_pending
        if isinstance(pending, str):
            pending = [pending]
        elif not isinstance(pending, list):
            pending = []

        if job_name not in pending:
            pending.append(job_name)

        self.auto_pending = pending

    def run_next_auto_pending(self):
        pending = self.auto_pending
        if isinstance(pending, str):
            pending = [pending]

        if not pending:
            self.auto_pending = []
            return

        next_job = pending.pop(0)
        self.auto_pending = pending
        self.run_auto_refresh_job(next_job)

    def run_auto_refresh_job(self, job_name):
        self.auto_index_after_refresh = True

        today = QDate.currentDate().toString("yyyy-MM-dd")
        if job_name in ("Detection", "Email"):
            date_str = f"{today}|{today}"
        elif job_name == "DLP":
            date_str = today
        elif job_name == "MailScreen":
            date_str = today
        else:
            self.run_refresh(job_name)
            return

        if self.running:
            self.queue_auto_refresh_job(job_name)
            return

        self.running = True
        self.set_status(f"{job_name} refresh", color="blue", spinning=True)

        self.worker = RefreshWorker(job_name=job_name, date_str=date_str)
        self.worker.ok.connect(self._on_refresh_ok)
        self.worker.fail.connect(self._on_refresh_fail)
        self.worker.progress.connect(self._on_refresh_progress)
        self.worker.start()

    def tab_config(self):
        btn_style = self.button_style("primary")
        secondary_btn_style = self.button_style("secondary")
        ghost_btn_style = self.button_style("ghost")
        root = QWidget()
        root.setObjectName("configRoot")
        root.setStyleSheet(self.config_root_stylesheet())
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(20)

        # ==================================================
        # 🔹 Cache Data 카드
        # ==================================================
        cache_card, cache_layout = self.make_card("Cache Data", legacy_title=True)

        btn_det_refresh = QPushButton("탐지 데이터 최신화")
        btn_mail_refresh = QPushButton("Inbound Mail 데이터 최신화")
        btn_endpoint_refresh = QPushButton("엔드포인트 데이터 최신화")
        btn_org_refresh = QPushButton("조직도 데이터 최신화")
        btn_user_refresh = QPushButton("유저 데이터 최신화")

        self.dlp_refresh_date = QDateEdit()
        self.dlp_refresh_date.setCalendarPopup(True)
        self.dlp_refresh_date.setDate(QDate.currentDate())
        self.dlp_refresh_date.setDisplayFormat("yyyy-MM-dd")

        self.mailscreen_refresh_date = QDateEdit()
        self.mailscreen_refresh_date.setCalendarPopup(True)
        self.mailscreen_refresh_date.setDate(QDate.currentDate())
        self.mailscreen_refresh_date.setDisplayFormat("yyyy-MM-dd")

        btn_dlp_refresh = QPushButton("DLP 데이터 최신화")
        btn_mailscreen_refresh = QPushButton("Outbound Mail 데이터 최신화")

        # ===== Detection 기간 선택 =====
        self.det_start_date = QDateEdit()
        self.det_start_date.setCalendarPopup(True)
        self.det_start_date.setDate(QDate.currentDate().addDays(-6))
        self.det_start_date.setDisplayFormat("yyyy-MM-dd")
        self.det_start_date.setMinimumHeight(36)

        self.det_end_date = QDateEdit()
        self.det_end_date.setCalendarPopup(True)
        self.det_end_date.setDate(QDate.currentDate())
        self.det_end_date.setDisplayFormat("yyyy-MM-dd")
        self.det_end_date.setMinimumHeight(36)

        # ===== Inbound Mail 기간 선택 =====
        self.mail_start_date = QDateEdit()
        self.mail_start_date.setCalendarPopup(True)
        self.mail_start_date.setDate(QDate.currentDate().addDays(-6))
        self.mail_start_date.setDisplayFormat("yyyy-MM-dd")
        self.mail_start_date.setMinimumHeight(36)

        self.mail_end_date = QDateEdit()
        self.mail_end_date.setCalendarPopup(True)
        self.mail_end_date.setDate(QDate.currentDate())
        self.mail_end_date.setDisplayFormat("yyyy-MM-dd")
        self.mail_end_date.setMinimumHeight(36)

        btn_det_refresh.clicked.connect(self.run_refresh_detection_range)
        btn_mail_refresh.clicked.connect(self.run_refresh_email_range)
        btn_endpoint_refresh.clicked.connect(lambda: self.run_refresh("Endpoint"))
        btn_org_refresh.clicked.connect(lambda: self.run_refresh("Organization"))
        btn_user_refresh.clicked.connect(lambda: self.run_refresh("User"))
        btn_dlp_refresh.clicked.connect(self.run_refresh_dlp)
        btn_mailscreen_refresh.clicked.connect(self.run_refresh_mailscreen)


        for widget in [
            self.det_start_date,
            self.det_end_date,
            self.mail_start_date,
            self.mail_end_date,
            self.dlp_refresh_date,
            self.mailscreen_refresh_date,
        ]:
            self.prepare_form_control(widget, height=38)

        for btn in [
            btn_det_refresh,
            btn_mail_refresh,
            btn_endpoint_refresh,
            btn_org_refresh,
            btn_user_refresh,
            btn_dlp_refresh,
            btn_mailscreen_refresh,
        ]:
            btn.setMinimumHeight(40)
            btn.setMinimumWidth(150)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn.setStyleSheet(btn_style)

        det_tilde = QLabel("~")
        det_tilde.setAlignment(Qt.AlignCenter)

        mail_tilde = QLabel("~")
        mail_tilde.setAlignment(Qt.AlignCenter)

# ===== Detection row =====
        det_row = QHBoxLayout()
        det_row.setSpacing(8)
        det_row.setContentsMargins(0, 0, 0, 0)
        det_row.addWidget(self.det_start_date, 1)
        det_row.addWidget(det_tilde)
        det_row.addWidget(self.det_end_date, 1)
        det_row.addWidget(btn_det_refresh, 1)

        # ===== Mail row =====
        mail_row = QHBoxLayout()
        mail_row.setSpacing(8)
        mail_row.setContentsMargins(0, 0, 0, 0)
        mail_row.addWidget(self.mail_start_date, 1)
        mail_row.addWidget(mail_tilde)
        mail_row.addWidget(self.mail_end_date, 1)
        mail_row.addWidget(btn_mail_refresh, 1)

        # ===== DLP row =====
        dlp_row = QHBoxLayout()
        dlp_row.setSpacing(8)
        dlp_row.setContentsMargins(0, 0, 0, 0)
        dlp_row.addWidget(self.dlp_refresh_date, 2)
        dlp_row.addWidget(btn_dlp_refresh, 1)

        # ===== MailScreen row =====
        mailscreen_row = QHBoxLayout()
        mailscreen_row.setSpacing(8)
        mailscreen_row.setContentsMargins(0, 0, 0, 0)
        mailscreen_row.addWidget(self.mailscreen_refresh_date, 2)
        mailscreen_row.addWidget(btn_mailscreen_refresh, 1)

        # ===== EP/Org/User row =====
        ep_org_row = QHBoxLayout()
        ep_org_row.setSpacing(8)
        ep_org_row.setContentsMargins(0, 0, 0, 0)
        ep_org_row.addWidget(btn_endpoint_refresh, 1)
        ep_org_row.addWidget(btn_org_refresh, 1)
        ep_org_row.addWidget(btn_user_refresh, 1)

        # 전체 묶기
        cache_rows = QVBoxLayout()
        cache_rows.setSpacing(10)
        cache_rows.setContentsMargins(0, 0, 0, 0)
        cache_rows.addLayout(det_row)
        cache_rows.addLayout(mail_row)
        cache_rows.addLayout(dlp_row)
        cache_rows.addLayout(mailscreen_row)
        cache_rows.addLayout(ep_org_row)

        cache_layout.addLayout(cache_rows)

        # ==================================================
        # 🔹 Auto Refresh 카드
        # ==================================================
        auto_card, auto_layout = self.make_card("Auto Refresh", legacy_title=True)

        self.chk_auto_det = QCheckBox("Detection - XDR Auto Refresh")
        self.chk_auto_mail = QCheckBox("Inbound Mail Auto Refresh")
        self.chk_auto_dlp = QCheckBox("DLP Auto Refresh")
        self.chk_auto_mailscreen = QCheckBox("Outbound Mail Auto Refresh")

        auto_checkbox_style = (
            f"QCheckBox {{ color:{UI_THEME['text']}; font-size:13px; font-weight:800; spacing:8px; }}"
            f"QCheckBox::indicator {{ width:16px; height:16px; }}"
        )
        for chk in [self.chk_auto_det, self.chk_auto_mail, self.chk_auto_dlp, self.chk_auto_mailscreen]:
            chk.setStyleSheet(auto_checkbox_style)
            chk.setMinimumHeight(22)

        self.spin_interval = QSpinBox()
        self.spin_interval.setObjectName("intervalSpin")
        self.spin_interval.setMinimum(1)
        self.spin_interval.setMaximum(1440)
        self.spin_interval.setValue(10)
        self.spin_interval.setSuffix(" min")
        self.spin_interval.setButtonSymbols(QAbstractSpinBox.UpDownArrows)
        self.spin_interval.setFixedSize(104, 28)
        self.spin_interval.setAlignment(Qt.AlignCenter)
        self.spin_interval.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        interval_label = QLabel("Interval")
        interval_label.setFixedWidth(56)
        interval_label.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-size:13px; font-weight:800;")

        interval_row = QHBoxLayout()
        interval_row.setContentsMargins(0, 0, 0, 0)
        interval_row.setSpacing(6)
        interval_row.addWidget(interval_label)
        interval_row.addWidget(self.spin_interval)
        interval_row.addStretch()

        auto_layout.addWidget(self.chk_auto_det)
        auto_layout.addWidget(self.chk_auto_mail)
        auto_layout.addWidget(self.chk_auto_dlp)
        auto_layout.addWidget(self.chk_auto_mailscreen)
        auto_layout.addLayout(interval_row)

        auto_status_grid = QGridLayout()
        auto_status_grid.setContentsMargins(0, 4, 0, 0)
        auto_status_grid.setHorizontalSpacing(8)
        auto_status_grid.setVerticalSpacing(2)

        self.lbl_det_status = QLabel("-")
        self.lbl_det_result = QLabel("-")
        self.lbl_mail_status = QLabel("-")
        self.lbl_mail_result = QLabel("-")
        self.lbl_dlp_status = QLabel("-")
        self.lbl_dlp_result = QLabel("-")
        self.lbl_mailscreen_status = QLabel("-")
        self.lbl_mailscreen_result = QLabel("-")

        auto_status_columns = [
            ("Detection", self.lbl_det_status, self.lbl_det_result),
            ("Inbound", self.lbl_mail_status, self.lbl_mail_result),
            ("DLP", self.lbl_dlp_status, self.lbl_dlp_result),
            ("Outbound", self.lbl_mailscreen_status, self.lbl_mailscreen_result),
        ]
        for col, (title, last_label, result_label) in enumerate(auto_status_columns):
            title_label = QLabel(title)
            title_label.setAlignment(Qt.AlignCenter)
            title_label.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-size:10px; font-weight:800;")
            last_label.setAlignment(Qt.AlignCenter)
            result_label.setAlignment(Qt.AlignCenter)
            last_label.setStyleSheet("color:#374151; font-size:10px; font-weight:600;")
            result_label.setStyleSheet("color:#374151; font-size:10px; font-weight:700;")
            auto_status_grid.addWidget(title_label, 0, col)
            auto_status_grid.addWidget(last_label, 1, col)
            auto_status_grid.addWidget(result_label, 2, col)
            auto_status_grid.setColumnStretch(col, 1)

        auto_layout.addLayout(auto_status_grid)

        self.chk_auto_det.stateChanged.connect(self.toggle_det_timer)
        self.chk_auto_mail.stateChanged.connect(self.toggle_mail_timer)
        self.chk_auto_dlp.stateChanged.connect(self.toggle_dlp_timer)
        self.chk_auto_mailscreen.stateChanged.connect(self.toggle_mailscreen_timer)
        self.spin_interval.valueChanged.connect(self.update_auto_interval)

        # ==================================================
        # Index Data card
        # - One button prepares SQLite data tables for normal tabs and search tokens for Timeline.
        # - The card shows row/event/token/file counts so index health is visible from Config.
        # ==================================================
        index_card, index_layout = self.make_card("Index Data", legacy_title=True)
        self.btn_data_index = QPushButton("전체 캐시 데이터 인덱싱")
        self.btn_data_index.setMinimumHeight(40)
        self.btn_data_index.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.btn_data_index.setStyleSheet(btn_style)

        self.lbl_index_last = QLabel("Last Build: -")
        self.lbl_index_status = QLabel("Status: -")
        self.lbl_index_rows = QLabel("Data Rows: -")
        self.lbl_index_events = QLabel("Timeline Events: -")
        self.lbl_index_tokens = QLabel("Search Tokens: -")
        self.lbl_index_files = QLabel("Cache Files: -")
        for label in [
            self.lbl_index_last,
            self.lbl_index_status,
            self.lbl_index_rows,
            self.lbl_index_events,
            self.lbl_index_tokens,
            self.lbl_index_files,
        ]:
            label.setStyleSheet("color:#374151; font-size:13px; font-weight:600;")

        index_desc = QLabel("전체 캐시 데이터를 SQLite 조회/검색 인덱스로 준비하고, 변경/신규 파일만 증분 반영합니다.")
        index_desc.setWordWrap(True)
        index_desc.setStyleSheet(f"color:{UI_THEME['text_muted']}; font-size:12px; font-weight:700;")
        index_layout.addWidget(index_desc)
        index_layout.addWidget(self.btn_data_index)
        index_layout.addWidget(self.lbl_index_last)
        index_layout.addWidget(self.lbl_index_status)
        index_layout.addWidget(self.lbl_index_rows)
        index_layout.addWidget(self.lbl_index_events)
        index_layout.addWidget(self.lbl_index_tokens)
        index_layout.addWidget(self.lbl_index_files)
        index_layout.addStretch()
        self.btn_data_index.clicked.connect(self.run_data_index)

        # Top card layout: Cache Data stays on the left; Auto Refresh and Index Data share the right side.
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(12)
        right_top = QHBoxLayout()
        right_top.setContentsMargins(0, 0, 0, 0)
        right_top.setSpacing(12)
        right_top.addWidget(auto_card, 1)
        right_top.addWidget(index_card, 1)
        top_row.addWidget(cache_card, 1)
        top_row.addLayout(right_top, 1)

        layout.addLayout(top_row)

        # ==================================================
        # 🔹 Export 카드
        # ==================================================
        export_card, export_layout = self.make_card("Export", legacy_title=True)

        today = QDate.currentDate()

        EXPORT_DATE_W = 116
        EXPORT_TIME_W = 82
        EXPORT_BTN_W = 180
        DLP_MACHINE_W = 150

        export_columns = QHBoxLayout()
        export_columns.setSpacing(14)
        export_columns.setContentsMargins(0, 0, 0, 0)
        export_left_layout = QVBoxLayout()
        export_left_layout.setSpacing(8)
        export_left_layout.setContentsMargins(0, 0, 0, 0)
        export_right_layout = QVBoxLayout()
        export_right_layout.setSpacing(8)
        export_right_layout.setContentsMargins(0, 0, 0, 0)
        export_columns.addLayout(export_left_layout, 2)
        export_columns.addLayout(export_right_layout, 1)
        export_layout.addLayout(export_columns)

        def prepare_export_control(widget):
            self.prepare_form_control(widget, height=38)
            if isinstance(widget, QDateEdit):
                widget.setFixedWidth(EXPORT_DATE_W)
            elif isinstance(widget, QTimeEdit):
                widget.setFixedWidth(EXPORT_TIME_W)
            elif isinstance(widget, QLineEdit):
                widget.setFixedWidth(DLP_MACHINE_W)

        # Detection Export
        det_layout = QHBoxLayout()
        det_layout.setSpacing(8)
        det_layout.setContentsMargins(0, 0, 0, 0)

        self.det_export_start_date = QDateEdit()
        self.det_export_start_time = QTimeEdit()
        self.det_export_end_date = QDateEdit()
        self.det_export_end_time = QTimeEdit()

        self.det_export_start_date.setDate(today.addDays(-6))
        self.det_export_end_date.setDate(today)
        self.det_export_start_date.setCalendarPopup(True)
        self.det_export_end_date.setCalendarPopup(True)
        self.det_export_start_time.setTime(QTime(0, 0, 0))
        self.det_export_end_time.setTime(QTime(23, 59, 59))
        self.det_export_start_time.setDisplayFormat("HH:mm:ss")
        self.det_export_end_time.setDisplayFormat("HH:mm:ss")

        btn_det_export = QPushButton("Detection Excel")
        btn_det_export.clicked.connect(self.export_detection_excel)
        btn_det_export.setStyleSheet(btn_style)

        for w in [self.det_export_start_date, self.det_export_start_time,
                  self.det_export_end_date, self.det_export_end_time]:
            prepare_export_control(w)
        btn_det_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_det_export.setMinimumHeight(38)

        det_layout.addWidget(self.det_export_start_date, 1)
        det_layout.addWidget(self.det_export_start_time, 1)
        det_layout.addWidget(self.det_export_end_date, 1)
        det_layout.addWidget(self.det_export_end_time, 1)
        det_layout.addWidget(btn_det_export, 1)

        export_left_layout.addLayout(det_layout)

        # Email - XDR Export
        xdr_layout = QHBoxLayout()
        xdr_layout.setSpacing(8)
        xdr_layout.setContentsMargins(0, 0, 0, 0)

        self.xdr_export_start_date = QDateEdit()
        self.xdr_export_start_time = QTimeEdit()
        self.xdr_export_end_date = QDateEdit()
        self.xdr_export_end_time = QTimeEdit()

        self.xdr_export_start_date.setDate(today.addDays(-6))
        self.xdr_export_end_date.setDate(today)
        self.xdr_export_start_date.setCalendarPopup(True)
        self.xdr_export_end_date.setCalendarPopup(True)
        self.xdr_export_start_time.setTime(QTime(0, 0, 0))
        self.xdr_export_end_time.setTime(QTime(23, 59, 59))
        self.xdr_export_start_time.setDisplayFormat("HH:mm:ss")
        self.xdr_export_end_time.setDisplayFormat("HH:mm:ss")

        btn_xdr_export = QPushButton("Email XDR Excel")
        btn_xdr_export.clicked.connect(self.export_detection_xdr_excel)
        btn_xdr_export.setStyleSheet(btn_style)

        for w in [self.xdr_export_start_date, self.xdr_export_start_time,
                  self.xdr_export_end_date, self.xdr_export_end_time]:
            prepare_export_control(w)
        btn_xdr_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_xdr_export.setMinimumHeight(38)

        xdr_layout.addWidget(self.xdr_export_start_date, 1)
        xdr_layout.addWidget(self.xdr_export_start_time, 1)
        xdr_layout.addWidget(self.xdr_export_end_date, 1)
        xdr_layout.addWidget(self.xdr_export_end_time, 1)
        xdr_layout.addWidget(btn_xdr_export, 1)

        export_left_layout.addLayout(xdr_layout)

        # Inbound Mail Export
        mail_layout = QHBoxLayout()
        mail_layout.setSpacing(8)
        mail_layout.setContentsMargins(0, 0, 0, 0)

        self.mail_export_start_date = QDateEdit()
        self.mail_export_start_time = QTimeEdit()
        self.mail_export_end_date = QDateEdit()
        self.mail_export_end_time = QTimeEdit()

        self.mail_export_start_date.setDate(today.addDays(-6))
        self.mail_export_end_date.setDate(today)
        self.mail_export_start_date.setCalendarPopup(True)
        self.mail_export_end_date.setCalendarPopup(True)
        self.mail_export_start_time.setTime(QTime(0, 0, 0))
        self.mail_export_end_time.setTime(QTime(23, 59, 59))
        self.mail_export_start_time.setDisplayFormat("HH:mm:ss")
        self.mail_export_end_time.setDisplayFormat("HH:mm:ss")

        btn_mail_export = QPushButton("Inbound Excel")
        btn_mail_export.setStyleSheet(btn_style)
        btn_mail_export.clicked.connect(self.export_email_excel)

        for w in [self.mail_export_start_date, self.mail_export_start_time,
                  self.mail_export_end_date, self.mail_export_end_time]:
            prepare_export_control(w)
        btn_mail_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_mail_export.setMinimumHeight(38)

        mail_layout.addWidget(self.mail_export_start_date, 1)
        mail_layout.addWidget(self.mail_export_start_time, 1)
        mail_layout.addWidget(self.mail_export_end_date, 1)
        mail_layout.addWidget(self.mail_export_end_time, 1)
        mail_layout.addWidget(btn_mail_export, 1)

        export_left_layout.addLayout(mail_layout)

        # DLP Export
        dlp_layout = QHBoxLayout()
        dlp_layout.setSpacing(8)
        dlp_layout.setContentsMargins(0, 0, 0, 0)

        self.dlp_export_start_date = QDateEdit()
        self.dlp_export_start_time = QTimeEdit()
        self.dlp_export_end_date = QDateEdit()
        self.dlp_export_end_time = QTimeEdit()

        self.dlp_export_machine_input = QLineEdit()
        self.dlp_export_machine_input.setPlaceholderText("Machine Name")

        self.dlp_export_start_date.setDate(today.addDays(-6))
        self.dlp_export_end_date.setDate(today)
        self.dlp_export_start_date.setCalendarPopup(True)
        self.dlp_export_end_date.setCalendarPopup(True)
        self.dlp_export_start_time.setTime(QTime(0, 0, 0))
        self.dlp_export_end_time.setTime(QTime(23, 59, 59))
        self.dlp_export_start_time.setDisplayFormat("HH:mm:ss")
        self.dlp_export_end_time.setDisplayFormat("HH:mm:ss")

        btn_dlp_export = QPushButton("DLP Excel")
        btn_dlp_export.setStyleSheet(btn_style)
        btn_dlp_export.clicked.connect(self.export_dlp_excel)

        for w in [self.dlp_export_start_date, self.dlp_export_start_time,
                  self.dlp_export_end_date, self.dlp_export_end_time,
                  self.dlp_export_machine_input]:
            prepare_export_control(w)
        btn_dlp_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_dlp_export.setMinimumHeight(38)

        dlp_layout.addWidget(self.dlp_export_start_date, 1)
        dlp_layout.addWidget(self.dlp_export_start_time, 1)
        dlp_layout.addWidget(self.dlp_export_end_date, 1)
        dlp_layout.addWidget(self.dlp_export_end_time, 1)
        dlp_layout.addWidget(self.dlp_export_machine_input, 1)
        dlp_layout.addWidget(btn_dlp_export, 1)

        export_left_layout.addLayout(dlp_layout)

        # MailScreen Export
        mailscreen_layout = QHBoxLayout()
        mailscreen_layout.setSpacing(8)
        mailscreen_layout.setContentsMargins(0, 0, 0, 0)

        self.mailscreen_export_start_date = QDateEdit()
        self.mailscreen_export_start_time = QTimeEdit()
        self.mailscreen_export_end_date = QDateEdit()
        self.mailscreen_export_end_time = QTimeEdit()

        self.mailscreen_export_start_date.setDate(today.addDays(-6))
        self.mailscreen_export_end_date.setDate(today)
        self.mailscreen_export_start_date.setCalendarPopup(True)
        self.mailscreen_export_end_date.setCalendarPopup(True)
        self.mailscreen_export_start_time.setTime(QTime(0, 0, 0))
        self.mailscreen_export_end_time.setTime(QTime(23, 59, 59))
        self.mailscreen_export_start_time.setDisplayFormat("HH:mm:ss")
        self.mailscreen_export_end_time.setDisplayFormat("HH:mm:ss")

        mailscreen_export_spacer = QLabel("")
        btn_mailscreen_export = QPushButton("Outbound Excel")
        btn_mailscreen_export.setStyleSheet(btn_style)
        btn_mailscreen_export.clicked.connect(self.export_mailscreen_excel)

        for w in [self.mailscreen_export_start_date, self.mailscreen_export_start_time,
                  self.mailscreen_export_end_date, self.mailscreen_export_end_time]:
            prepare_export_control(w)
        btn_mailscreen_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_mailscreen_export.setMinimumHeight(38)

        mailscreen_layout.addWidget(self.mailscreen_export_start_date, 1)
        mailscreen_layout.addWidget(self.mailscreen_export_start_time, 1)
        mailscreen_layout.addWidget(self.mailscreen_export_end_date, 1)
        mailscreen_layout.addWidget(self.mailscreen_export_end_time, 1)
        mailscreen_layout.addWidget(mailscreen_export_spacer, 1)
        mailscreen_layout.addWidget(btn_mailscreen_export, 1)

        export_left_layout.addLayout(mailscreen_layout)

        sensitive_title = QLabel("Sensitive")
        sensitive_title.setStyleSheet(f"color:{UI_THEME['accent_text']}; font-size:12px; font-weight:900;")
        export_right_layout.addWidget(sensitive_title)

        def make_sensitive_export_row(button_text, click_handler):
            wrapper = QVBoxLayout()
            wrapper.setSpacing(6)
            wrapper.setContentsMargins(0, 0, 0, 0)
            dt_row = QHBoxLayout()
            dt_row.setSpacing(6)
            start_date = QDateEdit()
            start_time = QTimeEdit()
            end_date = QDateEdit()
            end_time = QTimeEdit()
            start_date.setDate(today.addDays(-6))
            end_date.setDate(today)
            start_date.setCalendarPopup(True)
            end_date.setCalendarPopup(True)
            start_time.setTime(QTime(0, 0, 0))
            end_time.setTime(QTime(23, 59, 59))
            start_time.setDisplayFormat("HH:mm:ss")
            end_time.setDisplayFormat("HH:mm:ss")
            for w in [start_date, start_time, end_date, end_time]:
                prepare_export_control(w)
            dt_row.addWidget(start_date)
            dt_row.addWidget(start_time)
            dt_row.addWidget(end_date)
            dt_row.addWidget(end_time)
            btn = QPushButton(button_text)
            btn.setStyleSheet(btn_style)
            btn.setMinimumHeight(38)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn.clicked.connect(click_handler)
            wrapper.addLayout(dt_row)
            wrapper.addWidget(btn)
            return wrapper, start_date, start_time, end_date, end_time

        sensitive_files_row, self.sensitive_files_export_start_date, self.sensitive_files_export_start_time, self.sensitive_files_export_end_date, self.sensitive_files_export_end_time = make_sensitive_export_row(
            "Sensitive Files Excel",
            self.export_sensitive_files_excel,
        )
        sensitive_sites_row, self.sensitive_sites_export_start_date, self.sensitive_sites_export_start_time, self.sensitive_sites_export_end_date, self.sensitive_sites_export_end_time = make_sensitive_export_row(
            "Sensitive Sites Excel",
            self.export_sensitive_sites_excel,
        )
        export_right_layout.addLayout(sensitive_files_row)
        export_right_layout.addLayout(sensitive_sites_row)
        export_right_layout.addStretch()

        layout.addWidget(export_card)

        # ==================================================
        # 🔹 Report 카드
        # ==================================================
        report_card, report_layout = self.make_card("Report", legacy_title=True)

        self.report_start_date = QDateEdit()
        self.report_start_time = QTimeEdit()
        self.report_end_date = QDateEdit()
        self.report_end_time = QTimeEdit()

        self.report_start_date.setCalendarPopup(True)
        self.report_end_date.setCalendarPopup(True)

        self.report_start_date.setDate(QDate.currentDate().addDays(-7))
        self.report_end_date.setDate(QDate.currentDate())

        self.report_start_time.setTime(QTime(0, 0, 0))
        self.report_end_time.setTime(QTime(23, 59, 59))

        self.report_start_time.setDisplayFormat("HH:mm:ss")
        self.report_end_time.setDisplayFormat("HH:mm:ss")

        for w in [
            self.report_start_date,
            self.report_start_time,
            self.report_end_date,
            self.report_end_time,
        ]:
            prepare_export_control(w)

        btn_report = QPushButton("Download Security Report (PDF)")
        self.btn_security_report = btn_report
        btn_report.clicked.connect(self.start_security_report_worker)
        btn_report.setStyleSheet(btn_style)
        btn_report.setMinimumHeight(38)

        btn_report_exception = QPushButton("Report exception List")
        btn_report_exception.clicked.connect(self.open_report_exception_list_dialog)
        btn_report_exception.setStyleSheet(secondary_btn_style)
        btn_report_exception.setMinimumHeight(38)

        row = QHBoxLayout()
        row.addWidget(self.report_start_date)
        row.addWidget(self.report_start_time)
        row.addWidget(self.report_end_date)
        row.addWidget(self.report_end_time)
        row.addWidget(btn_report_exception)
        row.addWidget(btn_report)

        report_layout.addLayout(row)

        layout.addWidget(report_card)

        # ===============================
        # Folders (Quick Access)
        # ===============================
        folder_group, folder_layout = self.make_card("Folders", legacy_title=True)

        row = QHBoxLayout()   # 👈 가로 레이아웃 생성

        btn_log = QPushButton("Logs")
        btn_cache = QPushButton("Cache")
        btn_export = QPushButton("Exports")
        btn_report = QPushButton("Reports")

        for b in [btn_log, btn_cache, btn_export, btn_report]:
            b.setStyleSheet(secondary_btn_style)
            b.setMinimumHeight(38)
            row.addWidget(b)

        folder_layout.addLayout(row)   # 👈 카드에 가로 레이아웃 추가

        folder_layout.setStretch(0,1)
        folder_layout.setStretch(1,1)
        folder_layout.setStretch(2,1)
        folder_layout.setStretch(3,1)

        folder_group.setLayout(folder_layout)

        layout.addWidget(folder_group)

        btn_log.clicked.connect(self.open_log_folder)
        btn_cache.clicked.connect(self.open_cache_folder)
        btn_export.clicked.connect(self.open_export_folder)
        btn_report.clicked.connect(self.open_report_folder)

        layout.addStretch()

        return root


    def open_cache_folder(self):
        try:
            os.startfile(CACHE_DIR)
        except Exception:
            QMessageBox.warning(self, "실패", "캐시 폴더를 열 수 없습니다.")

    def open_export_folder(self):
        os.startfile(EXPORT_DIR)

    def open_report_folder(self):
        os.startfile(REPORT_DIR)

    def open_report_exception_list_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Report exception List")
        dialog.resize(700, 500)

        layout = QVBoxLayout(dialog)

        info = QLabel(
            "형식: 사용자명=부서명\n"
            "예) jeonjisu=디자인팀\n"
            "예) khyim=CX디자인팀"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        editor = QTextEdit()
        editor.setAcceptRichText(False)

        try:
            if os.path.exists(REPORT_EXCEPTION_LIST_PATH):
                with open(REPORT_EXCEPTION_LIST_PATH, "r", encoding="utf-8") as f:
                    editor.setPlainText(f.read())
        except Exception as e:
            QMessageBox.warning(self, "Load Error", str(e))

        layout.addWidget(editor)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("저장")
        btn_close = QPushButton("닫기")

        btn_row.addStretch()
        btn_row.addWidget(btn_save)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)

        def save_action():
            try:
                save_report_exception_text(editor.toPlainText())

                reload_all_data()
                self.refresh_all_tables()

                QMessageBox.information(
                    dialog,
                    "완료",
                    f"저장 완료\n{REPORT_EXCEPTION_LIST_PATH}"
                )
            except Exception as e:
                QMessageBox.critical(dialog, "Save Error", str(e))

        btn_save.clicked.connect(save_action)
        btn_close.clicked.connect(dialog.accept)

        dialog.exec_()

    def draw_table(
        self,
        c,
        x,
        y,
        headers,
        rows,
        font_name=None,
        font_size=10,
        col_widths=None,
        row_height=20,
        page_threshold=120
    ):
        from reportlab.pdfbase.pdfmetrics import stringWidth

        if not font_name:
            try:
                font_name = c._fontname
            except Exception:
                font_name = "Helvetica"

        if col_widths is None:
            col_count = max(len(headers), 1)
            if col_count == 2:
                col_widths = [350, 100]
            elif col_count == 3:
                col_widths = [220, 160, 70]
            else:
                col_widths = [150] * col_count

        def wrap_text(text, width):
            text = str(text or "")
            if not text.strip():
                return [""]

            words = text.split()
            if not words:
                return [text]

            lines = []
            current = ""

            for word in words:
                trial = f"{current} {word}".strip()
                if stringWidth(trial, font_name, font_size) <= max(20, width - 8):
                    current = trial
                else:
                    if current:
                        lines.append(current)
                    current = word

            if current:
                lines.append(current)

            return lines or [""]

        def draw_row(row_y, values, is_header=False):
            nonlocal y

            wrapped_cols = []
            max_lines = 1

            for i, value in enumerate(values):
                width = col_widths[i] if i < len(col_widths) else 120
                wrapped = wrap_text(value, width)
                wrapped_cols.append(wrapped)
                max_lines = max(max_lines, len(wrapped))

            current_row_height = max(row_height, 16 * max_lines + 8)

            y = self.check_page(c, row_y, threshold=page_threshold, font_name=font_name, font_size=font_size)

            if is_header:
                c.setFillGray(0.90)
                c.rect(x, y - current_row_height + 4, sum(col_widths), current_row_height, fill=1, stroke=0)
                c.setFillGray(0)

            c.setFont(font_name, font_size)

            offset_x = x
            for i, wrapped in enumerate(wrapped_cols):
                width = col_widths[i] if i < len(col_widths) else 120

                c.rect(offset_x, y - current_row_height + 4, width, current_row_height, fill=0, stroke=1)

                text_y = y - 12
                for line in wrapped:
                    c.drawString(offset_x + 4, text_y, str(line))
                    text_y -= 14

                offset_x += width

            return y - current_row_height

        y = draw_row(y, headers, is_header=True)

        for row in rows:
            y = draw_row(y, row, is_header=False)

        return y - 6

    def draw_summary_card(self, c, x, y, title, value, width=160, height=60, font_name="Helvetica"):
        # 카드 테두리
        c.roundRect(x, y - height, width, height, 8, stroke=1, fill=0)

        # 제목
        c.setFont(font_name, 9)
        c.drawString(x + 10, y - 18, title)

        # 값 (크게)
        c.setFont(font_name, 16)
        c.drawString(x + 10, y - 40, str(value))


    def draw_risk_card(self, c, x, y, risk_level, score, width=520, height=70, font_name="Helvetica"):
        # 색상 느낌만 주기 (배경 없이 강조)
        c.roundRect(x, y - height, width, height, 10, stroke=1, fill=0)

        c.setFont(font_name, 12)
        c.drawString(x + 15, y - 22, "Overall Risk Level")

        c.setFont(font_name, 20)
        c.drawString(x + 15, y - 50, f"{risk_level} (Score: {score}/100)")



    def check_page(self, c, y, threshold=120, font_name=None, font_size=10):
        if y < threshold:
            footer = getattr(c, "_smu_report_draw_footer", None)
            after_show_page = getattr(c, "_smu_report_after_show_page", None)
            if callable(footer):
                footer()
            c.showPage()
            if callable(after_show_page):
                after_show_page()
            if font_name:
                c.setFont(font_name, font_size)
            return 800
        return y


    def create_detection_graph(self, timeline):

        import matplotlib.pyplot as plt

        dates = sorted(timeline)
        values = [timeline[d] for d in dates]

        plt.figure(figsize=(8,4))

        plt.plot(dates, values, marker='o')

        plt.title("Detection Trend")
        plt.xlabel("Date")
        plt.ylabel("Detections")

        plt.grid(True)

        # ===== 여기 추가 =====
        n = len(dates)

        if n > 25:
            step = 5
        elif n > 15:
            step = 3
        else:
            step = 1

        plt.xticks(dates[::step], rotation=45)
        # ====================

        path = "reports/detection_trend.png"

        plt.tight_layout()
        plt.savefig(path)
        plt.close()

        return path

    def create_report_trend_graph(self, detection_timeline, graph_path, font_name="Helvetica"):
        if not detection_timeline:
            return None

        x_labels = list(sorted(detection_timeline.keys()))
        y_values = [detection_timeline[d] for d in x_labels]

        fig = Figure(figsize=(8.4, 3.4))
        ax = fig.add_subplot(111)

        x_positions = list(range(len(x_labels)))
        ax.plot(
            x_positions,
            y_values,
            marker="o",
            linewidth=2.2,
            markersize=5
        )

        ax.set_title("Detection Trend", fontsize=13, pad=12)
        ax.set_xlabel("Date", fontsize=10)
        ax.set_ylabel("Count", fontsize=10)

        ax.grid(True, linestyle="--", alpha=0.30)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        max_y = max(y_values) if y_values else 1
        ax.set_ylim(0, max(max_y * 1.25, 3))

        for i, value in enumerate(y_values):
            ax.annotate(
                str(value),
                xy=(x_positions[i], value),
                xytext=(0, 8),
                textcoords="offset points",
                ha="center",
                fontsize=9
            )

        step = max(1, len(x_labels) // 8) if len(x_labels) >= 10 else 1
        visible_labels = []
        for idx, label in enumerate(x_labels):
            if idx % step == 0 or idx == len(x_labels) - 1:
                visible_labels.append(label[5:] if len(label) >= 10 else label)
            else:
                visible_labels.append("")
        ax.set_xticks(x_positions)
        ax.set_xticklabels(visible_labels, rotation=35, ha="right", fontsize=9)

        ax.tick_params(axis="y", labelsize=9)

        fig.tight_layout()
        fig.savefig(graph_path, dpi=160)
        return graph_path

    def is_shared_pc_name(value):
        s = str(value or "").strip()
        return bool(re.match(r"(?i)^asset-\d+$", s))

    def get_endpoint_user_by_machine_name(machine_name):
        target = normalize_name_key(machine_name)
        if not target:
            return "", ""

        for e in ENDPOINTS:
            if not isinstance(e, dict):
                continue

            hostname = str(e.get("hostname", "") or "").strip()
            if normalize_name_key(hostname) != target:
                continue

            person = e.get("associatedPerson", {})
            if not isinstance(person, dict):
                person = {}

            user_name = str(person.get("name", "") or "").strip()
            via_login = str(person.get("viaLogin", "") or "").strip()

            user_id = via_login.split("\\")[-1] if "\\" in via_login else via_login
            return user_name, user_id

        return "", ""


    def build_security_insight_metrics(self, endpoint_detections, emails, dlp_rows, detection_timeline=None, report_identity_resolver=None):
        rule_counter = Counter()
        host_counter = Counter()
        file_counter = Counter()

        det_host_day_counter = defaultdict(set)
        dlp_host_day_counter = defaultdict(set)

        for d in endpoint_detections:
            if not isinstance(d, dict):
                continue

            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                raw = {}

            dd = d.get("detectionDescription", {})
            rule = ""
            if isinstance(dd, dict):
                rule = str(dd.get("createdReasonId", "") or "").strip()
            if not rule:
                rule = str(d.get("detectionRule", "") or "").strip()

            hostname = str(raw.get("meta_hostname", "") or "").strip()
            file_name, _ = get_display_file_and_sha(raw)

            if rule:
                rule_counter[rule] += 1
            if hostname and hostname != "None":
                host_counter[hostname] += 1
            if file_name and file_name != "None":
                file_counter[file_name] += 1

            if hostname and hostname != "None":
                t = d.get("time")
                if t:
                    try:
                        dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                        kst = dt.astimezone(timezone(timedelta(hours=9)))
                        det_host_day_counter[hostname.lower()].add(kst.strftime("%Y-%m-%d"))
                    except Exception:
                        pass

        # ── Detection 부서별 통계 ──────────────────────────────────────
        det_dept_stats = defaultdict(lambda: {
            "total": 0,
            "rules": Counter(),
            "files": Counter(),
            "hosts": set(),
            "users": set(),
        })

        for d in endpoint_detections:
            if not isinstance(d, dict):
                continue

            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                raw = {}

            dd = d.get("detectionDescription", {})
            rule = ""
            if isinstance(dd, dict):
                rule = str(dd.get("createdReasonId", "") or "").strip()
            if not rule:
                rule = str(d.get("detectionRule", "") or "").strip()

            hostname = str(raw.get("meta_hostname", "") or "").strip()
            file_name, _ = get_display_file_and_sha(raw)

            identity = resolve_identity_by_hostname(hostname)
            dept_name = identity.get("dept_name", "미분류") or "미분류"

            stat = det_dept_stats[dept_name]
            stat["total"] += 1
            if rule:
                stat["rules"][rule] += 1
            if file_name and file_name != "None":
                stat["files"][file_name] += 1
            if hostname and hostname != "None":
                stat["hosts"].add(hostname)
            user_name = identity.get("user_name", "")
            if user_name and user_name != "None":
                stat["users"].add(user_name)

        det_dept_rows = []
        for dept_name, stat in det_dept_stats.items():
            det_dept_rows.append({
                "dept_name": dept_name,
                "total": stat["total"],
                "host_count": len(stat["hosts"]),
                "user_count": len(stat["users"]),
                "top_rules": stat["rules"].most_common(3),
                "top_files": stat["files"].most_common(3),
                "hosts_preview": sorted(list(stat["hosts"]))[:5],
            })

        det_dept_rank = sorted(det_dept_rows, key=lambda x: (-x["total"], x["dept_name"]))


        high_risk_email_count = 0
        email_date_set = set()

        for m in emails:
            if not isinstance(m, dict):
                continue

            reason = str(m.get("reason", "") or "").lower()
            if any(x in reason for x in ["malware", "virus", "phish", "spam", "suspicious", "impersonation"]):
                high_risk_email_count += 1

            received_at = m.get("receivedAt")
            if received_at:
                try:
                    dt = datetime.fromisoformat(str(received_at).replace("Z", "+00:00"))
                    kst = dt.astimezone(timezone(timedelta(hours=9)))
                    email_date_set.add(kst.strftime("%Y-%m-%d"))
                except Exception:
                    pass

        dlp_host_set = set()
        dlp_date_set = defaultdict(int)
        dlp_category_counter = Counter()

        dept_stats = defaultdict(lambda: {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "users": set(),
            "machines": set(),
            "sources": Counter(),
            "target_types": Counter(),
            "dest_details": Counter(),
            "dest_groups": defaultdict(lambda: {
                "count": 0,
                "sources": Counter(),
                "target_types": Counter(),
            }),
        })

        unclassified_user_counter = Counter()

        for row in dlp_rows:
            if not isinstance(row, dict):
                continue

            machine_name = str(row.get("machine_name", "") or "").strip()
            event_name = str(row.get("event_id", "") or row.get("content_policy", "") or "").strip()

            source_name = str(
                row.get("filename", "")
                or row.get("source", "")
                or row.get("item_name", "")
                or "None"
            ).strip()

            target_type = str(
                row.get("destination_type", "")
                or row.get("target_type", "")
                or row.get("targetType", "")
                or "None"
            ).strip()

            dest_detail = str(
                row.get("destinationDetails", "")
                or row.get("destination_detail", "")
                or row.get("destination", "")
                or row.get("item_details", "")
                or "None"
            ).strip()

            dest_detail = normalize_report_destination(dest_detail)
            dest_category = classify_dlp_destination("", target_type, dest_detail)
            if dest_category:
                dlp_category_counter[dest_category] += 1

            if machine_name:
                dlp_host_set.add(machine_name.lower())

            t = str(row.get("eventtimelocal", "") or "").strip()
            if len(t) >= 10:
                day_key = t[:10]
                dlp_date_set[day_key] += 1
                if machine_name:
                    dlp_host_day_counter[machine_name.lower()].add(day_key)

            if report_identity_resolver:
                identity_info = report_identity_resolver(machine_name)
                endpoint_user_name = str(identity_info.get("user_name", "") or "")
                endpoint_user_id = str(identity_info.get("user_id", "") or "")
                user_type = str(identity_info.get("user_type", "") or "")
                dept_name = str(identity_info.get("dept_name", "미분류") or "미분류")
                dept_code = str(identity_info.get("dept_code", "") or "")
                if identity_info.get("is_unclassified"):
                    display_name = str(identity_info.get("display_name", "") or "").strip()
                    if display_name:
                        unclassified_user_counter[display_name] += 1
            else:
                endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(machine_name)

                if user_type == "shared_pc":
                    dept_name = "공용PC"
                    dept_code = ""
                else:
                    dept_name, dept_code = get_org_info_by_user(endpoint_user_name, endpoint_user_id, machine_name)

                    if not dept_name or dept_name == "미분류":
                        manual_dept = get_report_exception_dept(endpoint_user_name)

                        if not manual_dept:
                            manual_dept = get_report_exception_dept(machine_name)
                        if manual_dept:
                            dept_name = manual_dept
                            dept_code = ""
                        else:
                            dept_name = "미분류"

                            display_name = str(endpoint_user_name or "").strip()
                            if not display_name:
                                display_name = f"[NO_USER] {machine_name}"

                            unclassified_user_counter[display_name] += 1

            stat = dept_stats[dept_name]
            stat["total"] += 1

            event_name_l = event_name.lower()
            is_blocked = any(x in event_name_l for x in ["block", "deny", "차단", "반려"])

            if is_blocked:
                stat["blocked"] += 1
            else:
                stat["allowed"] += 1

            if endpoint_user_name and endpoint_user_name != "공용PC":
                stat["users"].add(endpoint_user_name)
            if machine_name:
                stat["machines"].add(machine_name)
            if source_name and source_name != "None":
                stat["sources"][source_name] += 1
            if target_type and target_type != "None":
                stat["target_types"][target_type] += 1
            if dest_detail and dest_detail != "None":
                stat["dest_details"][dest_detail] += 1

                # 상세 리스트용 목적지 그룹은 허용건만 반영
                if not is_blocked:
                    group = stat["dest_groups"][dest_detail]
                    group["count"] += 1

                    if source_name and source_name != "None":
                        group["sources"][source_name] += 1

                    if target_type and target_type != "None":
                        group["target_types"][target_type] += 1

        if unclassified_user_counter:
            log.info(
                "[DLP UNCLASSIFIED USERS] %s",
                ", ".join([f"{name}({cnt})" for name, cnt in unclassified_user_counter.most_common()])
            )

        dlp_dept_rows = []
        for dept_name, stat in dept_stats.items():
            total = stat["total"]
            blocked = stat["blocked"]
            allowed = stat["allowed"]
            block_ratio = round((blocked / total) * 100, 1) if total else 0.0

            top_dest_group_rows = []

            for dest_name, group in sorted(
                stat["dest_groups"].items(),
                key=lambda x: (-x[1]["count"], x[0])
            )[:3]:
                top_sources = [
                    shorten_path_text(name, 46)
                    for name, _ in group["sources"].most_common(5)
                ]
                source_text = "\n".join(top_sources) if top_sources else "-"

                target_parts = [
                    f"{name} ({cnt})"
                    for name, cnt in group["target_types"].most_common(5)
                ]
                target_text = "\n".join(target_parts) if target_parts else "-"
                dest_category = classify_dlp_destination("", target_text, dest_name)
                target_text_with_category = f"{dest_category}\n{target_text}" if target_text != "-" else dest_category

                top_dest_group_rows.append({
                    "dest_detail": dest_name,
                    "count": group["count"],
                    "source_text": source_text,
                    "target_text": target_text_with_category,
                    "category": dest_category,
                })

            dlp_dept_rows.append({
                "dept_name": dept_name,
                "total": total,
                "blocked": blocked,
                "allowed": allowed,
                "block_ratio": block_ratio,
                "user_count": len(stat["users"]),
                "machine_count": len(stat["machines"]),
                "top_sources": stat["sources"].most_common(5),
                "top_target_types": stat["target_types"].most_common(5),
                "top_dest_details": stat["dest_details"].most_common(5),
                "top_dest_group_rows": top_dest_group_rows,
                "users_preview": list(sorted(stat["users"]))[:5],
                "machines_preview": list(sorted(stat["machines"]))[:5],
            })

        dlp_dept_rank = sorted(dlp_dept_rows, key=lambda x: (-x["total"], x["dept_name"]))
        dlp_dept_block_rank = sorted(dlp_dept_rows, key=lambda x: (-x["blocked"], x["dept_name"]))

        top_dlp_dept = dlp_dept_rank[0] if dlp_dept_rank else {}
        top_blocked_dlp_dept = dlp_dept_block_rank[0] if dlp_dept_block_rank else {}
        dlp_total_for_ratio = len(dlp_rows)
        dlp_blocked_count = sum(row.get("blocked", 0) for row in dlp_dept_rows)
        dlp_allowed_count = sum(row.get("allowed", 0) for row in dlp_dept_rows)
        dlp_blocked_ratio = round((dlp_blocked_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_allowed_ratio = round((dlp_allowed_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_top_dept_ratio = round((top_dlp_dept.get("total", 0) / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio and top_dlp_dept else 0.0
        dlp_sensitive_categories = {
            "AI/생성형AI",
            "클라우드/오브젝트 스토리지",
            "메일/대용량 첨부",
            "메신저/고객상담",
            "소셜/미디어 업로드",
            "문서/PDF/이미지 변환",
            "디자인/협업 SaaS",
        }
        dlp_sensitive_category_count = sum(
            cnt for category, cnt in dlp_category_counter.items()
            if category in dlp_sensitive_categories
        )
        dlp_sensitive_category_ratio = round((dlp_sensitive_category_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_top_sensitive_categories = [
            (category, cnt)
            for category, cnt in dlp_category_counter.most_common()
            if category in dlp_sensitive_categories
        ][:5]

        detection_host_set = set([h.lower() for h in host_counter.keys() if h])
        cross_hosts = sorted(list(detection_host_set.intersection(dlp_host_set)))
        cross_host_count = len(cross_hosts)
        detection_host_count = len(detection_host_set)
        dlp_host_count = len(dlp_host_set)

        cross_host_ratio = round((cross_host_count / detection_host_count) * 100, 1) if detection_host_count else 0.0

        cross_host_rank = []
        for host in cross_hosts:
            det_cnt = 0
            for origin_host, cnt in host_counter.items():
                if str(origin_host).lower() == host:
                    det_cnt = cnt
                    break

            dlp_cnt = 0
            for row in dlp_rows:
                if not isinstance(row, dict):
                    continue
                mname = str(row.get("machine_name", "") or "").strip().lower()
                if mname == host:
                    dlp_cnt += 1

            cross_host_rank.append((host.upper(), det_cnt + dlp_cnt))

        cross_host_rank = sorted(cross_host_rank, key=lambda x: x[1], reverse=True)

        same_day_det_dlp = {}
        if detection_timeline is None:
            detection_timeline = {}

        for d in detection_timeline.keys():
            if d in dlp_date_set:
                same_day_det_dlp[d] = {
                    "detection_count": detection_timeline.get(d, 0),
                    "dlp_count": dlp_date_set.get(d, 0),
                }

        overlap_day_count = len(same_day_det_dlp)
        detection_day_count = len(detection_timeline)
        overlap_day_ratio = round((overlap_day_count / detection_day_count) * 100, 1) if detection_day_count else 0.0

        triple_overlap_days = sorted(list(set(same_day_det_dlp.keys()).intersection(email_date_set)))
        triple_overlap_count = len(triple_overlap_days)

        repeated_det_hosts = sorted([host for host, days in det_host_day_counter.items() if len(days) >= 2])
        repeated_dlp_hosts = sorted([host for host, days in dlp_host_day_counter.items() if len(days) >= 2])
        repeated_cross_hosts = sorted(list(set(repeated_det_hosts).intersection(repeated_dlp_hosts)))

        top_rule, top_rule_count = rule_counter.most_common(1)[0] if rule_counter else ("", 0)
        top_host, top_host_count = host_counter.most_common(1)[0] if host_counter else ("", 0)
        top_file, top_file_count = file_counter.most_common(1)[0] if file_counter else ("", 0)

        return {
            "endpoint_detection_count": len(endpoint_detections),
            "email_count": len(emails),
            "dlp_count": len(dlp_rows),

            "unique_host_count": len(host_counter),
            "unique_file_count": len(file_counter),
            "unique_rule_count": len(rule_counter),

            "high_risk_email_count": high_risk_email_count,

            "top_rule": top_rule,
            "top_rule_count": top_rule_count,
            "top_host": top_host,
            "top_host_count": top_host_count,
            "top_file": top_file,
            "top_file_count": top_file_count,

            "top_rules": rule_counter.most_common(5),
            "top_hosts": host_counter.most_common(5),
            "top_files": file_counter.most_common(5),

            "repeat_rule_exists": top_rule_count >= 3,
            "repeat_host_exists": top_host_count >= 3,
            "repeat_file_exists": top_file_count >= 3,

            "cross_hosts": cross_hosts,
            "cross_host_count": cross_host_count,
            "cross_host_ratio": cross_host_ratio,
            "cross_host_rank": cross_host_rank[:5],
            "detection_host_count": detection_host_count,
            "dlp_host_count": dlp_host_count,

            "same_day_det_dlp": same_day_det_dlp,
            "overlap_day_count": overlap_day_count,
            "overlap_day_ratio": overlap_day_ratio,
            "overlap_days_preview": sorted(list(same_day_det_dlp.keys()))[:5],

            "triple_overlap_days": triple_overlap_days,
            "triple_overlap_count": triple_overlap_count,
            "triple_overlap_days_preview": triple_overlap_days[:5],

            "repeated_det_hosts": repeated_det_hosts,
            "repeated_dlp_hosts": repeated_dlp_hosts,
            "repeated_cross_hosts": repeated_cross_hosts,
            "repeated_cross_host_count": len(repeated_cross_hosts),
            "repeated_cross_hosts_preview": repeated_cross_hosts[:5],

            "dlp_dept_rows": dlp_dept_rows,
            "dlp_dept_rank": dlp_dept_rank[:5],
            "dlp_dept_block_rank": dlp_dept_block_rank[:5],
            "top_dlp_dept": top_dlp_dept,
            "top_blocked_dlp_dept": top_blocked_dlp_dept,
            "dlp_dept_count": len(dlp_dept_rows),
            "dlp_allowed_count": dlp_allowed_count,
            "dlp_blocked_count": dlp_blocked_count,
            "dlp_allowed_ratio": dlp_allowed_ratio,
            "dlp_blocked_ratio": dlp_blocked_ratio,
            "dlp_top_dept_ratio": dlp_top_dept_ratio,
            "dlp_category_counts": dlp_category_counter.most_common(),
            "dlp_sensitive_category_count": dlp_sensitive_category_count,
            "dlp_sensitive_category_ratio": dlp_sensitive_category_ratio,
            "dlp_top_sensitive_categories": dlp_top_sensitive_categories,

            "unclassified_user_names": [name for name, _ in unclassified_user_counter.most_common()],
            "unclassified_user_counts": unclassified_user_counter.most_common(),
            "unclassified_user_count": len(unclassified_user_counter),

            # Detection 부서별
            "det_dept_rank": det_dept_rank,
        }


    def build_security_insight_lines(self, metrics):
        lines = []

        endpoint_count = metrics.get("endpoint_detection_count", 0)
        unique_hosts = metrics.get("unique_host_count", 0)
        unique_files = metrics.get("unique_file_count", 0)

        top_host = metrics.get("top_host", "")
        top_host_count = metrics.get("top_host_count", 0)

        top_rule = metrics.get("top_rule", "")
        top_rule_count = metrics.get("top_rule_count", 0)

        top_file = metrics.get("top_file", "")
        top_file_count = metrics.get("top_file_count", 0)

        email_count = metrics.get("email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        overlap_day_count = metrics.get("overlap_day_count", 0)
        overlap_day_ratio = metrics.get("overlap_day_ratio", 0.0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)

        cross_host_rank = metrics.get("cross_host_rank", [])
        overlap_days_preview = metrics.get("overlap_days_preview", [])
        triple_overlap_days_preview = metrics.get("triple_overlap_days_preview", [])
        repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])

        if endpoint_count == 0 and email_count == 0 and dlp_count == 0:
            return ["분석 기간 동안 확인된 보안 이벤트가 없습니다."]

        if endpoint_count > 0 and top_host:
            ratio = round((top_host_count / endpoint_count) * 100, 1) if endpoint_count else 0
            lines.append(f"탐지는 '{top_host}' 호스트에 {top_host_count}건 집중 (전체의 {ratio}%).")

        if endpoint_count > 0 and top_rule:
            ratio = round((top_rule_count / endpoint_count) * 100, 1) if endpoint_count else 0
            lines.append(f"최다 룰 '{top_rule}' — {top_rule_count}건 (전체의 {ratio}%).")

        if endpoint_count > 0 and top_file:
            lines.append(f"최다 연관 파일 '{top_file}' — {top_file_count}건.")

        if unique_hosts > 0 or unique_files > 0:
            lines.append(f"탐지 발생 호스트 {unique_hosts}개, 연관 파일 {unique_files}종.")



        top_dlp_dept = metrics.get("top_dlp_dept", {})
        top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})

        if dlp_count > 0 and top_dlp_dept:
            dept_name = top_dlp_dept.get("dept_name", "미분류")
            total = top_dlp_dept.get("total", 0)
            block_ratio = top_dlp_dept.get("block_ratio", 0.0)

            top_sources = top_dlp_dept.get("top_sources", [])
            top_target_types = top_dlp_dept.get("top_target_types", [])
            top_dest_details = top_dlp_dept.get("top_dest_details", [])

            parts = [f"DLP 최다 발생 부서는 '{dept_name}'이며 총 {total}건, 차단율 {block_ratio}%입니다."]

            if top_sources:
                parts.append(f"주요 파일은 {top_sources[0][0]}")
            if top_target_types:
                parts.append(f"주요 대상유형은 {top_target_types[0][0]}")
            if top_dest_details:
                parts.append(f"주요 목적지는 {top_dest_details[0][0]}")

            lines.append(" / ".join(parts) + ".")

        if dlp_count > 0 and top_blocked_dlp_dept:
            dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
            blocked = top_blocked_dlp_dept.get("blocked", 0)

            if blocked > 0:
                lines.append(f"DLP 차단 건수는 '{dept_name}' 부서가 가장 높으며 총 {blocked}건입니다.")

        if cross_host_count > 0:
            if cross_host_rank:
                preview = ", ".join([name for name, _ in cross_host_rank[:5]])
                lines.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count}개, 탐지 호스트 대비 {cross_host_ratio}% 수준이며 "
                    f"주요 교차 호스트는 {preview}입니다."
                )
            else:
                lines.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count}개, 탐지 호스트 대비 {cross_host_ratio}% 수준입니다."
                )

        if overlap_day_count > 0:
            if overlap_days_preview:
                day_preview = ", ".join(overlap_days_preview)
                lines.append(
                    f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했으며, "
                    f"Detection 발생일 기준 중첩률은 {overlap_day_ratio}%입니다. "
                    f"주요 발생일: {day_preview}"
                )
            else:
                lines.append(
                    f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했으며, "
                    f"Detection 발생일 기준 중첩률은 {overlap_day_ratio}%입니다."
                )

        if triple_overlap_count > 0:
            if triple_overlap_days_preview:
                day_preview = ", ".join(triple_overlap_days_preview)
                lines.append(
                    f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날이 {triple_overlap_count}일 확인되었습니다. "
                    f"주요 날짜: {day_preview}"
                )
            else:
                lines.append(
                    f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날이 {triple_overlap_count}일 확인되었습니다."
                )

        if repeated_cross_host_count > 0:
            if repeated_cross_hosts_preview:
                host_preview = ", ".join(repeated_cross_hosts_preview)
                lines.append(
                    f"Detection과 DLP가 반복적으로 함께 나타난 호스트가 {repeated_cross_host_count}개이며, "
                    f"주요 호스트는 {host_preview}입니다."
                )
            else:
                lines.append(
                    f"Detection과 DLP가 반복적으로 함께 나타난 호스트가 {repeated_cross_host_count}개로, "
                    f"단발성보다 반복형 패턴 점검이 필요합니다."
                )

        if email_count > 0 and endpoint_count > 0:
            lines.append(
                f"Email {email_count}건과 Endpoint 탐지가 같은 기간 내 함께 존재하여, "
                f"유입 이벤트와 단말 행위 간 시간적 연계 여부 확인이 필요합니다."
            )

        if dlp_count > 0:
            lines.append(f"DLP {dlp_count}건 — 파일 반출 이벤트의 반복성 및 탐지 시점 중첩 여부 확인 필요.")

        top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})
        if top_blocked_dlp_dept:
            dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
            blocked = top_blocked_dlp_dept.get("blocked", 0)
            if blocked > 0:
                lines.append(
                    f"DLP 차단 건수는 '{dept_name}' 부서가 가장 높으며 총 {blocked}건입니다."
                )

        return lines


    def build_security_risk_assessment(self, metrics, selected_days=1):
        """Build a weighted, explainable 100-point report risk score.

        The score intentionally separates event volume from spread, DLP exposure,
        cross-signal correlation, and attribution quality so the PDF can explain
        not only "how many events" occurred but also why the selected period is
        considered risky.
        """
        factors = []
        score_breakdown = []
        selected_days = max(int(selected_days or 1), 1)

        endpoint_count = metrics.get("endpoint_detection_count", 0)
        email_count = metrics.get("email_count", 0)
        high_risk_email_count = metrics.get("high_risk_email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        unique_host_count = metrics.get("unique_host_count", 0)
        top_rule_count = metrics.get("top_rule_count", 0)
        top_host_count = metrics.get("top_host_count", 0)
        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)
        unclassified_user_count = metrics.get("unclassified_user_count", 0)

        dlp_allowed_ratio = metrics.get("dlp_allowed_ratio", 0.0)
        dlp_sensitive_category_count = metrics.get("dlp_sensitive_category_count", 0)
        dlp_sensitive_category_ratio = metrics.get("dlp_sensitive_category_ratio", 0.0)
        dlp_top_dept_ratio = metrics.get("dlp_top_dept_ratio", 0.0)
        dlp_top_sensitive_categories = metrics.get("dlp_top_sensitive_categories", []) or []

        avg_endpoint_per_day = round(endpoint_count / selected_days, 1)
        avg_email_per_day = round(email_count / selected_days, 1)
        avg_high_risk_email_per_day = round(high_risk_email_count / selected_days, 1)
        avg_dlp_per_day = round(dlp_count / selected_days, 1)
        top_host_ratio = round((top_host_count / endpoint_count) * 100, 1) if endpoint_count else 0.0
        high_risk_email_ratio = round((high_risk_email_count / email_count) * 100, 1) if email_count else 0.0

        def band(value, rules):
            for threshold, points in rules:
                if value >= threshold:
                    return points
            return 0

        def add_breakdown(label, score, max_score, detail, interpretation):
            if score <= 0:
                return
            score_breakdown.append({
                "label": label,
                "score": score,
                "max_score": max_score,
                "score_display": f"{score}/{max_score}",
                "detail": detail,
                "interpretation": interpretation,
            })
            factors.append(f"{label} {score}/{max_score} — {interpretation}")

        # 1) Endpoint 위협 활동: 단말 탐지의 양, 확산 범위, 반복 룰, 특정 호스트 집중도를 함께 본다. (25점)
        endpoint_score = 0
        endpoint_score += band(avg_endpoint_per_day, [(30, 10), (10, 6), (1, 3)])
        endpoint_score += band(unique_host_count, [(20, 7), (10, 5), (3, 3), (1, 1)])
        endpoint_score += band(top_rule_count, [(100, 5), (50, 4), (10, 2), (3, 1)])
        endpoint_score += band(top_host_ratio, [(50, 3), (30, 2), (15, 1)])
        endpoint_score = min(endpoint_score, 25)
        endpoint_interpretation = (
            "탐지량·호스트 확산·반복 룰이 함께 높아 단말 우선 분석이 필요합니다."
            if endpoint_score >= 18 else
            "반복 또는 확산 징후가 있어 상위 호스트/룰 중심 확인이 필요합니다."
            if endpoint_score >= 9 else
            "단말 탐지는 제한적이나 발생 내역은 추적 대상입니다."
        )
        add_breakdown(
            "Endpoint 위협 활동",
            endpoint_score,
            25,
            f"총 {endpoint_count:,}건 / {selected_days}일 = 일평균 {avg_endpoint_per_day:,}건, "
            f"탐지 호스트 {unique_host_count:,}개, 최다 룰 {top_rule_count:,}건, 최다 호스트 집중도 {top_host_ratio}%",
            endpoint_interpretation,
        )

        # 2) Email 유입 위험: 고위험 메일의 절대량과 메일 이벤트 내 비중을 함께 본다. (20점)
        email_score = 0
        email_score += band(avg_high_risk_email_per_day, [(30, 10), (10, 7), (3, 4), (1, 2)])
        email_score += band(avg_email_per_day, [(300, 4), (100, 3), (30, 2), (1, 1)])
        email_score += band(high_risk_email_ratio, [(50, 4), (20, 3), (10, 2), (1, 1)])
        if email_count > 0 and endpoint_count > 0:
            email_score += 2
        email_score = min(email_score, 20)
        email_interpretation = (
            "고위험 메일 유입량과 비중이 높아 유입 후 단말 행위 연계 점검이 필요합니다."
            if email_score >= 14 else
            "의심 메일이 지속 확인되어 발신자·URL·첨부파일 기준 샘플링이 필요합니다."
            if email_score >= 7 else
            "메일 유입 위험은 낮지만 Endpoint 이벤트와 같은 기간 존재 여부를 유지 관찰합니다."
        )
        add_breakdown(
            "Email 유입 위험",
            email_score,
            20,
            f"Email 총 {email_count:,}건 / 일평균 {avg_email_per_day:,}건, "
            f"고위험 {high_risk_email_count:,}건 / 일평균 {avg_high_risk_email_per_day:,}건, 고위험 비중 {high_risk_email_ratio}%",
            email_interpretation,
        )

        # 3) DLP 반출 노출: DLP 발생량, 허용 비중, 민감 목적지 분류, 부서 집중도를 함께 본다. (30점)
        dlp_score = 0
        dlp_score += band(avg_dlp_per_day, [(1000, 8), (500, 6), (100, 4), (1, 2)])
        dlp_score += band(dlp_allowed_ratio, [(95, 7), (80, 5), (50, 3), (1, 1)]) if dlp_count else 0
        dlp_score += band(dlp_sensitive_category_ratio, [(50, 8), (25, 6), (10, 4), (1, 2)])
        dlp_score += band(dlp_top_dept_ratio, [(50, 5), (30, 3), (15, 2)])
        dlp_score += band(unclassified_user_count, [(30, 2), (10, 1)])
        dlp_score = min(dlp_score, 30)
        sensitive_preview = ", ".join([f"{name} {cnt:,}건" for name, cnt in dlp_top_sensitive_categories[:3]]) or "민감 목적지 분류 없음"
        dlp_interpretation = (
            "허용 반출과 민감 목적지 사용이 함께 높아 파일 샘플링 및 정책 예외 검토가 필요합니다."
            if dlp_score >= 21 else
            "반출 이벤트가 지속 확인되어 상위 부서·목적지·파일명 기준 점검이 필요합니다."
            if dlp_score >= 10 else
            "DLP 노출은 제한적이나 허용 이벤트는 목적지 기준으로 추적합니다."
        )
        add_breakdown(
            "DLP 반출 노출",
            dlp_score,
            30,
            f"총 {dlp_count:,}건 / 일평균 {avg_dlp_per_day:,}건, 허용 비중 {dlp_allowed_ratio}%, "
            f"민감 목적지 {dlp_sensitive_category_count:,}건({dlp_sensitive_category_ratio}%), 상위 부서 집중도 {dlp_top_dept_ratio}% / {sensitive_preview}",
            dlp_interpretation,
        )

        # 4) 상관/연계 위험: Detection과 DLP, Email이 같은 호스트/날짜에서 겹치는지를 본다. (20점)
        correlation_score = 0
        correlation_score += band(cross_host_count, [(20, 8), (10, 6), (5, 4), (1, 2)])
        correlation_score += band(cross_host_ratio, [(50, 5), (30, 3), (10, 1)])
        correlation_score += band(triple_overlap_count, [(5, 4), (2, 3), (1, 2)])
        correlation_score += band(repeated_cross_host_count, [(10, 3), (1, 2)])
        correlation_score = min(correlation_score, 20)
        correlation_interpretation = (
            "탐지·메일·DLP가 같은 기간/호스트에서 겹쳐 유입부터 반출까지의 연계 가능성을 우선 확인해야 합니다."
            if correlation_score >= 14 else
            "교차 호스트 또는 동시 발생일이 확인되어 시계열 상관분석이 필요합니다."
            if correlation_score >= 6 else
            "상관 징후는 제한적이나 교차 호스트는 추적 목록에 유지합니다."
        )
        add_breakdown(
            "상관/연계 위험",
            correlation_score,
            20,
            f"Detection+DLP 교차 호스트 {cross_host_count:,}개({cross_host_ratio}%), "
            f"3종 동시 발생일 {triple_overlap_count:,}일, 반복 교차 호스트 {repeated_cross_host_count:,}개",
            correlation_interpretation,
        )

        # 5) 식별/운영 품질: 미분류 사용자가 많을수록 실제 조치 지연 위험이 커진다. (5점)
        quality_score = min(band(unclassified_user_count, [(30, 5), (10, 3), (1, 1)]), 5)
        quality_interpretation = (
            "미분류 사용자가 많아 부서 책임자 지정과 후속 조치가 지연될 수 있습니다."
            if quality_score >= 3 else
            "일부 미분류 사용자가 있어 조직 매핑 보완이 필요합니다."
            if quality_score > 0 else
            "사용자/부서 식별 품질은 위험도에 큰 영향을 주지 않습니다."
        )
        add_breakdown(
            "식별/운영 품질",
            quality_score,
            5,
            f"DLP 미분류 사용자 {unclassified_user_count:,}명",
            quality_interpretation,
        )

        score = min(sum(item.get("score", 0) for item in score_breakdown), 100)
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        if not factors:
            factors.append("전반적으로 특이 위험 요소는 제한적입니다.")

        return {
            "level": level,
            "score": score,
            "max_score": 100,
            "factors": factors,
            "score_breakdown": score_breakdown,
            "selected_days": selected_days,
            "avg_endpoint_per_day": avg_endpoint_per_day,
            "avg_high_risk_email_per_day": avg_high_risk_email_per_day,
            "avg_dlp_per_day": avg_dlp_per_day,
        }


    def build_security_conclusion_lines(self, metrics, risk):
        lines = []

        level = str(risk.get("level", "LOW"))

        if level == "CRITICAL":
            lines.append("복수 보안 신호가 강하게 중첩되어 즉시 대응이 필요한 치명 위험 수준입니다.")
            lines.append("교차 호스트, DLP 허용 반출, 고위험 메일 유입을 우선순위로 당일 점검해야 합니다.")
        elif level == "HIGH":
            lines.append("다수의 보안 이벤트가 동시다발적으로 확인되어 우선 대응이 필요한 수준입니다.")
            lines.append("반복 탐지 및 고위험 이벤트를 중심으로 즉시 상세 분석이 필요합니다.")
        elif level == "MEDIUM":
            lines.append("일부 반복 이벤트 및 다수 탐지가 확인되어 주의가 필요한 수준입니다.")
            lines.append("현재 즉각적인 대규모 침해 정황은 제한적일 수 있으나 지속 모니터링이 필요합니다.")
        else:
            lines.append("전체적으로 위험도는 낮은 수준으로 평가됩니다.")
            lines.append("현재까지 즉각적인 침해 대응이 필요한 정황은 제한적으로 판단됩니다.")

        if metrics.get("repeat_host_exists"):
            lines.append("특정 사용자 또는 특정 호스트 중심의 반복 이벤트 여부를 함께 검토하는 것이 적절합니다.")

        if metrics.get("repeat_file_exists"):
            lines.append("반복적으로 탐지되는 파일은 정상 프로그램 여부를 기준으로 예외처리 가능성을 검토할 수 있습니다.")

        if metrics.get("high_risk_email_count", 0) > 0:
            lines.append("이메일 위협 이벤트는 수신자, 발신지, 포함 URL 또는 첨부파일 중심으로 추가 확인이 필요합니다.")

        return lines


    def build_security_action_items(self, metrics, risk):
        actions = []

        if metrics.get("repeat_rule_exists"):
            actions.append("반복 발생 탐지 룰에 대해 정상 행위 기반 여부를 검토합니다.")

        if metrics.get("repeat_host_exists"):
            actions.append("탐지 집중 호스트에 대해 사용자 행위 및 실행 프로그램을 재확인합니다.")

        if metrics.get("repeat_file_exists"):
            actions.append("반복 탐지 파일에 대해 정상 프로그램 여부 및 예외처리 필요성을 검토합니다.")

        if metrics.get("high_risk_email_count", 0) > 0:
            actions.append("고위험 이메일 이벤트 — 발신자, 수신자, URL, 첨부파일 기준 추가 분석을 진행합니다.")

        cross_host_rank = metrics.get("cross_host_rank", [])
        cross_host_count = metrics.get("cross_host_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)

        if cross_host_count > 0:
            if cross_host_rank:
                preview = ", ".join([name for name, _ in cross_host_rank[:3]])
                actions.append(f"Detection + DLP 교차 호스트({preview})를 우선 점검합니다.")
            else:
                actions.append("Detection + DLP 교차 호스트를 우선 점검합니다.")

        repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])
        triple_overlap_days_preview = metrics.get("triple_overlap_days_preview", [])

        if repeated_cross_host_count > 0:
            if repeated_cross_hosts_preview:
                preview = ", ".join(repeated_cross_hosts_preview)
                actions.append(f"반복 교차 호스트({preview})의 업무성 행위 여부를 우선 확인합니다.")
            else:
                actions.append("반복적으로 Detection과 DLP가 함께 발생한 호스트군의 업무성 행위 여부를 우선 확인합니다.")

        if triple_overlap_count > 0:
            if triple_overlap_days_preview:
                preview = ", ".join(triple_overlap_days_preview)
                actions.append(f"3종 이벤트 동시 발생일({preview})을 기준으로 전후 행위를 교차 확인합니다.")
            else:
                actions.append("Detection·Email·DLP 3종 이벤트가 겹친 날짜를 기준으로 전후 행위를 교차 확인합니다.")

        if metrics.get("dlp_count", 0) > 0:
            actions.append("파일 반출 이벤트 — 업무 목적 여부 및 반복 업로드 패턴을 확인합니다.")

            top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})
            if top_blocked_dlp_dept:
                dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
                blocked = top_blocked_dlp_dept.get("blocked", 0)
                if blocked > 0:
                    actions.append(
                        f"DLP 차단 상위 부서('{dept_name}')에 대해 주요 파일, 업로드 대상, 사용자 반복 여부를 우선 점검합니다."
                    )
        if str(risk.get("level", "LOW")) in {"CRITICAL", "HIGH"}:
            actions.append("고위험 구간 — 반복 이벤트 우선 상세 분석 및 선제 대응을 수행합니다.")

        return actions


    def build_security_manager_summary(self, metrics, risk):
        endpoint_count = metrics.get("endpoint_detection_count", 0)
        email_count = metrics.get("email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        top_host = metrics.get("top_host", "")
        top_host_count = metrics.get("top_host_count", 0)

        top_rule = metrics.get("top_rule", "")
        top_rule_count = metrics.get("top_rule_count", 0)

        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        overlap_day_count = metrics.get("overlap_day_count", 0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)

        level = str(risk.get("level", "LOW"))

        parts = [
            f"선택 기간 동안 Detection {endpoint_count}건, Email {email_count}건, DLP {dlp_count}건이 확인되었습니다."
        ]

        if top_host:
            parts.append(f"상위 호스트는 {top_host} ({top_host_count}건).")

        if top_rule:
            parts.append(f"주요 탐지 룰은 {top_rule} ({top_rule_count}건).")
        top_dlp_dept = metrics.get("top_dlp_dept", {})
        if top_dlp_dept:
            dept_name = top_dlp_dept.get("dept_name", "미분류")
            total = top_dlp_dept.get("total", 0)
            parts.append(f"DLP는 {dept_name} 부서에서 가장 많이 발생했으며 {total}건입니다.")
        if cross_host_count > 0:
            parts.append(
                f"Detection과 DLP가 함께 확인된 교차 호스트는 {cross_host_count}개이며, "
                f"탐지 호스트 대비 {cross_host_ratio}% 수준입니다."
            )

        if overlap_day_count > 0:
            parts.append(f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했습니다.")

        if triple_overlap_count > 0:
            parts.append(f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날은 {triple_overlap_count}일입니다.")

        if repeated_cross_host_count > 0:
            parts.append(f"반복적으로 Detection과 DLP가 함께 나타난 호스트는 {repeated_cross_host_count}개입니다.")

        if email_count > 0 and endpoint_count > 0:
            parts.append("메일 이벤트와 Endpoint 탐지가 같은 기간 내 함께 존재하여 유입 후 행위 연계 가능성을 점검 대상으로 포함합니다.")

        level_text = {"CRITICAL": "치명 위험", "HIGH": "고위험", "MEDIUM": "중위험", "LOW": "저위험"}.get(level, "저위험")
        parts.append(f"종합 판단: {level_text} 수준.")

        return " ".join(parts)


    def build_security_narrative_lines(self, metrics, risk):
        lines = []

        endpoint_count = metrics.get("endpoint_detection_count", 0)
        email_count = metrics.get("email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        top_host = metrics.get("top_host", "")
        top_host_count = metrics.get("top_host_count", 0)

        top_rule = metrics.get("top_rule", "")
        top_rule_count = metrics.get("top_rule_count", 0)

        top_file = metrics.get("top_file", "")
        top_file_count = metrics.get("top_file_count", 0)

        if endpoint_count > 0 and top_host:
            lines.append(
                f"탐지는 '{top_host}' 호스트에 {top_host_count}건 집중되어 특정 사용자 또는 특정 장비 중심 패턴으로 볼 수 있습니다."
            )

        if endpoint_count > 0 and top_rule:
            lines.append(
                f"주요 탐지 룰은 '{top_rule}'이며 총 {top_rule_count}건 발생하여 동일 행위 반복 가능성이 있습니다."
            )

        if endpoint_count > 0 and top_file:
            lines.append(
                f"주요 연관 파일은 '{top_file}'이며 총 {top_file_count}건 확인되었습니다."
            )

        if metrics.get("repeat_file_exists") and top_file:
            lines.append(
                f"'{top_file}' 파일의 반복 연관 여부를 볼 때 정상 프로그램 또는 업무용 설치 파일 기반 행위인지 우선 점검하는 것이 적절합니다."
            )

        if email_count > 0:
            lines.append(
                f"Detection과 별도로 Email 이벤트 {email_count}건이 함께 존재하여 메일 유입과 사용자 행위 간 연결 가능성도 존재합니다."
            )

        if dlp_count > 0:
            lines.append(
                f"DLP 이벤트 {dlp_count}건이 함께 확인되어 파일 업로드/반출 행위와 시점상 겹치는 구간이 있는지 추가 확인이 필요합니다."
            )

        level = str(risk.get("level", "LOW"))
        if level == "CRITICAL":
            lines.append("전체적으로는 교차 신호와 반출 노출이 높은 치명 위험 구간으로 즉시 대응 대상입니다.")
        elif level == "HIGH":
            lines.append("전체적으로는 이벤트 집중도와 반복성이 높아 우선 분석 대상 구간으로 판단됩니다.")
        elif level == "MEDIUM":
            lines.append("전체적으로는 반복 이벤트 중심의 모니터링이 필요한 수준으로 판단됩니다.")
        else:
            lines.append("전체적으로는 운영상 관리 가능한 범위이나 지속 관찰은 필요합니다.")

        if not lines:
            lines.append("분석 가능한 이벤트가 충분하지 않아 정성적 판단은 제한적입니다.")

        return lines


    def build_report_html(
            self,
            start,
            end,
            detection_count,
            email_count,
            rule_counter,
            host_counter,
            file_counter,
            timeline):

        top_rules = rule_counter.most_common(5)
        top_hosts = host_counter.most_common(5)
        top_files = file_counter.most_common(5)

        timeline_rows = ""

        for d in sorted(timeline):
            timeline_rows += f"<tr><td>{d}</td><td>{timeline[d]}</td></tr>"

        html = f"""
        <html>
        <head>
        <style>

        body {{
            font-family: Malgun Gothic;
            margin:40px;
        }}

        h1 {{
            text-align:center;
        }}

        table {{
            border-collapse:collapse;
            width:100%;
            margin-bottom:30px;
        }}

        th, td {{
            border:1px solid #444;
            padding:8px;
            text-align:center;
        }}

        th {{
            background:#1f6fa9;
            color:white;
        }}

        </style>
        </head>

        <body>

        <h1>Security Monitoring Report</h1>

        <table>
        <tr>
            <th>Monitoring Period</th>
            <td>{start} ~ {end}</td>
        </tr>
        <tr>
            <th>Total Detections</th>
            <td>{detection_count}</td>
        </tr>
        <tr>
            <th>Email Threats</th>
            <td>{email_count}</td>
        </tr>
        </table>

        <h2>Top Detection Rules</h2>

        <table>
        <tr>
        <th>Rule</th>
        <th>Count</th>
        </tr>

        {''.join(f"<tr><td>{r}</td><td>{c}</td></tr>" for r,c in top_rules)}

        </table>


        <h2>Top Infected Hosts</h2>

        <table>
        <tr>
        <th>Hostname</th>
        <th>Count</th>
        </tr>

        {''.join(f"<tr><td>{h}</td><td>{c}</td></tr>" for h,c in top_hosts)}

        </table>


        <h2>Top Malicious Files</h2>

        <table>
        <tr>
        <th>File</th>
        <th>Count</th>
        </tr>

        {''.join(f"<tr><td>{f}</td><td>{c}</td></tr>" for f,c in top_files)}

        </table>


        <h2>Detection Timeline</h2>

        <table>
        <tr>
        <th>Date</th>
        <th>Detection Count</th>
        </tr>

        {timeline_rows}

        </table>


        </body>
        </html>
        """

        return html

    def _safe_percent(self, part, whole):
        try:
            part = float(part)
            whole = float(whole)
            if whole <= 0:
                return 0.0
            return round((part / whole) * 100, 1)
        except Exception:
            return 0.0


    def _calc_daily_counts_from_detection_rows(self, rows):
        daily = defaultdict(int)

        for d in rows or []:
            if not isinstance(d, dict):
                continue

            t = d.get("time")
            if not t:
                continue

            try:
                dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                daily[kst.strftime("%Y-%m-%d")] += 1
            except Exception:
                continue

        return dict(daily)


    def _calc_daily_counts_from_email_rows(self, rows):
        daily = defaultdict(int)

        for m in rows or []:
            if not isinstance(m, dict):
                continue

            t = m.get("receivedAt")
            if not t:
                continue

            try:
                dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9)))
                daily[kst.strftime("%Y-%m-%d")] += 1
            except Exception:
                continue

        return dict(daily)


    def _calc_daily_counts_from_dlp_rows(self, rows):
        daily = defaultdict(int)

        for r in rows or []:
            if not isinstance(r, dict):
                continue

            t = str(r.get("eventtimelocal", "")).strip()
            if len(t) >= 10:
                daily[t[:10]] += 1

        return dict(daily)

    def _filter_detection_rows_by_datetime(self, rows, start_dt, end_dt):
        filtered = []

        for d in rows or []:
            if not isinstance(d, dict):
                continue

            t = d.get("time")
            if not t:
                continue

            try:
                dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
            except Exception:
                continue

            if start_dt <= kst <= end_dt:
                filtered.append(d)

        return filtered


    def _filter_email_rows_by_datetime(self, rows, start_dt, end_dt):
        filtered = []

        for m in rows or []:
            if not isinstance(m, dict):
                continue

            t = m.get("receivedAt")
            if not t:
                continue

            try:
                dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                kst = dt.astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
            except Exception:
                continue

            if start_dt <= kst <= end_dt:
                filtered.append(m)

        return filtered


    def _filter_dlp_rows_by_datetime(self, rows, start_dt, end_dt):
        filtered = []

        for r in rows or []:
            if not isinstance(r, dict):
                continue

            dt = dlp_time_to_dt(r.get("eventtimelocal"))
            if not dt:
                continue

            if start_dt <= dt <= end_dt:
                filtered.append(r)

        return filtered

    def _find_spike_days(self, timeline, min_count=3, ratio_threshold=2.0):
        results = []

        if not timeline:
            return results

        days = sorted(timeline.keys())

        for i, day in enumerate(days):
            current = timeline.get(day, 0)

            if current < min_count:
                continue

            prev_values = []
            for j in range(max(0, i - 3), i):
                prev_values.append(timeline.get(days[j], 0))

            if not prev_values:
                continue

            avg_prev = sum(prev_values) / len(prev_values)

            if avg_prev <= 0:
                if current >= min_count:
                    results.append({
                        "date": day,
                        "count": current,
                        "baseline": round(avg_prev, 1),
                        "ratio": None,
                        "reason": "baseline_zero"
                    })
                continue

            ratio = current / avg_prev

            if ratio >= ratio_threshold:
                results.append({
                    "date": day,
                    "count": current,
                    "baseline": round(avg_prev, 1),
                    "ratio": round(ratio, 1),
                    "reason": "spike"
                })

        return results


    def _find_multi_host_file_spread(self, detections):
        spread_map = defaultdict(set)
        count_map = defaultdict(int)

        for d in detections or []:
            if not isinstance(d, dict):
                continue

            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                continue

            hostname = str(raw.get("meta_hostname", "")).strip()
            file_name, _ = get_display_file_and_sha(raw)

            if not file_name or file_name == "None":
                continue

            count_map[file_name] += 1

            if hostname:
                spread_map[file_name].add(hostname)

        results = []

        for file_name, hosts in spread_map.items():
            if len(hosts) >= 2:
                results.append({
                    "file_name": file_name,
                    "host_count": len(hosts),
                    "event_count": count_map[file_name],
                    "hosts": sorted(hosts),
                })

        results.sort(key=lambda x: (x["host_count"], x["event_count"]), reverse=True)
        return results


    def _calc_day_overlap_ratio(self, left_map, right_map):
        left_days = {k for k, v in (left_map or {}).items() if v > 0}
        right_days = {k for k, v in (right_map or {}).items() if v > 0}

        if not left_days or not right_days:
            return {
                "overlap_days": [],
                "overlap_count": 0,
                "left_days": len(left_days),
                "right_days": len(right_days),
                "overlap_ratio_by_left": 0.0,
                "overlap_ratio_by_right": 0.0,
            }

        overlap = sorted(left_days & right_days)

        return {
            "overlap_days": overlap,
            "overlap_count": len(overlap),
            "left_days": len(left_days),
            "right_days": len(right_days),
            "overlap_ratio_by_left": self._safe_percent(len(overlap), len(left_days)),
            "overlap_ratio_by_right": self._safe_percent(len(overlap), len(right_days)),
        }



    def update_auto_status(self, kind, success=True):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        short_now = datetime.now().strftime("%m-%d %H:%M")

        targets = {
            "Detection": (self.lbl_det_status, self.lbl_det_result),
            "Email": (self.lbl_mail_status, self.lbl_mail_result),
            "DLP": (self.lbl_dlp_status, self.lbl_dlp_result),
            "MailScreen": (self.lbl_mailscreen_status, self.lbl_mailscreen_result),
        }

        if kind in targets:
            last_label, result_label = targets[kind]
            last_label.setToolTip(f"Last Run: {now}")
            last_label.setText(short_now)

            if success:
                result_label.setText("SUCCESS")
                result_label.setStyleSheet(f"color:{UI_THEME['status_success_text']}; font-size:10px; font-weight:800;")
            else:
                result_label.setText("FAILED")
                result_label.setStyleSheet(f"color:{UI_THEME['status_fail_text']}; font-size:10px; font-weight:800;")
            return

        if kind == "Detection":
            self.lbl_det_status.setText(f"Last Run: {now}")

            if success:
                self.lbl_det_result.setText("Status: SUCCESS")
                self.lbl_det_result.setStyleSheet(f"color:{UI_THEME['status_success_text']}; font-weight:600;")
            else:
                self.lbl_det_result.setText("Status: FAILED")
                self.lbl_det_result.setStyleSheet(f"color:{UI_THEME['status_fail_text']}; font-weight:600;")

        elif kind == "Email":
            self.lbl_mail_status.setText(f"Last Run: {now}")

            if success:
                self.lbl_mail_result.setText("Status: SUCCESS")
                self.lbl_mail_result.setStyleSheet(f"color:{UI_THEME['status_success_text']}; font-weight:600;")
            else:
                self.lbl_mail_result.setText("Status: FAILED")
                self.lbl_mail_result.setStyleSheet(f"color:{UI_THEME['status_fail_text']}; font-weight:600;")

    def make_card(self, title, legacy_title=False):
        frame = QFrame()
        frame.setObjectName("dashboardCard")
        frame.setStyleSheet(self.card_style("dashboardCard", accent=False))
        self.apply_soft_shadow(frame, blur=30, y_offset=12, alpha=90)

        layout = QVBoxLayout(frame)
        if legacy_title:
            layout.setContentsMargins(15, 15, 15, 15)
            layout.setSpacing(10)
            self.add_legacy_card_title(layout, title)
        else:
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)
            self.add_card_title(layout, title)

        return frame, layout

    def sensitive_export_sheet_name(self, category, used_names):
        base = re.sub(r"[\[\]\:\*\?\/\\]", "_", str(category or "기타")).strip()
        base = re.sub(r"\s+", " ", base).replace(" / ", "_").replace("/", "_")
        base = base[:31].strip(" _") or "기타"
        name = base
        suffix = 2
        while name in used_names:
            suffix_text = f"_{suffix}"
            name = f"{base[:31 - len(suffix_text)]}{suffix_text}"
            suffix += 1
        used_names.add(name)
        return name

    def load_sensitive_export_records(self, table_name, version_key, expected_version, start_dt, end_dt, sources):
        start_text = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_text = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        source_values = list(sources or [])
        if not source_values:
            return {}
        placeholders = ",".join("?" for _ in source_values)
        with app_cache_connect() as conn:
            version_row = conn.execute("SELECT value FROM app_cache_meta WHERE key = ?", (version_key,)).fetchone()
            if not version_row or version_row[0] != expected_version:
                return None
            rows = conn.execute(
                f"""
                SELECT category, record_json
                FROM {table_name}
                WHERE source IN ({placeholders})
                  AND event_time >= ?
                  AND event_time <= ?
                ORDER BY category ASC, event_time DESC
                """,
                source_values + [start_text, end_text],
            ).fetchall()
        grouped = defaultdict(list)
        for category, raw_json in rows:
            try:
                record = json.loads(raw_json)
                if isinstance(record, dict):
                    grouped[str(category or record.get("category") or "기타")].append(record)
            except Exception as e:
                log.warning("Sensitive export record parse failed table=%s: %s", table_name, e)
        return dict(grouped)

    def write_category_excel(self, path, grouped_rows, row_builder):
        used_sheet_names = set()
        with pd.ExcelWriter(path) as writer:
            for category in sorted(grouped_rows.keys()):
                records = grouped_rows.get(category) or []
                if not records:
                    continue
                rows = [row_builder(record) for record in records]
                sheet_name = self.sensitive_export_sheet_name(category, used_sheet_names)
                pd.DataFrame(rows).to_excel(writer, sheet_name=sheet_name, index=False)

    def export_sensitive_files_excel(self):
        os.makedirs(EXPORT_DIR, exist_ok=True)
        start_dt = combine_date_time(self.sensitive_files_export_start_date, self.sensitive_files_export_start_time)
        end_dt = combine_date_time(self.sensitive_files_export_end_date, self.sensitive_files_export_end_time)
        grouped = self.load_sensitive_export_records(
            "sensitive_files_index",
            "sensitive_files_index_version",
            SENSITIVE_FILES_INDEX_VERSION,
            start_dt,
            end_dt,
            ["DLP", "Outbound Mail"],
        )
        if grouped is None:
            QMessageBox.information(self, "Sensitive Files Export", "Sensitive Files 인덱스가 없습니다. Data Index를 먼저 실행하세요.")
            return
        if not grouped:
            QMessageBox.information(self, "Sensitive Files Export", "조건에 맞는 Sensitive Files 데이터가 없습니다.")
            return

        start = start_dt.strftime("%Y-%m-%d")
        end = end_dt.strftime("%Y-%m-%d")
        path = get_unique_path(os.path.join(EXPORT_DIR, f"sensitive_files_{start}_{end}.xlsx"))

        def build_row(record):
            return {
                "시간": record.get("event_time", ""),
                "분류": record.get("category", ""),
                "탐지 키워드": ", ".join(record.get("keywords", []) or []),
                "파일명": record.get("display_filename", ""),
                "사용자": record.get("user", ""),
                "User ID": record.get("user_id", ""),
                "부서": record.get("dept", ""),
                "출처": record.get("source", ""),
                "이벤트": record.get("event", ""),
                "경로/원본": record.get("filename") or record.get("mail_attach_raw", ""),
                "대상": record.get("destination", ""),
                "대상 유형": record.get("destination_type", ""),
                "목적지 세부정보": record.get("destination_detail", ""),
                "메일 제목": record.get("mail_subject", ""),
                "발신자": record.get("mail_sender", ""),
                "수신자": record.get("mail_receiver", ""),
                "파일 해시": record.get("filehash", ""),
                "RawData": json.dumps(record.get("row", {}), ensure_ascii=False, default=str),
            }

        self.write_category_excel(path, grouped, build_row)
        QMessageBox.information(self, "Sensitive Files Export", f"Sensitive Files Excel 저장 완료\n{path}")

    def export_sensitive_sites_excel(self):
        os.makedirs(EXPORT_DIR, exist_ok=True)
        start_dt = combine_date_time(self.sensitive_sites_export_start_date, self.sensitive_sites_export_start_time)
        end_dt = combine_date_time(self.sensitive_sites_export_end_date, self.sensitive_sites_export_end_time)
        grouped = self.load_sensitive_export_records(
            "sensitive_sites_index",
            "sensitive_sites_index_version",
            SENSITIVE_SITES_INDEX_VERSION,
            start_dt,
            end_dt,
            ["DLP"],
        )
        if grouped is None:
            QMessageBox.information(self, "Sensitive Sites Export", "Sensitive Sites 인덱스가 없습니다. Data Index를 먼저 실행하세요.")
            return
        if not grouped:
            QMessageBox.information(self, "Sensitive Sites Export", "조건에 맞는 Sensitive Sites 데이터가 없습니다.")
            return

        start = start_dt.strftime("%Y-%m-%d")
        end = end_dt.strftime("%Y-%m-%d")
        path = get_unique_path(os.path.join(EXPORT_DIR, f"sensitive_sites_{start}_{end}.xlsx"))

        def build_row(record):
            return {
                "시간": record.get("event_time", ""),
                "분류": record.get("category", ""),
                "탐지 키워드": ", ".join(record.get("keywords", []) or []),
                "사이트": record.get("site", ""),
                "URL": record.get("url", ""),
                "사용자": record.get("user", ""),
                "User ID": record.get("user_id", ""),
                "부서": record.get("dept", ""),
                "출처": record.get("source", ""),
                "이벤트": record.get("event", ""),
                "대상": record.get("destination", ""),
                "목적지 세부정보": record.get("destination_detail", ""),
                "파일명": record.get("filename", ""),
                "파일 해시": record.get("filehash", ""),
                "RawData": json.dumps(record.get("row", {}), ensure_ascii=False, default=str),
            }

        self.write_category_excel(path, grouped, build_row)
        QMessageBox.information(self, "Sensitive Sites Export", f"Sensitive Sites Excel 저장 완료\n{path}")

    def export_detection_excel(self):
        start_dt = combine_date_time(self.det_export_start_date, self.det_export_start_time)
        end_dt = combine_date_time(self.det_export_end_date, self.det_export_end_time)

        start = start_dt.strftime("%Y-%m-%d")
        end = end_dt.strftime("%Y-%m-%d")

        detections = load_endpoint_detections_by_range(start, end)

        if not detections:
            QMessageBox.information(self, "Info", "No Detection - XDR Data")
            return

        path = os.path.join(EXPORT_DIR, f"Detection_XDR_{start}_{end}.xlsx")
        path = get_unique_path(path)

        rows = []

        for d in detections:
            if not isinstance(d, dict):
                continue

            event_dt = iso_to_kst_dt(d.get("time"))
            if not event_dt:
                continue
            if event_dt < start_dt or event_dt > end_dt:
                continue

            sensor = d.get("sensor", {})
            if not isinstance(sensor, dict) or sensor.get("type") != "endpoint":
                continue

            raw = d.get("rawData", {}) if isinstance(d.get("rawData"), dict) else {}

            hostname = str(raw.get("meta_hostname", "") or "").strip()
            private_ip = raw.get("meta_ip_address", "")
            public_ip = raw.get("meta_public_ip", "")

            identity = resolve_identity_by_hostname(hostname)

            file_name, sha = get_display_file_and_sha(raw)
            if file_name == "None":
                file_name = ""
            if sha == "None":
                sha = ""

            rule = ""
            dd = d.get("detectionDescription", {})
            if isinstance(dd, dict):
                rule = dd.get("createdReasonId", "") or ""
            if not rule:
                rule = d.get("detectionRule", "") or ""

            lineage = ""
            assoc = raw.get("associated_lineages", [])
            if isinstance(assoc, list):
                for l in assoc:
                    if not isinstance(l, dict):
                        continue
                    names = [
                        x.get("name")
                        for x in (l.get("lineage", []) or [])
                        if isinstance(x, dict) and x.get("name")
                    ]
                    if names:
                        lineage = " -> ".join(reversed(names))
                        break

            rows.append({
                "Time": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "Hostname": hostname,
                "User ID": identity["user_id"],
                "User": identity["user_name"],
                "Dept": identity["dept_name"],
                "Private IP": private_ip,
                "Public IP": public_ip,
                "File": file_name,
                "SHA256": sha,
                "Rule": rule,
                "Lineage": lineage,
                "RawData": json.dumps(d, ensure_ascii=False)
            })

        if not rows:
            QMessageBox.information(self, "Info", "No Detection - XDR Data")
            return

        df = pd.DataFrame(rows)
        df.to_excel(path, index=False)
        QMessageBox.information(self, "Export", f"Detection - XDR Excel saved\n{path}")

    def export_detection_xdr_excel(self):
        start_dt = combine_date_time(self.xdr_export_start_date, self.xdr_export_start_time)
        end_dt = combine_date_time(self.xdr_export_end_date, self.xdr_export_end_time)

        start = start_dt.strftime("%Y-%m-%d")
        end = end_dt.strftime("%Y-%m-%d")

        detections = load_xdr_email_detections_by_range(start, end)

        if not detections:
            QMessageBox.information(self, "Info", "No Email - XDR Data")
            return

        rows = []

        for d in detections:
            if not isinstance(d, dict):
                continue

            event_dt = iso_to_kst_dt(d.get("time"))
            if not event_dt:
                continue
            if event_dt < start_dt or event_dt > end_dt:
                continue

            sensor = d.get("sensor", {})
            if not isinstance(sensor, dict) or sensor.get("type") != "email":
                continue

            dd = d.get("detectionDescription", {})
            rule = ""
            if isinstance(dd, dict):
                rule = dd.get("createdReasonId", "") or ""
            if not rule:
                rule = d.get("detectionRule", "") or ""

            if rule not in XDR_EMAIL_RULES:
                continue

            row_data = extract_xdr_email_fields(d)
            identity = resolve_identity_by_mailbox(row_data["mailbox"])

            rows.append({
                "Time": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "Rule": row_data["rule"],
                "Mailbox": row_data["mailbox"],
                "User ID": identity["user_id"],
                "User": identity["user_name"],
                "Dept": identity["dept_name"],
                "From": row_data["from"],
                "To": row_data["to"],
                "Subject": row_data["subject"],
                "Sender IP": row_data["sender_ip"],
                "IOC": row_data["ioc"],
                "IOC SHA256": row_data["ioc_sha"],
                "Detail": row_data["detail"],
                "RawData": json.dumps(d, ensure_ascii=False)
            })

        if not rows:
            QMessageBox.information(self, "Info", "No Email - XDR Data")
            return

        path = os.path.join(EXPORT_DIR, f"Email_XDR_{start}_{end}.xlsx")
        path = get_unique_path(path)

        df = pd.DataFrame(rows)
        df.to_excel(path, index=False)

        QMessageBox.information(self, "Export", f"Email - XDR Excel saved\n{path}")


    def export_email_excel(self):
        start_dt = combine_date_time(self.mail_export_start_date, self.mail_export_start_time)
        end_dt = combine_date_time(self.mail_export_end_date, self.mail_export_end_time)

        start = start_dt.strftime("%Y-%m-%d")
        end = end_dt.strftime("%Y-%m-%d")

        emails = load_emails_by_range(start, end)

        if not emails:
            QMessageBox.information(self, "Info", "No Inbound Mail Data")
            return

        path = os.path.join(EXPORT_DIR, f"Email_{start}_{end}.xlsx")
        path = get_unique_path(path)

        rows = []

        for m in emails:
            if not isinstance(m, dict):
                continue

            event_dt = iso_to_kst_dt(m.get("receivedAt"))
            if not event_dt:
                continue
            if event_dt < start_dt or event_dt > end_dt:
                continue

            from_addr = email_addr(m.get("from"))
            to_list = [email_addr(x) for x in (m.get("to", []) or []) if isinstance(x, dict)]
            cc_list = [email_addr(x) for x in (m.get("cc", []) or []) if isinstance(x, dict)]

            subject = str(m.get("subject", ""))
            cip = str(m.get("clientIp", ""))
            reason = str(m.get("reason", "None"))

            if not to_list:
                continue

            for to in to_list:
                rows.append({
                    "Received": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "From": from_addr,
                    "To": to,
                    "CC": join_list(cc_list),
                    "Subject": subject or "None",
                    "Reason": reason,
                    "Sender IP": cip or "None",
                    "RawData": json.dumps(m, ensure_ascii=False)
                })

        if not rows:
            QMessageBox.information(self, "Info", "No Inbound Mail Data")
            return

        df = pd.DataFrame(rows)
        df.to_excel(path, index=False)
        QMessageBox.information(self, "Export", f"Inbound Mail Excel saved\n{path}")

    def export_dlp_excel(self):
        try:
            os.makedirs(EXPORT_DIR, exist_ok=True)

            start_dt = combine_date_time(self.dlp_export_start_date, self.dlp_export_start_time)
            end_dt = combine_date_time(self.dlp_export_end_date, self.dlp_export_end_time)

            start_date = start_dt.strftime("%Y-%m-%d")
            end_date = end_dt.strftime("%Y-%m-%d")

            machine_name_filter = self.dlp_export_machine_input.text().strip().lower()

            rows = load_dlp_by_range(start_date, end_date)

            filtered_rows = []

            for row in rows:
                if not isinstance(row, dict):
                    continue

                event_dt = dlp_time_to_dt(row.get("eventtimelocal"))
                if not event_dt:
                    continue

                if event_dt < start_dt or event_dt > end_dt:
                    continue

                machine_name = str(row.get("machine_name", "")).strip()
                machine_name_key = machine_name.lower()

                if machine_name_filter:
                    if machine_name_key != machine_name_filter:
                        continue

                dept_name, dept_code = get_dept_by_hostname(machine_name)

                filtered_rows.append({
                    "이벤트": format_dlp_event_id(row.get("event_id", "None")),
                    "날짜/시간 (클라이언트)": str(row.get("eventtimelocal", "None")),
                    "부서": str(dept_name or "미분류"),
                    "부서코드": str(dept_code or ""),
                    "컴퓨터": str(row.get("machine_name", "None")),
                    "소스 IP-주소": str(row.get("ip", "None")),
                    "사용자명": str(row.get("client_name", "None")),
                    "소스": str(row.get("filename", "None")),
                    "대상": str(row.get("destination", "None")),
                    "대상 유형": str(row.get("destination_type", "None")),
                    "목적지 세부정보": str(row.get("item_details") or row.get("destinationDetails") or "None"),
                    "파일 크기": str(row.get("filesize", "None")),
                    "파일 해시": str(row.get("filehash", "None")),
                    "정책 유형": str(row.get("content_policy_type", "None")),
                    "정책명": str(row.get("content_policy", "None")),
                    "운영체제": str(row.get("os_value", "None")),
                })

            if not filtered_rows:
                QMessageBox.information(self, "DLP Export", "조건에 맞는 DLP 데이터가 없습니다.")
                return

            df = pd.DataFrame(filtered_rows)

            suffix = machine_name_filter if machine_name_filter else "all"
            file_name = f"dlp_export_{start_date}_{end_date}_{suffix}.xlsx"
            path = os.path.join(EXPORT_DIR, file_name)
            path = get_unique_path(path)

            df.to_excel(path, index=False)

            QMessageBox.information(
                self,
                "DLP Export",
                f"DLP Excel 저장 완료\n{path}"
            )

        except Exception as e:
            QMessageBox.critical(self, "DLP Export Error", str(e))

    def export_mailscreen_excel(self):
        try:
            os.makedirs(EXPORT_DIR, exist_ok=True)

            start_dt = combine_date_time(self.mailscreen_export_start_date, self.mailscreen_export_start_time)
            end_dt = combine_date_time(self.mailscreen_export_end_date, self.mailscreen_export_end_time)

            start_date = start_dt.strftime("%Y-%m-%d")
            end_date = end_dt.strftime("%Y-%m-%d")

            rows = load_mailscreen_by_range(start_date, end_date)
            filtered_rows = []

            for row in rows:
                if not isinstance(row, dict):
                    continue

                enriched = enrich_mailscreen_sender_fields(row)
                event_dt = timeline_parse_dt(enriched.get("date"))
                if not event_dt:
                    continue

                if event_dt < start_dt or event_dt > end_dt:
                    continue

                filtered_rows.append({
                    "SEQ": str(enriched.get("seq", "None")),
                    "날짜": str(enriched.get("date", "None")),
                    "메일 처리": str(enriched.get("mail_process", "None")),
                    "전송 결과": str(enriched.get("send_result", "None")),
                    "전송 상세": str(enriched.get("send_detail", "None")),
                    "첨부": str(enriched.get("attach", "None")),
                    "제목": str(enriched.get("subject", "None")),
                    "발신자 이메일": str(enriched.get("sender_email", "None")),
                    "발신자 명": str(enriched.get("sender_name", "None")),
                    "발신자 User ID": str(enriched.get("sender_user_id", "None")),
                    "소속": str(enriched.get("sender_dept", "None")),
                    "발신자 상세": str(enriched.get("sender_detail", "None")),
                    "수신자": str(enriched.get("receiver", "None")),
                    "수신자 상세": str(enriched.get("receiver_detail", "None")),
                    "크기": str(enriched.get("size", "None")),
                    "적용 정책": str(enriched.get("policy", "None")),
                    "처리 날짜": str(enriched.get("process_date", "None")),
                    "결재자": str(enriched.get("approver", "None")),
                    "RawData": json.dumps(enriched, ensure_ascii=False),
                })

            if not filtered_rows:
                QMessageBox.information(self, "Outbound Mail Export", "조건에 맞는 Outbound Mail 데이터가 없습니다.")
                return

            df = pd.DataFrame(filtered_rows)
            file_name = f"mailscreen_export_{start_date}_{end_date}.xlsx"
            path = get_unique_path(os.path.join(EXPORT_DIR, file_name))

            df.to_excel(path, index=False)

            QMessageBox.information(
                self,
                "Outbound Mail Export",
                f"Outbound Mail Excel 저장 완료\n{path}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Outbound Mail Export Error", str(e))


    def auto_refresh_detection(self):

        if self.running:
            self.auto_index_after_refresh = True
            self.queue_auto_refresh_job("Detection")
            return

        self.run_auto_refresh_job("Detection")

    def auto_refresh_email(self):

        print("AUTO EMAIL TRIGGER / running =", self.running)

        if self.running:
            self.auto_index_after_refresh = True
            self.queue_auto_refresh_job("Email")
            return

        self.run_auto_refresh_job("Email")

    def auto_refresh_dlp(self):
        if self.running:
            self.auto_index_after_refresh = True
            self.queue_auto_refresh_job("DLP")
            return

        self.run_auto_refresh_job("DLP")

    def auto_refresh_mailscreen(self):
        if self.running:
            self.auto_index_after_refresh = True
            self.queue_auto_refresh_job("MailScreen")
            return

        self.run_auto_refresh_job("MailScreen")

    def update_auto_interval(self):
        interval = self.spin_interval.value() * 60 * 1000

        if self.det_timer.isActive():
            self.det_timer.start(interval)

        if self.mail_timer.isActive():
            self.mail_timer.start(interval)

        if self.dlp_timer.isActive():
            self.dlp_timer.start(interval)

        if self.mailscreen_timer.isActive():
            self.mailscreen_timer.start(interval)

    def toggle_det_timer(self, state):
        if state:
            interval = self.spin_interval.value() * 60 * 1000

            self.auto_refresh_detection()

            self.det_timer.start(interval)
        else:
            self.det_timer.stop()

    def refresh_endpoint_manual(self):
        log.info("Manual Refresh - Endpoint")
        self.run_refresh("Endpoint")

    def refresh_org_manual(self):
        log.info("Manual Refresh - Organization")
        self.run_refresh("Organization")

    def toggle_mail_timer(self, state):
        if state:
            interval = self.spin_interval.value() * 60 * 1000

            # 🔥 직접 run_refresh 하지 말고 auto 함수 호출
            self.auto_refresh_email()

            self.mail_timer.start(interval)
        else:
            self.mail_timer.stop()

    def toggle_dlp_timer(self, state):
        if state:
            interval = self.spin_interval.value() * 60 * 1000
            self.auto_refresh_dlp()
            self.dlp_timer.start(interval)
        else:
            self.dlp_timer.stop()

    def toggle_mailscreen_timer(self, state):
        if state:
            interval = self.spin_interval.value() * 60 * 1000
            self.auto_refresh_mailscreen()
            self.mailscreen_timer.start(interval)
        else:
            self.mailscreen_timer.stop()

    def excepthook(exc_type, exc_value, exc_traceback):
        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print("UNCAUGHT EXCEPTION:")
        print(error_msg)

        with open("fatal_error.log", "w", encoding="utf-8") as f:
            f.write(error_msg)

    sys.excepthook = excepthook


# =========================
# 실행 (이거 그대로 두면 됨)
# =========================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
