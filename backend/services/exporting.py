from __future__ import annotations

from typing import Iterable

ExportColumn = dict[str, object]

EXPORT_SCHEMAS: dict[str, dict[str, object]] = {
    "detections": {
        "label": "Detection XLSX",
        "columns": [
            {"key": "time", "label": "Time", "default": True},
            {"key": "hostname", "label": "Hostname", "default": True},
            {"key": "dept", "label": "Dept", "default": True},
            {"key": "username", "label": "Username", "default": True},
            {"key": "privateIp", "label": "Private IP", "default": True},
            {"key": "publicIp", "label": "Public IP", "default": True},
            {"key": "file", "label": "File", "default": True},
            {"key": "sha256", "label": "SHA256", "default": True},
            {"key": "rule", "label": "Rule", "default": True},
            {"key": "lineage", "label": "Lineage", "default": True},
            {"key": "_sourceFile", "label": "Source File", "default": False},
        ],
    },
    "xdr": {
        "label": "Email XDR XLSX",
        "columns": [
            {"key": "time", "label": "Time", "default": True},
            {"key": "rule", "label": "Rule", "default": True},
            {"key": "mailbox", "label": "Mailbox", "default": True},
            {"key": "userId", "label": "User ID", "default": True},
            {"key": "user", "label": "User", "default": True},
            {"key": "dept", "label": "Dept", "default": True},
            {"key": "from", "label": "From", "default": True},
            {"key": "to", "label": "To", "default": True},
            {"key": "subject", "label": "Subject", "default": True},
            {"key": "senderIp", "label": "Sender IP", "default": True},
            {"key": "ioc", "label": "IOC", "default": True},
            {"key": "iocSha256", "label": "IOC SHA256", "default": True},
            {"key": "detail", "label": "Detail", "default": True},
            {"key": "_sourceFile", "label": "Source File", "default": False},
        ],
    },
    "inbound": {
        "label": "Inbound Mail XLSX",
        "columns": [
            {"key": "received", "label": "Received", "default": True},
            {"key": "from", "label": "From", "default": True},
            {"key": "to", "label": "To", "default": True},
            {"key": "user", "label": "User", "default": True},
            {"key": "dept", "label": "Dept", "default": True},
            {"key": "cc", "label": "CC", "default": True},
            {"key": "subject", "label": "Subject", "default": True},
            {"key": "reason", "label": "Reason", "default": True},
            {"key": "senderIp", "label": "Sender IP", "default": True},
            {"key": "_sourceFile", "label": "Source File", "default": False},
        ],
    },
    "outbound": {
        "label": "Outbound Mail XLSX",
        "columns": [
            {"key": "date", "label": "Date", "default": True},
            {"key": "mailProcess", "label": "Mail Process", "default": True},
            {"key": "sendResult", "label": "Send Result", "default": True},
            {"key": "subject", "label": "Subject", "default": True},
            {"key": "senderEmail", "label": "Sender Email", "default": True},
            {"key": "senderName", "label": "Sender Name", "default": True},
            {"key": "dept", "label": "Dept", "default": True},
            {"key": "receiver", "label": "Receiver", "default": True},
            {"key": "size", "label": "Size", "default": True},
            {"key": "policy", "label": "Policy", "default": True},
            {"key": "attachment", "label": "Attachment", "default": True},
            {"key": "_sourceFile", "label": "Source File", "default": False},
        ],
    },
    "dlp": {
        "label": "DLP File XLSX",
        "columns": [
            {"key": "event", "label": "Event", "default": True},
            {"key": "time", "label": "Time", "default": True},
            {"key": "computer", "label": "Computer", "default": True},
            {"key": "dept", "label": "Dept", "default": True},
            {"key": "sourceIp", "label": "Source IP", "default": True},
            {"key": "username", "label": "Username", "default": True},
            {"key": "source", "label": "Source", "default": True},
            {"key": "destination", "label": "Destination", "default": True},
            {"key": "destinationType", "label": "Destination Type", "default": True},
            {"key": "destinationDetail", "label": "Destination Detail", "default": True},
            {"key": "fileSize", "label": "File Size", "default": True},
            {"key": "fileHash", "label": "File Hash", "default": True},
            {"key": "_sourceFile", "label": "Source File", "default": False},
        ],
    },
}

REPORT_SECTIONS: list[dict[str, object]] = [
    {"key": "detections", "label": "Detection", "default": True},
    {"key": "xdr", "label": "Email XDR", "default": True},
    {"key": "inbound", "label": "Inbound Mail", "default": True},
    {"key": "outbound", "label": "Outbound Mail", "default": True},
    {"key": "dlp", "label": "DLP File", "default": True},
]


def schema_payload() -> dict[str, object]:
    return {"exports": EXPORT_SCHEMAS, "report": {"label": "Security Report PDF", "sections": REPORT_SECTIONS}}


def _keys(items: Iterable[dict[str, object]]) -> set[str]:
    return {str(item.get("key")) for item in items}


def default_export_columns(kind: str) -> list[str]:
    schema = EXPORT_SCHEMAS.get(kind)
    if schema is None:
        raise ValueError("Unknown export type")
    return [str(column["key"]) for column in schema["columns"] if bool(column.get("default", True))]


def export_headers(kind: str) -> dict[str, str]:
    schema = EXPORT_SCHEMAS.get(kind)
    if schema is None:
        raise ValueError("Unknown export type")
    return {str(column["key"]): str(column.get("label") or column["key"]) for column in schema["columns"]}


def normalize_export_columns(kind: str, requested: object) -> list[str]:
    allowed = _keys(EXPORT_SCHEMAS.get(kind, {}).get("columns", []))
    if not allowed:
        raise ValueError("Unknown export type")
    if not isinstance(requested, list) or not requested:
        return default_export_columns(kind)
    columns = [str(column) for column in requested if str(column) in allowed]
    if not columns:
        raise ValueError("At least one export column must be selected")
    return list(dict.fromkeys(columns))


def normalize_report_sections(requested: object) -> list[str]:
    allowed = _keys(REPORT_SECTIONS)
    if not isinstance(requested, list) or not requested:
        return [str(section["key"]) for section in REPORT_SECTIONS if bool(section.get("default", True))]
    sections = [str(section) for section in requested if str(section) in allowed]
    if not sections:
        raise ValueError("At least one report section must be selected")
    return list(dict.fromkeys(sections))
