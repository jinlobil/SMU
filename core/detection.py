# -*- coding: utf-8 -*-
"""Detection/XDR classification helpers shared by cache, timeline, and UI tabs."""

from __future__ import annotations


XDR_EMAIL_RULES = {
    "XDR-sophos-email-maliciousurl",
    "XDR-sophos-email-virus",
    "XDR-sophos-email-impersonation",
}


def get_detection_sensor_type(detection: dict) -> str:
    """Return normalized Sophos detection sensor type: endpoint/email/blank."""
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
