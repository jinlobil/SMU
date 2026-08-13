"""Stable, display-only columns used by the Event List query index.

These columns mirror existing list fields. They deliberately do not introduce
user/device identities or alter the current mapping model.
"""

SCHEMA_VERSION = "3"

FIELDS = (
    "time", "hostname", "dept", "username", "privateIp", "publicIp", "file", "sha256", "rule", "lineage",
    "mailbox", "userId", "user", "from", "to", "subject", "senderIp", "ioc", "iocSha256", "detail",
    "received", "cc", "reason", "date", "mailProcess", "sendResult", "senderEmail", "senderName", "receiver",
    "size", "policy", "attachment", "event", "computer", "sourceIp", "source", "destination", "destinationType",
    "destinationDetail", "fileSize", "fileHash",
    "severity", "sourcePort", "destinationIp", "destinationPort", "protocol", "application", "url", "action", "threat",
    "sourceCountry", "destinationCountry", "sourceZone", "destinationZone", "deviceName", "deviceModel", "deviceSerial",
    "logType", "logComponent", "logSubtype", "eventType", "eventId", "hits", "processUser", "filePath", "processId",
    "processHash", "threatFeed", "mitreTactic", "mitreTechnique",
)

FIELD_COLUMNS = {field: f"field_{index:02d}" for index, field in enumerate(FIELDS)}
DISPLAY_COLUMNS = tuple(FIELD_COLUMNS.values())


def values_for_row(row: dict) -> tuple[str, ...]:
    return tuple(str(row.get(field, "") or "") for field in FIELDS)
