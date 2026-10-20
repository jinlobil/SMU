"""Preserve CAP raw fields while supplying aliases consumed by existing DLP views."""
ALIASES = {
    'event_time_local': 'eventtimelocal', 'client_time_utc': 'eventtime',
    'file_name': 'filename', 'file_size': 'filesize', 'file_hash': 'filehash',
    'serial_no': 'serialno', 'destination_details': 'destinationDetails',
    'email_sender': 'emailSender', 'email_subject': 'emailSubject',
    'shadow_exists': 'shadowExists', 'shadow_is_deleted': 'is_deleted',
    'repository_type': 'repositoryType', 'loc_log_id': 'loclogid', 'os_type': 'os_value',
}


def normalize_dlp_row(raw):
    row = dict(raw)
    for current, legacy in ALIASES.items():
        if current in raw: row[legacy] = raw[current]
    return row
