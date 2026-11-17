"""Sophos XDR events -> the existing Outbound canonical mail model."""
import hashlib
import json
import math
from collections import OrderedDict
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
CANONICAL_FIELDS = ('date', 'mailProcess', 'sendResult', 'subject', 'senderEmail',
                    'senderName', 'dept', 'receiver', 'size', 'policy', 'attachment')


def event_time(value):
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value / 1000 if abs(value) >= 1e12 else value, timezone.utc)
        parsed = datetime.fromisoformat(str(value or '').replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError): return None


def message_groups(events):
    """Missing Sophos IDs never merge unrelated events under a blank key."""
    groups = OrderedDict()
    for index, event in enumerate(events):
        if not isinstance(event, dict): raise ValueError('Invalid Sophos Outbound event')
        identifier = str(event.get('x_sophos_email_id') or '').strip()
        if identifier:
            key = 'sophos:' + identifier
        else:
            digest = hashlib.sha256(json.dumps(event, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            key = f'missing:{digest}:{index}'
        groups.setdefault(key, []).append(index)
    return groups


def _values(value):
    if isinstance(value, list):
        return [item for part in value for item in _values(part)]
    if value is None or value == '': return []
    return [json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, dict) else str(value)]


def normalize_outbound(events):
    output = []
    for key, indexes in message_groups(events).items():
        rows = [events[index] for index in indexes]
        ordered = sorted(rows, key=lambda row: event_time(row.get('event_time')) or event_time(row.get('timestamp')) or datetime.min.replace(tzinfo=timezone.utc))
        accepted = [event_time(row.get('event_time')) for row in rows if row.get('event_type') == 'ACCEPTED']
        times = [event_time(row.get('event_time')) for row in rows]
        stamps = [event_time(row.get('timestamp')) for row in rows]
        selected = next((min(valid) for group in (accepted, times, stamps) if (valid := [item for item in group if item])), None)
        if selected is None: raise ValueError('Sophos Outbound event time missing')
        deliveries = [row for row in ordered if row.get('event_type') == 'DELIVERY_ATTEMPT']
        if deliveries:
            results = [str(row.get('event_details') or '').strip() for row in deliveries]
            successes = sum(value.casefold() == 'delivery successful' for value in results)
            result = 'Success' if successes == len(results) else 'Partial Failed' if successes else 'Failed'
        else:
            last = ordered[-1]
            result = 'Accepted' if all(row.get('event_type') == 'ACCEPTED' for row in rows) else last.get('event_details') or last.get('event_type') or 'None'
        first = lambda field: next((row[field] for row in rows if row.get(field) and
                                   (not isinstance(row[field], str) or row[field].strip())), None)
        sender = first('envelope_sender')
        if not sender:
            header = first('header_from')
            if isinstance(header, dict):
                local = header.get('local_address') or header.get('localAddress')
                domain = header.get('domain_address') or header.get('domainAddress')
                sender = f'{local}@{domain}' if local and domain else None
        receivers = list(dict.fromkeys(value for row in rows for value in _values(row.get('envelope_recipient'))))
        policies = list(dict.fromkeys(value for row in rows for field in ('reason', 'reason_list') for value in _values(row.get(field))))
        sizes = []
        for row in rows:
            try: value = float(row.get('message_size_kb') or 0)
            except (ValueError, TypeError): continue
            if math.isfinite(value) and value > 0: sizes.append(value)
        mime_ids = list(dict.fromkeys(str(row['mime_message_id']) for row in rows if row.get('mime_message_id')))
        output.append({'date': selected.astimezone(KST).strftime('%Y-%m-%d %H:%M:%S'),
            'mailProcess': 'DELIVERY_ATTEMPT' if deliveries else ordered[-1].get('event_type'),
            'sendResult': result, 'subject': first('subject'), 'senderEmail': sender, 'senderName': None, 'dept': None,
            'receiver': ', '.join(receivers) or None, 'size': f'{max(sizes):g} KB' if sizes else None,
            'policy': '; '.join(policies) or None, 'attachment': None,
            'x_sophos_email_id': first('x_sophos_email_id'), 'mime_message_id': mime_ids[0] if mime_ids else None,
            'mime_message_ids': mime_ids, 'policyReasons': policies,
            'recipientResults': [{'receiver': row.get('envelope_recipient'), 'event_time': row.get('event_time'),
                                  'event_details': row.get('event_details'), 'reason': row.get('reason'),
                                  'reason_list': row.get('reason_list')} for row in deliveries],
            '_messageKey': key, '_rawIndexes': indexes})
    return output
