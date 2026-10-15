"""Collect the existing LNL-ServerInventory contract; consumers use cache only."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import copy
import logging
import random
import time
from pathlib import Path

from backend.services.aws_assets import load_aws_credentials
from system_monitor.collector import acquire_singleton

SEOUL = timezone(timedelta(hours=9), 'Asia/Seoul')
DOCUMENT = 'LNL-ServerInventory'
# Verified against the administrator-supplied schemaVersion 2.2 Document definition.
STEPS = {'Linux': 'linuxInventory', 'Windows': 'windowsInventory'}
SUPPORTED_PLATFORMS = set(STEPS)
log = logging.getLogger('smu.aws.ssm')
INVENTORY_KEYS = ('hostname', 'kernel', 'os', 'os_install_date', 'was', 'web', 'db')
PLUGIN_GRACE_SECONDS = 25
THROTTLING_CODES = {'Throttling', 'ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'}


class InventoryFailure(Exception):
    """Safe metadata only: never retain output, command IDs or exception messages."""
    def __init__(self, stage, reason, *, cause=None, status=None, response_code=None, output_length=None, keys_present=None):
        super().__init__(reason)
        self.stage, self.reason = stage, reason
        self.exception_type = type(cause).__name__ if cause is not None else type(self).__name__
        code = getattr(cause, 'response', {}).get('Error', {}).get('Code')
        self.aws_code = code if isinstance(code, str) and code.isalnum() and len(code) <= 80 else None
        self.status = status if status in {'Pending', 'InProgress', 'Delayed', 'Cancelling', 'Success', 'Failed', 'TimedOut', 'Cancelled'} else None
        self.response_code = response_code if type(response_code) is int else None
        self.output_length = output_length if type(output_length) is int else None
        self.keys_present = {key: None if keys_present is None else bool(keys_present.get(key))
                             for key in INVENTORY_KEYS}


def normalized(value):
    # Shared with Sophos/Excel consumers; intentionally retained.
    if not isinstance(value, str): return None
    value = value.strip()
    return None if value.casefold() in {'', 'unknown', 'n/a', 'none', 'null', '-'} else value


class OutputParseError(ValueError):
    def __init__(self, reason, keys_present):
        super().__init__(reason)
        self.reason, self.keys_present = reason, keys_present


def parse_inventory(output):
    """Parse the unmodified Custom Document's KV/product contract, never stdout JSON."""
    fields = ('hostname', 'kernel', 'os', 'os_install_date')
    products = ('was', 'web', 'db')
    result = dict.fromkeys((*fields, 'os_version'))
    result.update(was=[], web=[], db=[])
    records = []
    keys = dict.fromkeys(INVENTORY_KEYS, False)
    if not isinstance(output, str) or not output.strip().strip('\ufeff').strip():
        raise OutputParseError('empty_output', keys)
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        key = key.strip().lstrip('\ufeff').strip().casefold()
        if not sep: continue
        if key in keys: keys[key] = True
        if key in fields or key in products: records.append((key, value))
    # AWS returns only the first 24,000 stdout characters. Do not save a partial inventory.
    if len(output) >= 24000:
        raise OutputParseError('output_truncated', keys)
    for key, value in records:
        if key in products:
            if normalized(value) is None: continue
            parts = value.split('|')
            if len(parts) != 4:
                raise OutputParseError('invalid_product_record', keys)
            item = dict(zip(('product', 'version', 'path', 'status'), map(normalized, parts)))
            if not item['product']:
                raise OutputParseError('invalid_product_record', keys)
            result[key].append(item)
        else:
            result[key] = normalized(value)
    if not result['hostname']: raise OutputParseError('missing_hostname', keys)
    if not result['os']: raise OutputParseError('missing_os', keys)
    # Both Document steps always emit all three product categories, even when absent.
    # Missing categories can signal incomplete stdout even below the AWS size limit.
    if not all(keys[key] for key in products): raise OutputParseError('parse_failed', keys)
    return result


def output_diagnostics(output):
    """Only counts and known-key presence; never return output values or paths."""
    keys = dict.fromkeys(INVENTORY_KEYS, False)
    counts = dict.fromkeys(('was', 'web', 'db'), 0)
    lines = output.splitlines() if isinstance(output, str) else []
    for line in lines:
        key, sep, value = line.partition('=')
        key = key.strip().lstrip('\ufeff').strip().casefold()
        if not sep: continue
        if key in keys: keys[key] = True
        if key in counts and normalized(value) is not None: counts[key] += 1
    return {'output_length': len(output) if isinstance(output, str) else None,
            'line_count': len(lines), 'keys_present': keys, 'record_counts': counts}


def cache_lock(root: Path):
    return acquire_singleton(root / 'runtime/aws-inventory.lock')


@contextmanager
def cache_write_lock(root: Path):
    deadline = time.monotonic() + 5
    lease = None
    while lease is None:
        lease = acquire_singleton(root / 'runtime/aws-cache-write.lock')
        if lease is not None: break
        if time.monotonic() >= deadline: raise RuntimeError('AWS Cache 저장이 이미 실행 중입니다.')
        time.sleep(0.05)
    try: yield
    finally: lease.close()


def _date(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=SEOUL)
        return parsed.astimezone(SEOUL).date().isoformat()
    except (ValueError, TypeError, AttributeError): return None


class SsmInventoryCollector:
    def __init__(self, root: Path, client_factory=None, *, now=None, timeout=330, collection_timeout=1800,
                 poll_interval=1, clock=time.monotonic, sleep=time.sleep, jitter=random.random):
        self.root, self.client_factory = root, client_factory
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.timeout, self.collection_timeout = timeout, collection_timeout
        self.poll_interval, self.clock, self.sleep, self.jitter = poll_interval, clock, sleep, jitter

    def _client(self):
        credentials = load_aws_credentials(self.root / 'env/aws_env.txt')
        if self.client_factory: return self.client_factory(credentials)
        import boto3
        from botocore.config import Config
        return boto3.client('ssm', region_name=credentials['AWS_REGION'], aws_access_key_id=credentials['AWS_ACCESS_KEY_ID'],
                            aws_secret_access_key=credentials['AWS_SECRET_ACCESS_KEY'],
                            config=Config(connect_timeout=3, read_timeout=5, retries={'max_attempts': 0}))

    def _request(self, method, stage, deadline, *, diagnostics=None, retry_deadline=None, **kwargs):
        # Explicit throttling only. Get retries share one budget across all polls,
        # so plugin-readiness retries cannot multiply the throttle retry allowance.
        for attempt in range(5):
            if self.clock() >= deadline: raise InventoryFailure(stage, 'polling_timeout')
            if attempt and retry_deadline is not None and self.clock() >= retry_deadline:
                failure = InventoryFailure(stage, 'throttled')
                failure.aws_code = diagnostics.get('last_aws_error_code') if diagnostics is not None else None
                raise failure
            if diagnostics is not None:
                diagnostics['attempts'][stage] += 1
                self._log_diagnostic(diagnostics, stage, 'request_started')
            try:
                response = method(**kwargs)
            except Exception as exc:
                code = getattr(exc, 'response', {}).get('Error', {}).get('Code')
                safe_code = code if isinstance(code, str) and code.isalnum() and len(code) <= 80 else None
                if diagnostics is not None:
                    diagnostics['last_aws_error_code'] = safe_code
                    if code == 'InvalidPluginName': diagnostics['invalid_plugin_name_count'] += 1
                    if code == 'InvocationDoesNotExist': diagnostics['invocation_not_ready_count'] += 1
                    reason = {'InvalidPluginName': 'invalid_plugin_name', 'InvocationDoesNotExist': 'invocation_not_ready'}.get(code, 'request_failed')
                    self._log_diagnostic(diagnostics, stage, 'throttled' if code in THROTTLING_CODES else reason,
                                         exception_type=type(exc).__name__, aws_error_code=safe_code)
                if code not in THROTTLING_CODES: raise
                retry = diagnostics['throttle_retries'][stage] if diagnostics is not None else attempt
                delay = min(4.0, 0.25 * 2 ** retry) * (0.5 + 0.5 * self.jitter())
                if retry >= 4 or self.clock() + delay >= min(deadline, retry_deadline if retry_deadline is not None else deadline):
                    raise InventoryFailure(stage, 'throttled', cause=exc) from None
                if diagnostics is not None: diagnostics['throttle_retries'][stage] += 1
                self.sleep(delay)
            else:
                if self.clock() >= deadline: raise InventoryFailure(stage, 'polling_timeout')
                return response

    def _managed(self, client, instance_ids, deadline):
        output = {}
        for start in range(0, len(instance_ids), 50):
            args = {'Filters': [{'Key': 'InstanceIds', 'Values': instance_ids[start:start + 50]}], 'MaxResults': 50}
            seen = set()
            while True:
                page = self._request(client.describe_instance_information, 'describe_instance_information', deadline, **args)
                for item in page.get('InstanceInformationList', []):
                    if item.get('InstanceId') in instance_ids: output[item['InstanceId']] = item
                token = page.get('NextToken')
                if not token: break
                if token in seen: raise InventoryFailure('describe_instance_information', 'repeated_pagination_token')
                seen.add(token); args['NextToken'] = token
        return output

    def _invoke(self, client, identifier, platform, collection_deadline):
        started = self.clock()
        deadline = min(collection_deadline, started + self.timeout)
        step = STEPS[platform]
        diagnostics = {'instance_id': identifier, 'platform_type': platform, 'started': started,
                       'attempts': {'send_command': 0, 'get_command_invocation': 0},
                       'throttle_retries': {'send_command': 0, 'get_command_invocation': 0},
                       'polling_attempt': 0, 'invalid_plugin_name_count': 0,
                       'invocation_not_ready_count': 0, 'last_aws_error_code': None}
        metadata = {}
        try:
            try:
                sent = self._request(client.send_command, 'send_command', deadline, diagnostics=diagnostics,
                    InstanceIds=[identifier], DocumentName=DOCUMENT, TimeoutSeconds=60)
                command = sent['Command']['CommandId']
            except InventoryFailure: raise
            except Exception as exc:
                raise InventoryFailure('send_command', 'send_command_failed', cause=exc) from None
            self._log_diagnostic(diagnostics, 'send_command', 'send_command_succeeded', send_success=True, target_count=1)
            grace_deadline = min(deadline, self.clock() + PLUGIN_GRACE_SECONDS)
            state = response_code = None
            not_ready = registered = False
            last_plugin_failure = None
            for polling_attempt in range(1, 361):
                # No extra request at/after grace expiration following InvalidPluginName.
                if last_plugin_failure is not None and self.clock() >= grace_deadline:
                    raise last_plugin_failure
                if self.clock() >= deadline: break
                diagnostics['polling_attempt'] = polling_attempt
                try:
                    invocation = self._request(client.get_command_invocation, 'get_command_invocation', deadline,
                        retry_deadline=grace_deadline if last_plugin_failure is not None else None, diagnostics=diagnostics, CommandId=command, InstanceId=identifier, PluginName=step)
                except InventoryFailure: raise
                except Exception as exc:
                    code = getattr(exc, 'response', {}).get('Error', {}).get('Code')
                    if code == 'InvalidPluginName':
                        failure = InventoryFailure('get_command_invocation', 'invalid_plugin_name', cause=exc)
                        if registered or self.clock() >= grace_deadline: raise failure from None
                        last_plugin_failure = failure
                        delay = min(5, 2 ** min(diagnostics['invalid_plugin_name_count'] - 1, 3),
                                    max(0, grace_deadline - self.clock()))
                        self._log_diagnostic(diagnostics, 'get_command_invocation', 'plugin_grace_wait',
                                             retry_delay_seconds=delay)
                        self.sleep(delay)
                        continue
                    last_plugin_failure = None
                    if code != 'InvocationDoesNotExist':
                        raise InventoryFailure('get_command_invocation', 'get_command_invocation_failed', cause=exc) from None
                    not_ready = True
                else:
                    last_plugin_failure = None
                    not_ready, registered = False, True
                    state, response_code = invocation.get('Status'), invocation.get('ResponseCode')
                    metadata = output_diagnostics(invocation.get('StandardOutputContent', ''))
                    safe_status = state if state in {'Pending', 'InProgress', 'Delayed', 'Cancelling', 'Success', 'Failed', 'TimedOut', 'Cancelled'} else None
                    self._log_diagnostic(diagnostics, 'get_command_invocation',
                        'stdout_received' if state == 'Success' else 'invocation_response',
                        status=safe_status, response_code=response_code if type(response_code) is int else None, **metadata)
                    if state == 'Success':
                        if type(response_code) is not int or response_code != 0:
                            raise InventoryFailure('terminal_status', 'nonzero_response_code', status=state, response_code=response_code, output_length=metadata['output_length'])
                        try:
                            inventory = parse_inventory(invocation.get('StandardOutputContent', ''))
                        except OutputParseError as exc:
                            raise InventoryFailure('parse', exc.reason, cause=exc, status=state, response_code=response_code,
                                                   output_length=metadata['output_length'], keys_present=exc.keys_present) from None
                        self._log_diagnostic(diagnostics, 'parse', 'inventory_parsed', status=state, response_code=response_code, **metadata)
                        return inventory
                    if state not in {'Pending', 'InProgress', 'Delayed', 'Cancelling'}:
                        raise InventoryFailure('terminal_status', 'terminal_failed', status=state, response_code=response_code, output_length=metadata['output_length'])
                self.sleep(min(self.poll_interval, max(0, deadline - self.clock())))
            if last_plugin_failure is not None: raise last_plugin_failure
            failure = InventoryFailure('get_command_invocation', 'invocation_not_ready' if not_ready else 'polling_timeout',
                                       cause=TimeoutError(), status=state, response_code=response_code)
            if not_ready: failure.aws_code = 'InvocationDoesNotExist'
            raise failure
        except InventoryFailure as failure:
            # This snapshot contains safe counters only, never command IDs/output/exception text.
            failure.diagnostics = diagnostics
            failure.output_metadata = metadata
            raise

    def _log_diagnostic(self, context, stage, reason, *, level=logging.INFO, keys_present=None, record_counts=None, **values):
        fields = {'instance_id': context.get('instance_id'), 'platform_type': context.get('platform_type'),
                  'document_name': DOCUMENT, 'selected_step': STEPS.get(context.get('platform_type')),
                  'stage': stage, 'reason': reason, 'exception_type': None, 'aws_error_code': None,
                  'attempt_count': context.get('attempts', {}).get(stage if stage == 'send_command' else 'get_command_invocation', 0),
                  'elapsed_seconds': round(max(0, self.clock() - context['started']), 3) if 'started' in context else None,
                  'polling_attempt': context.get('polling_attempt', 0),
                  'invalid_plugin_name_count': context.get('invalid_plugin_name_count', 0),
                  'invocation_not_ready_count': context.get('invocation_not_ready_count', 0),
                  'last_aws_error_code': context.get('last_aws_error_code'),
                  'status': None, 'response_code': None}
        fields.update(values)
        for key in INVENTORY_KEYS: fields['has_' + key] = None if keys_present is None else keys_present.get(key)
        for key in ('was', 'web', 'db'): fields[key + '_record_count'] = None if record_counts is None else record_counts.get(key)
        log.log(level, 'SSM inventory %s', ' '.join(f'{key}={value}' for key, value in fields.items()))

    def _log_failure(self, identifier, platform, failure):
        context = getattr(failure, 'diagnostics', {'instance_id': identifier, 'platform_type': platform})
        metadata = getattr(failure, 'output_metadata', {})
        self._log_diagnostic(context, failure.stage, failure.reason, level=logging.WARNING,
            exception_type=failure.exception_type, aws_error_code=failure.aws_code,
            status=failure.status, response_code=failure.response_code,
            **{**metadata, 'output_length': failure.output_length,
               'keys_present': metadata.get('keys_present', failure.keys_present)},
            parse_reason=failure.reason if failure.stage == 'parse' else None,
            send_success=False if failure.stage == 'send_command' else None,
            target_count=1 if failure.stage == 'send_command' else None)

    def collect(self, ec2_instances, previous=None, *, force=False, progress=lambda _: None):
        try:
            return self._collect(ec2_instances, previous, force=force, progress=progress)
        except Exception as exc:
            log.warning('SSM collection unavailable error_type=%s', type(exc).__name__)
            result = copy.deepcopy(previous) if isinstance(previous, dict) else {}
            records = result.get('instances')
            result['instances'] = records = {key: item for key, item in records.items() if isinstance(item, dict)} if isinstance(records, dict) else {}
            timestamp = self.now().astimezone(SEOUL).isoformat()
            for item in ec2_instances:
                identifier = item.get('InstanceId')
                if identifier and (force or _date(records.get(identifier, {}).get('last_attempt_at')) != _date(timestamp)):
                    self._failed(records, identifier, timestamp, 'collection_failed')
            result.update(last_attempt_at=timestamp, status='stale' if any(item.get('last_success_at') for item in records.values()) else 'failed')
            return result

    def _collect(self, ec2_instances, previous=None, *, force=False, progress=lambda _: None):
        result = copy.deepcopy(previous) if isinstance(previous, dict) else {}
        records = result.get('instances')
        result['instances'] = records = {key: item for key, item in records.items() if isinstance(item, dict)} if isinstance(records, dict) else {}
        started = self.now().astimezone(SEOUL)
        today, timestamp = started.date().isoformat(), started.isoformat()
        identifiers = sorted({item['InstanceId'] for item in ec2_instances if isinstance(item.get('InstanceId'), str) and item['InstanceId'].startswith('i-')})
        if not identifiers:
            result.update(snapshot_date=today, collected_at=timestamp, last_attempt_at=timestamp, status='success')
            return result
        needed = [identifier for identifier in identifiers if force
                  or _date(records.get(identifier, {}).get('last_attempt_at')) != today]
        if not needed:
            active = [records[identifier] for identifier in identifiers]
            complete = all(item.get('status') == 'success' and _date(item.get('last_success_at')) == today for item in active)
            result['status'] = 'success' if complete else 'partial' if any(item.get('last_success_at') for item in active) else 'failed'
            if complete: result['snapshot_date'] = today
            result.pop('error', None)
            return result
        result['last_attempt_at'] = timestamp
        collection_deadline = self.clock() + self.collection_timeout
        try:
            client = self._client()
            managed = self._managed(client, needed, collection_deadline)
        except Exception as exc:
            failure = exc if isinstance(exc, InventoryFailure) else InventoryFailure('describe_instance_information', 'discovery_failed', cause=exc)
            for identifier in needed:
                self._failed(records, identifier, timestamp, failure.reason)
                self._log_failure(identifier, records.get(identifier, {}).get('platform_type'), failure)
            result['status'] = 'stale' if any(item.get('last_success_at') for item in records.values()) else 'failed'
            result['error'] = 'SSM 대상 조회 실패 · 권한/연결 설정 확인'
            return result
        targets = []
        for identifier in needed:
            info = managed.get(identifier, {})
            existing = records.get(identifier, {})
            if info.get('PlatformType') in SUPPORTED_PLATFORMS and not existing.get('last_success_at'):
                records.setdefault(identifier, {})['platform_type'] = info['PlatformType']
            if info.get('PingStatus') != 'Online' or info.get('PlatformType') not in SUPPORTED_PLATFORMS:
                self._failed(records, identifier, timestamp, 'not_online' if info.get('PingStatus') != 'Online' else 'unsupported_platform')
                continue
            targets.append((identifier, info['PlatformType']))
        def collect_one(target):
            identifier, platform = target
            try: return identifier, platform, self._invoke(client, identifier, platform, collection_deadline), None
            except Exception as exc:
                failure = exc if isinstance(exc, InventoryFailure) else InventoryFailure('collector', 'collection_failed', cause=exc)
                self._log_failure(identifier, platform, failure)
                return identifier, platform, None, failure.reason
        if targets:
            progress(f'SSM Server Inventory · {len(targets)}대 조회 중')
            with ThreadPoolExecutor(max_workers=3) as pool:
                for identifier, platform, inventory, failure_reason in pool.map(collect_one, targets):
                    attempted = self.now().astimezone(SEOUL).isoformat()
                    if inventory is None:
                        self._failed(records, identifier, attempted, failure_reason)
                    else:
                        records[identifier] = {**inventory, 'status': 'success', 'platform_type': platform,
                                               'last_attempt_at': attempted, 'last_success_at': attempted}
        active = [records.get(identifier, {}) for identifier in identifiers]
        complete = all(item.get('status') == 'success' and _date(item.get('last_success_at')) == today for item in active)
        online = [identifier for identifier in identifiers if managed.get(identifier, {}).get('PingStatus') == 'Online'
                  and managed.get(identifier, {}).get('PlatformType') in SUPPORTED_PLATFORMS]
        # Snapshot date covers the eligible Online set, not unmanageable EC2s.
        # Per-instance last_attempt_at gates automatic attempts, including failures.
        if online and all(records[identifier].get('status') == 'success' and _date(records[identifier].get('last_success_at')) == today for identifier in online):
            result['snapshot_date'] = today
        if targets and any(records[identifier].get('status') == 'success' for identifier, _ in targets):
            result['collected_at'] = self.now().astimezone(SEOUL).isoformat()
        result['status'] = 'success' if complete else 'partial' if any(item.get('last_success_at') for item in active) else 'failed'
        result.pop('error', None)
        return result

    @staticmethod
    def _failed(records, identifier, timestamp, reason):
        record = records.setdefault(identifier, {})
        record.update(status='stale' if record.get('last_success_at') else 'failed', last_attempt_at=timestamp, error=reason)
