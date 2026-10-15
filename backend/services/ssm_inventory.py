"""Cache-only consumers, with bounded Run Command collection during AWS refresh."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import copy
import logging
import time
from pathlib import Path

from backend.services.aws_assets import load_aws_credentials
from system_monitor.collector import acquire_singleton

SEOUL = timezone(timedelta(hours=9), 'Asia/Seoul')
DOCUMENT = 'LNL-ServerInventory'
SUPPORTED_PLATFORMS = {'Linux', 'Windows'}
log = logging.getLogger('smu.aws.ssm')


class InvocationFailure(Exception):
    """Only bounded, non-output diagnostic metadata may cross the worker boundary."""
    def __init__(self, stage, reason, *, cause=None, status=None, response_code=None):
        super().__init__(reason)
        self.stage, self.reason = stage, reason
        self.exception_type = type(cause).__name__ if cause is not None else type(self).__name__
        code = getattr(cause, 'response', {}).get('Error', {}).get('Code')
        # Never interpolate exception messages, output, URLs or command identifiers.
        self.aws_code = code if isinstance(code, str) and code.isalnum() and len(code) <= 80 else None
        self.status = status if status in {'Pending', 'InProgress', 'Delayed', 'Cancelling', 'Success', 'Failed', 'TimedOut', 'Cancelled'} else None
        self.response_code = response_code if type(response_code) is int else None


def normalized(value):
    if not isinstance(value, str): return None
    value = value.strip()
    return None if value.casefold() in {'', 'unknown', 'n/a', 'none', 'null', '-'} else value


def parse_inventory(output: str) -> dict:
    result = dict.fromkeys(('hostname', 'kernel', 'os', 'os_install_date'))
    result.update(was=[], web=[], db=[])
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        key = key.strip().lstrip('\ufeff').strip().casefold()
        if not sep or key not in result: continue
        if key in {'was', 'web', 'db'}:
            if normalized(value) is None: continue
            parts = value.split('|')
            if len(parts) != 4: raise ValueError('Invalid inventory product record')
            item = dict(zip(('product', 'version', 'path', 'status'), map(normalized, parts)))
            if item['product']: result[key].append(item)
        else:
            result[key] = normalized(value)
    if not result['hostname'] or not result['os']:
        raise ValueError('Inventory hostname/OS missing')
    return result


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
    def __init__(self, root: Path, client_factory=None, *, now=None, timeout=45, poll_interval=1, clock=time.monotonic, sleep=time.sleep):
        self.root, self.client_factory = root, client_factory
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.timeout, self.poll_interval, self.clock, self.sleep = timeout, poll_interval, clock, sleep

    def _client(self):
        credentials = load_aws_credentials(self.root / 'env/aws_env.txt')
        if self.client_factory: return self.client_factory(credentials)
        import boto3
        from botocore.config import Config
        return boto3.client('ssm', region_name=credentials['AWS_REGION'], aws_access_key_id=credentials['AWS_ACCESS_KEY_ID'],
                            aws_secret_access_key=credentials['AWS_SECRET_ACCESS_KEY'],
                            config=Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 2}))

    def _managed(self, client, instance_ids):
        output = {}
        for start in range(0, len(instance_ids), 50):
            args = {'Filters': [{'Key': 'InstanceIds', 'Values': instance_ids[start:start + 50]}], 'MaxResults': 50}
            seen = set()
            while True:
                page = client.describe_instance_information(**args)
                for item in page.get('InstanceInformationList', []):
                    if item.get('InstanceId') in instance_ids: output[item['InstanceId']] = item
                token = page.get('NextToken')
                if not token: break
                if token in seen: raise RuntimeError('Repeated SSM pagination token')
                seen.add(token); args['NextToken'] = token
        return output

    @staticmethod
    def _resolve_plugin(client, command, identifier):
        """Use execution metadata, never infer step names from the OS/plugin action."""
        page = client.list_command_invocations(CommandId=command, InstanceId=identifier, Details=True)
        invocations = [item for item in page.get('CommandInvocations', [])
                       if item.get('InstanceId') == identifier and item.get('CommandId') == command]
        if not invocations: return False, None
        if len(invocations) != 1 or page.get('NextToken'):
            raise InvocationFailure('get_command_invocation', 'ambiguous_invocation_metadata')
        plugins = invocations[0].get('CommandPlugins', [])
        if not plugins: return False, None
        if len(plugins) == 1:
            # AWS explicitly allows omission only for a single-step document.
            return True, None
        active = [item for item in plugins if not (
            isinstance(item.get('Output'), str) and
            item['Output'].lstrip('\ufeff').strip().casefold().startswith('step execution skipped due to unsupported plugin:'))]
        if len(active) == 1:
            name = active[0].get('Name')
            if not isinstance(name, str) or not name:
                raise InvocationFailure('get_command_invocation', 'plugin_name_missing')
            return True, name
        if any(item.get('Status') in {'Pending', 'InProgress', 'Delayed', 'Cancelling'} for item in plugins):
            return False, None
        # Multiple non-skipped steps cannot safely be assigned to a platform by guessing.
        raise InvocationFailure('get_command_invocation', 'ambiguous_inventory_plugin')

    def _invoke(self, client, identifier, platform):
        try:
            response = client.send_command(InstanceIds=[identifier], DocumentName=DOCUMENT, TimeoutSeconds=60)
            command = response['Command']['CommandId']
        except Exception as exc:
            raise InvocationFailure('send_command', 'send_command_failed', cause=exc) from None
        deadline = self.clock() + self.timeout
        state = response_code = None
        missing = False
        resolved, plugin = False, None
        # A fixed attempt cap also bounds polling with a stalled/mocked clock.
        for attempt in range(46):
            if self.clock() >= deadline: break
            try:
                if not resolved:
                    resolved, plugin = self._resolve_plugin(client, command, identifier)
                if resolved:
                    args = {'CommandId': command, 'InstanceId': identifier}
                    if plugin is not None: args['PluginName'] = plugin
                    invocation = client.get_command_invocation(**args)
                else:
                    invocation = {'Status': 'Pending'}
            except Exception as exc:
                if isinstance(exc, InvocationFailure): raise
                aws_code = getattr(exc, 'response', {}).get('Error', {}).get('Code')
                if aws_code == 'InvalidPluginName':
                    raise InvocationFailure('get_command_invocation', 'invalid_plugin_name', cause=exc) from None
                if aws_code != 'InvocationDoesNotExist':
                    raise InvocationFailure('get_command_invocation', 'get_command_invocation_failed', cause=exc) from None
                missing = True
            else:
                missing = False
                state, response_code = invocation.get('Status'), invocation.get('ResponseCode')
                if state == 'Success':
                    if response_code != 0:
                        raise InvocationFailure('terminal_status', 'response_code_nonzero', status=state, response_code=response_code)
                    output = invocation.get('StandardOutputContent', '')
                    # AWS returns only the first 24,000 stdout characters inline.
                    # S3 URL presence is normal, but a full inline buffer may be truncated.
                    if isinstance(output, str) and len(output) >= 24000:
                        raise InvocationFailure('parse', 'output_may_be_truncated', status=state, response_code=response_code)
                    try:
                        return parse_inventory(output)
                    except Exception as exc:
                        raise InvocationFailure('parse', 'parse_failed', cause=exc, status=state, response_code=response_code) from None
                if state not in {'Pending', 'InProgress', 'Delayed', 'Cancelling'}:
                    reason = {'Failed': 'terminal_failed', 'TimedOut': 'terminal_timed_out', 'Cancelled': 'terminal_cancelled'}.get(state, 'terminal_status_unknown')
                    raise InvocationFailure('terminal_status', reason, status=state, response_code=response_code)
            self.sleep(min(self.poll_interval, max(0, deadline - self.clock())))
        cause = TimeoutError()
        if missing:
            failure = InvocationFailure('get_command_invocation', 'invocation_not_found_timeout', cause=cause)
            failure.aws_code = 'InvocationDoesNotExist'
            raise failure
        raise InvocationFailure('get_command_invocation', 'invocation_poll_timeout', cause=cause, status=state, response_code=response_code)

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
                if item.get('InstanceId'): self._failed(records, item['InstanceId'], timestamp, 'collection_failed')
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
        try:
            client = self._client()
            managed = self._managed(client, needed)
        except Exception as exc:
            for identifier in needed: self._failed(records, identifier, timestamp, 'discovery_failed')
            result['status'] = 'stale' if any(item.get('last_success_at') for item in records.values()) else 'failed'
            result['error'] = 'SSM 대상 조회 실패 · 권한/연결 설정 확인'
            log.warning('SSM discovery failed error_type=%s', type(exc).__name__)
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
            try: return identifier, platform, self._invoke(client, identifier, platform), None
            except Exception as exc:
                failure = exc if isinstance(exc, InvocationFailure) else InvocationFailure('get_command_invocation', 'unexpected_invocation_failure', cause=exc)
                log.warning('SSM inventory failed instance_id=%s platform_type=%s stage=%s reason=%s exception_type=%s aws_error_code=%s status=%s response_code=%s',
                            identifier, platform, failure.stage, failure.reason, failure.exception_type, failure.aws_code, failure.status, failure.response_code)
                return identifier, platform, None, failure.reason
        if targets:
            progress(f'SSM Server Inventory · {len(targets)}대 조회 중')
            with ThreadPoolExecutor(max_workers=5) as pool:
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
