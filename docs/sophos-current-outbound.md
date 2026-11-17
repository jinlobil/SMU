# Current Outbound: Sophos XDR / preserved MailScreen Legacy

## Scope and source boundary

Current Outbound now uses the existing `SophosClient` and `env/Sophos_env.txt`.
No extra credential file, integration, client ID or secret store was added.
MailScreenClient, its ENV/Integration support and `cache/mailscreen` remain intact.
`RefreshService.refresh_outbound_legacy()` and `TransferService._collect_outbound_legacy()`
retain explicit access to the old collector/parser. Current does not fall back to or
combine Legacy mail counts, even when Sophos cache is empty.

## Collection and HTTP behavior

`Scheduler / Fetcher -> refresh_outbound_range -> refresh_outbound -> SophosClient.fetch_outbound_emails`.
Each day uses the shared OAuth/WhoAmI flow and tenant dataRegion base URL. POST
`/xdr-query/v1/queries/runs` has `from`, `to` and `adHocQuery: {name, template}`.
The supplied SQL selects `xdr_xge_events` with OUTBOUND direction, all requested fields,
ORDER BY event_time DESC, and no LIMIT.

KST day 2026-11-16 becomes UTC 2026-11-15T15:00:00.000Z through
2026-11-16T14:59:59.999Z. The shared Detection/Inbound `utc_range()` is unchanged.

After obtaining a run ID: wait 2 seconds, poll the same run about every 3 seconds,
with a 120-second polling deadline. GET request timeout is capped to the remaining
budget (maximum 15 seconds). Only finished/succeeded permits results. Other terminal
states and timeout raise sanitized errors. Poll retry never creates a new query run.

XDR HTTP requests retry 429, 5xx and temporary network errors up to three times
(four attempts). Retry-After accepts seconds or HTTP date; otherwise 1/2/4-second
backoff is used. Poll sleeps/retries stay within its deadline. Non-poll Retry-After
longer than 120 seconds fails rather than blocking indefinitely. A retry of a failed
POST repeats that same operation; after an ID is obtained, only GETs are retried.

Results use pageSize=2000, then URL-encoded pageFromKey=pages.nextKey until no cursor.
No numbered-page fallback is used. Invalid items, repeated cursors, a safety ceiling
of 10,000 result pages and incomplete final item totals fail collection rather than
committing partial data. Request bodies, credentials, response bodies and original
exception messages are not logged or passed to Progress/Error responses.

## Cache commit

- Raw: `cache/sophos_outbound_raw/YYYY-MM-DD.json` — all returned event dictionaries.
- Current: `cache/sophos_outbound/YYYY-MM-DD.json` — canonical message records.

Both complete payloads are staged as unique .tmp files before replacements. Raw is
replaced first and normalized last. A normal local replacement failure rolls back
already-replaced files and removes staging files. A per-day process lock rejects
concurrent refresh of the same date. API, pagination, normalization and serialization
failures leave the prior cache pair untouched. Recollection replaces that date,
without append accumulation. Abrupt machine/storage failure between the two separate
file replacements cannot be made into a cross-file transaction; message-key Raw joins
prevent a reader from attaching a different message merely because its old row offset
was reused.

Refresh returns date, rows/count (normalized message count), rawRows, normalizedRows,
pages, path and rawPath. The range runner and existing Fetcher chain remain compatible.

## Normalization and identity

- Primary group: exact x_sophos_email_id. Shared MIME IDs do not merge different Sophos IDs.
- Missing Sophos IDs: separate deterministic fingerprint/index groups per raw event;
  no unrelated blank-ID records are coalesced and no guessed MIME grouping is applied.
- Date: earliest valid ACCEPTED event_time; otherwise earliest event_time; otherwise
  timestamp. Converted to the existing KST display format. Missing all valid dates
  is an error, protecting the prior cache.
- mailProcess: DELIVERY_ATTEMPT when present; otherwise latest event_type.
- sendResult: Success / Partial Failed / Failed over DELIVERY_ATTEMPT results;
  ACCEPTED-only is Accepted, other final event information is preserved.
- Receiver: distinct envelope recipients in source order. recipientResults retains
  each delivery attempt's recipient, time, details, reason and reason_list.
- Sender: first envelope_sender; fallback header_from local/domain address.
- Subject: first non-empty value; size: maximum positive finite message_size_kb, in KB.
- Policy: all distinct reason/reason_list values plus policyReasons array.
- Attachment: null. No file name, file size or attachment is inferred.
- Sender name and department use existing EmailSecurityService directory identity,
  EndpointService department context and ExceptionService resolution. Reapplied on
  read so changed identity rules continue to work without refetching Sophos.

Normalized records also retain Sophos ID, MIME ID/list, message key and raw offsets.
Raw Detail adds all related original events using the message key, with no row cap.
Neither normalized rows nor Raw Detail remove events from the Raw cache.

## Existing consumers and index transition

Transfer canonical columns and design remain unchanged. The existing failed-row
class also recognizes English Failed/Partial Failed; no CSS, tab or card was added.
EventListIndex freshness, source inference, snapshots and fetch/smart/range/full
indexing now recognize the normalized Sophos source. Raw cache is not separately
indexed as mail events. Old MailScreen source metadata remains recognized.

Current list/count queries exclude known MailScreen-derived index rows. During the
first smart cycle, the Legacy manifest marker causes those derived rows to be removed
from Current event/timeline/sensitive indexes without touching Legacy source files.
Fetcher-first upgrades perform the same cleanup before saving the new manifest.
Previously created timeline indexes retain Legacy Raw hydration until rebuilding;
new timeline collectors/rebuilds use Current only.

On deployment, perform General -> full cache indexing once after the first Sophos
Outbound refresh, especially if older indexes lack source-file metadata or if historical
index coverage should change immediately. Subsequent normal Fetcher/smart cycles use
changed-file indexing. Dashboard summary cache version is incremented so old aggregate
counts are not reused. Displayed mail counts use normalized messages, not event rows.

Report adapts canonical rows to the unchanged PDF renderer field names/layout.
The renderer recognizes English success/failure states; Partial Failed belongs in the
existing failure count. No separate approval data is fabricated. Timeline, XLSX Export,
Dashboard and Learner continue through the existing canonical/index interfaces.
Sensitive Files has no new Outbound attachment records while attachment is unavailable;
this is intentional, not a fallback to Legacy attachments.

## Changed files

- backend/clients/sophos.py: XDR query/poll/retry/cursor collection and safe errors.
- backend/services/sophos_outbound.py: grouping, canonical normalization and Raw linkage.
- backend/services/refresh.py: Current collector, per-day commit/lock, explicit Legacy entry.
- backend/services/transfers.py: Current canonical/Raw reader, shared identity enrichment, Legacy reader.
- backend/services/event_list_index.py: Current source path and exclusion of Legacy-derived counts/rows.
- backend/services/indexing.py: Current inference/snapshots/incremental updates and Legacy transition cleanup.
- backend/services/report.py: canonical-to-PDF field adapter.
- backend/services/legacy_report.py: English delivery state aggregation compatibility.
- backend/services/timeline.py: Current bounds and retained Legacy-index Raw hydration.
- backend/services/dashboard.py: aggregate cache-version transition.
- backend/app.py: Current Outbound cache status path.
- frontend/src/pages/TransferPage.tsx: same failed-row styling for English states.
- tests/test_sophos_outbound_client.py: HTTP/auth/date/poll/retry/pagination tests.
- tests/test_sophos_outbound_flow.py: normalization, persistence, legacy protection and consumer integration tests.
- tests/test_transfer_service.py: Current-source fixture for the existing canonical list/filter test.
- docs/sophos-current-outbound.md: behavior and operational verification.

## Local verification

Targeted command:

```sh
.venv/bin/pytest -q tests/test_sophos_outbound_client.py tests/test_sophos_outbound_flow.py tests/test_sophos_client.py tests/test_refresh_service.py tests/test_indexing_service.py tests/test_event_list_index.py tests/test_transfer_service.py tests/test_report_service.py tests/test_timeline_service.py tests/test_sensitive_service.py tests/test_email_security_service.py tests/test_fetcher_agent.py tests/test_scheduler_dispatch_e2e.py tests/test_dashboard_service.py
```

111 passed. Includes 2000+2000+745 rows, retry boundaries, all delivery states,
cache rollback, missing IDs, explicit Legacy collection, smart/fetch migration,
actual PDF/XLSX, Dashboard message count and Learner consumption.

Whole suite `.venv/bin/pytest -q`: 952 passed, 2 pre-existing failures, 1 warning.
- test_scheduler_runs_every_target_then_index: existing ScheduledIndex test double has no mode attribute.
- test_search_all_is_not_limited_by_timeline_group_item_cap: existing indexed Timeline search returns 100 of 150 same-group events.

Frontend `npm run typecheck` and `npm run build` passed (existing large-chunk build warning).
`git diff --check` passed. No new Python dependency. No live Sophos/production requests,
no credentials inspected.

## Production verification still required

Confirm tenant XDR entitlement and the adHocQuery body against the deployed Sophos API,
then verify run terminal status, pages.nextKey/item totals, KST day-edge coverage and
normalized Sophos ID counts against Central. The ~4779/~1465 figures supplied are
reference observations, not asserted production counts from this development environment.
Verify header_from/reason_list variants in real data and compare per-recipient delivery
semantics when the same recipient has multiple attempts. Attachment detail and
xdr_xge_att_data collection are intentionally not implemented in this scope.
