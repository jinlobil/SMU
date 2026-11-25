# Firewall Rule workbook: NAT and Static Route extension

## Confirmed API contract

Implementation follows the SFOS fields supplied by the operator on 2026-11-25.
No NAT entity guessing, alternate NAT module fallback, new authentication client,
or firewall write operation is used. The existing FirewallClient.get() allowlist
now includes NATRule and issues the same authenticated XML Get as other entities.

No production firewall was accessed. The operator-provided schema, deidentified
mock XML and local workbook validation are the evidence used in this implementation.

## Files

- backend/services/firewall.py: allow NATRule through the existing read transport.
- backend/services/firewall_nat.py: NAT_COLUMNS and parse_nat_rules.
- backend/services/firewall_routes.py: shared parse_unicast_routes and route_cidr.
- backend/services/firewall_path_check.py: import the shared route parser; Path Check matching unchanged.
- backend/services/firewall_rule_export.py: reuse parsed rules/client, collect NAT/Route, build sections, isolate/sanitize errors.
- backend/services/spreadsheet.py: optional section worksheets with independent OOXML tables and appended top-alignment style variants.
- tests/test_firewall_rule_export.py: retain original tests; extend successful mocks/expected sheet and request lists for the new feature.
- tests/test_firewall_export_sections.py: shared route parser, CIDR, spacing/table/OOXML/style regression.
- tests/test_firewall_nat_route_export.py: observed NAT/Route field contracts and integrated export/error regression.
- docs/firewall-nat-route-export.md.

## NAT parsing

Entity: NATRule. Direct scalar fields are read only from the NAT record, so After/Name
cannot be mistaken for the rule Name. Original lists and interface lists are read
from their direct containers and newline-joined without dropping distinct members.
All optional fields remain blank if omitted. Missing networks/services are not
converted to Any. MASQ, Original, object names, Enable/Disable and Top/After are
preserved as supplied; no numeric ordering is synthesized. Internal description
line breaks are retained.

| Excel column | XML field |
|---|---|
| Rule Name | Name |
| Status | Status |
| IP Family | IPFamily |
| Position | Position |
| After Rule | After/Name |
| Original Source | OriginalSourceNetworks/Network |
| Original Destination | OriginalDestinationNetworks/Network |
| Original Service | OriginalServices/Service |
| Translated Source | TranslatedSource |
| Translated Destination | TranslatedDestination |
| Translated Service | TranslatedService |
| Inbound Interface | InboundInterfaces/Interface |
| Outbound Interface | OutboundInterfaces/Interface |
| Linked Firewall Rule | LinkedFirewallrule, then exact-name reverse mapping |
| NAT Method | NATMethod |
| Health Check | HealthCheck |
| Override Interface NAT | OverrideInterfaceNATPolicy |
| Description | Description |

A non-empty LinkedFirewallrule other than None wins. Otherwise the NAT Name is
matched exactly against existing parsed Firewall Rule `Linked NAT` values.
All distinct corresponding Firewall Rule names are newline-joined. Substring
matching is not used, and a comma in an object/rule name is not treated as a delimiter.
Rules are never fetched again for this calculation. When rule collection failed,
only an actual direct link can be displayed; missing links are left blank.

## Static Route parsing

Entity: UnicastRoute. Export and Path Check use the same parser, now in
firewall_routes.py; firewall_path_check.parse_unicast_routes remains importable.
The parser supports the existing Destination/Network aliases and prioritizes the
observed DestinationIP. IPFamily is retained internally. Distance and
AdministrativeDistance are independent values, with no fallback from one into the
other. Blackhole and Status are preserved, including Status=ON.

Route columns, in order:

Destination, Netmask, CIDR, Gateway, Interface, Distance, Administrative Distance,
Status, Blackhole, Description.

CIDR uses IPv4Network(destination/netmask, strict=False), accepting IPv4 dotted
masks or numeric prefixes. Invalid masks/addresses leave CIDR blank while preserving
the original Destination and Netmask. No missing-mask /32 is invented by Export.
Empty Gateway/Description are valid. PortA/PortB/xfrm1/xfrm2/xfrm3 are strings, never
used to infer a gateway or reject a route. Path Check longest-prefix selection and
its existing default-route behavior remain unchanged.

## Collection and failure isolation

Existing selected-firewall semantics and master-sheet ordering are unchanged.
The same FirewallClient instances and parsed rules are retained in memory. After
the existing rule/object collection, selected devices are queried once each for
NATRule and once each for UnicastRoute, sequentially. New-section order is always
Cloud, Seoul, Icheon, Anseong, restricted to the devices selected by the user.
No unselected device is contacted. The existing FirewallRule/SecurityPolicy
compatibility fallback is unchanged.

An individual NAT/Route exception, malformed XML or API error status affects only
that device/entity section. Other devices and the other entity continue. The section
contains `조회 실패 · Entity: safe diagnostic`; the existing Export Errors sheet
also records firewall, entity/error type and safe diagnostic. Details are restricted
to API code, exception type or fixed timeout text. Upstream exception messages,
response bodies, URLs and request/Login XML are not placed in Excel, progress or logs.
The same sanitization protects existing rule/enrichment failure output.

Successful zero-row sections contain No data. Counts are computed before placeholders:
existing counts/analysisCounts retain their meaning; natCounts and routeCounts are
added. A zero key means successful empty data; a failed device/entity has an error
entry and is omitted from that entity's success counts.

## Workbook layout

The existing master and LAN ↔ OFFICE / LAN ↔ WAN / ETC sheet data, columns and XML
remain unchanged. NAT and Route are the last two worksheets. Export Errors, when
present, retains its prior position after the analysis sheets and before the new
sheets. No frontend menu, button or CSS was added.

Each selected device receives title, header and data (or one No data/error row),
then exactly one fully empty row before the next title. No trailing separator is
added. Titles are merged across the table width. Tables exclude titles and empty
separator rows. Names are tbl_nat_cloud / tbl_route_cloud etc., unique across the
workbook. Each table has its own autoFilter; no conflicting worksheet-wide filter
is added to NAT/Route.

Both sheets freeze at A3 (the first title/header stay visible). Column widths use the
existing 10–60 bound. All new-section cells wrap and align top. Fonts, colors and
borders reuse existing ledger models; their top-alignment variants are appended so
existing style indices and sheet XML remain unchanged. Ordinary writer callers
without sections retain their existing output behavior.

## Verification

```sh
.venv/bin/pytest -q tests/test_firewall_nat_route_export.py tests/test_firewall_rule_export.py tests/test_firewall_export_sections.py tests/test_firewall_path_check.py tests/test_common_xlsx_style.py
```

118 passed. Coverage includes SNAT, DNAT, source-restricted DNAT, absent optional
tags, multiple lists, Original/MASQ/object values, direct and multi-rule reverse
links, Top/After, multiline descriptions, empty NAT, DestinationIP, /12 /16 /22 /23
/24 /28 /32 CIDRs, invalid masks, xfrm empty gateways, distinct distances, ON,
Blackhole, empty routes, entity/device failures, credentials in exceptions, request
counts, selected-device ordering and the actual generated workbook.

Full suite: 1030 passed, 2 pre-existing failures, 1 deprecation warning (41.27s).
Existing failures remain Scheduler test-double mode missing and Timeline same-group
150/100 result mismatch. Neither was changed.

ZIP/XML/relationship/table parts were validated. All seven existing sheet XML
parts matched a pre-extension workbook byte for byte. Original cell-style models
were compared unchanged; eight independent table/filter parts were checked.
A separate temporary openpyxl reader loaded the generated 9-sheet/8-table workbook
and verified filters, A3 panes and Distance=4 / Administrative Distance=9. It emitted
only the same missing-default-style warning as the pre-existing writer. openpyxl was
installed under /tmp for validation only; no production dependency was added.
Microsoft Excel itself was not available for a native application open test.

Remaining operational verification: run the existing Export against the actual
selected devices and confirm their provided schema/version and policy values.
No API field-definition blocker remains after the supplied NATRule/UnicastRoute
contract. Unsupported route families and SD-WAN/dynamic/BGP/OSPF/precedence/config
backup are outside this task.
