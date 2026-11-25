# Firewall workbook: Interface, Zone and Gateway configuration

## Scope and API calls

This extends the existing FirewallRule/NATRule/UnicastRoute export using the exact
Interface, Alias, Zone and GatewayConfiguration contract supplied on 2026-11-25.
FirewallClient.get() retains its authenticated read-only XML transport; those four
entities are added to its allowlist. No new credentials, client, cache DB, frontend
menu/button/CSS or configuration write is introduced.

FirewallRuleExportService.build() invokes
firewall_network_export.collect_network_sheets() after the existing NAT/Route
collection. Each selected device's existing FirewallClient is reused. Interface,
Alias, Zone and GatewayConfiguration are each queried once, sequentially. Alias
inheritance, Zone membership and cross-sheet references do not trigger more calls.
New section ordering follows Cloud, Seoul, Icheon, Anseong; unselected devices are
not queried, preserving the original selection behavior.

## Changed files

- backend/services/firewall.py: four entities in the existing Get allowlist.
- backend/services/firewall_network_export.py: parsers, CIDR helper, cross-entity joins,
  per-device collection/failure isolation and three new sheet specs.
- backend/services/firewall_rule_export.py: connect those specs and additive counts.
- backend/services/spreadsheet.py: optional merged section notes, freeze through the
  first header, and preservation of boundary whitespace in section text cells.
- tests/test_firewall_network_export.py: 38 new parser/transport/workbook/error tests.
- tests/test_firewall_rule_export.py: existing fixtures, sheet/request expectations
  extended to the new feature; original assertions remain.
- tests/test_firewall_nat_route_export.py: existing count/sheet/request expectations
  extended; Rule/NAT/Route parser assertions retained.
- docs/firewall-network-export.md: this implementation and validation record.
- docs/maintenance-todo.md: explicitly separate, unimplemented Monitor stop-script task.

## Interface and Alias

parse_interfaces() reads direct record fields Name, Hardware, NetworkZone,
IPv4Assignment, IPAddress, Netmask, GatewayName, GatewayIP, InterfaceStatus, Status,
InterfaceSpeed, AutoNegotiation, MTU and MACAddress. Source records use Type=Physical.
IP Family is determined only when the actual IPAddress parses as a valid IP address,
not from enable flags or naming guesses. Other optional fields including MSS do not
cause errors or invent values when absent; fields outside the requested columns
are not added to the workbook.

parse_aliases() reads Name, Interface, IPFamily, IPAddress and Netmask with Type=Alias.
Parent Interface remains the raw Interface value. The parent's Zone is inherited
by exact match against already received Interface Name/Hardware values. An absent
parent leaves Zone blank. Hardware, assignment, gateway, status and other physical-
only Alias cells stay blank; they are not inherited from the parent.

Only returned entity records are rows. Scalar or nested Interface references such
as BreakoutMembers/Interface are not promoted to additional physical records.
No Interface is fabricated from UI labels, Zone names or Alias parents.

CIDR uses ip_interface(), preserving the host IP: 192.0.2.201 plus 255.255.255.0
becomes 192.0.2.201/24, not the network address. Invalid address/mask leaves CIDR
blank while IP Address and Netmask stay unchanged. NAT/Route CIDR behavior is not
modified.

Columns: Name, Type, Parent Interface, Hardware, Zone, IP Family, IPv4 Assignment,
IP Address, Netmask, CIDR, Gateway Name, Gateway IP, Interface Status, Status,
Interface Speed, Auto Negotiation, MTU, MAC Address.

## Zone

parse_zones() exports all returned Zone records, including LOCAL, Discover, VPN
and WiFi. Name/Type/Description are preserved. Device Access includes only Enable
services from the supplied ApplianceAccess categories and uses the requested
human-readable labels. Disable or absent services produce no entry. A missing
ApplianceAccess produces a blank cell, not a synthetic default.

Members is the unique physical Interface Name list matched exactly by NetworkZone.
Alias rows are excluded, even when supplied to the parser. Empty membership is
valid. No xfrm/wireless/GuestAP or other additional entity lookup is used to fill it.

Columns: Name, Type, Members, Device Access, Description.

## Gateway configuration

parse_gateways() reads GatewayConfiguration/Gateway and preserves direct Name,
IPFamily, IPAddress, Type and Weight. Interface Gateway Name/Gateway IP values are
not rewritten to force a match; original object names provide the cross-sheet link.

GatewayFailoverTimeout belongs to the whole device configuration. Each device's
section note is `Gateway Failover Timeout : 60 sec` (using the received value), above
its table and outside all Gateway rows. Missing timeout creates no guessed note;
zero is preserved as zero. Successful zero gateways still have a section/No data.

Each FailOverRules/Rule contributes one slot in all four parallel newline-separated
columns: Protocol, Target(IPAddress), Port and Condition. Empty slots are retained,
including an empty first Condition followed by a later condition; XML whitespace
preservation prevents trimming that relationship. Missing rules leave all four cells
blank. The Gateway's own IP is never substituted for a missing failover target.

Columns: Name, IP Family, Gateway IP, Type, Weight, Failover Protocol, Failover Target,
Failover Port, Failover Condition. No runtime Up/Down, Usage, RTT or Loss is inferred.

## Failure and empty data behavior

The four API calls are isolated independently. Successful Interface records survive
Alias failure, and successful Alias records survive Interface failure (with blank
inherited Zones). Partial Interface sections show safe failure notes above the table.
If no rows are available and an API failed, the body says 조회 실패 rather than No data.
If Interface failed but Zone succeeded, the Zone table remains and a note explicitly
states that Members could not be determined. Zone/Gateway failures affect only their
own sections. All failures also enter the existing Export Errors sheet with entity,
error type and safe diagnostic. The existing credential-safe formatter is reused;
no upstream exception message, request XML/URL, password or credential is included.

The existing count fields remain unchanged. interfaceCounts counts displayed physical
plus Alias rows, aliasCounts the Alias subset, zoneCounts/gatewayCounts successful
entity rows. Missing failed entities are not
misrepresented as successful zero-query results; error records and partial notes
accompany the available counts.

## Workbook and regression guarantees

The new last three sheets are Interface, Zone and Gateway. Each selected device has
its own title and uniquely named Table/Auto Filter, e.g. tbl_interface_cloud,
tbl_zone_cloud, tbl_gateway_cloud. Alias has no separate sheet. Exactly one empty
row separates the end of each device's table from the next title. Notes are outside
the Table and merged using existing body styling. Titles keep the existing header
style. Maximum column width remains 60; cells wrap and align top.

Freeze panes follow the existing principle of keeping the first title/header visible:
A3 normally, A4 when a timeout/error note adds a row before the first header. Existing
NAT/Route panes remain A3. No per-table freeze panes are attempted.

With complete successful fixtures, there are 12 worksheets and 20 independent tables.
All previous 9 worksheet XML parts and the entire style XML are byte-identical to the
pre-extension workbook. Existing rule classification, NAT fields/links, Route fields,
master order and existing Export Errors placement policy are preserved.

## Validation

Targeted tests:

```sh
.venv/bin/pytest -q tests/test_firewall_network_export.py tests/test_firewall_rule_export.py tests/test_firewall_nat_route_export.py tests/test_firewall_export_sections.py tests/test_common_xlsx_style.py
```

111 passed, including 38 new tests. Tests cover all supplied service labels,
Physical/Alias mapping and optional fields, invalid host CIDR, parent absence,
physical-only Zone members, all returned Zone names, Gateway global metadata,
multiple/absent failover rules, empty Condition alignment, success-empty vs error,
partial data retention, no credentials in errors, request counts and actual XLSX.

Full suite: 1068 passed, 2 pre-existing failures, 1 deprecation warning (40.45s).
Unchanged failures are Scheduler test-double mode missing and Timeline same-group
150/100 count mismatch. No new passing-test regression was found.

A temporary openpyxl reader loaded the actual generated workbook: 12 sheets,
20 filtered tables, Alias WAN inheritance, physical-only Members, unchanged
PortB_GW references, one timeout note per device and a leading-empty Condition slot
all verified. The reader is a /tmp-only validation tool, not a new production dependency.
Native Microsoft Excel was not available. No production firewall call was performed.

## Explicit exclusions and separate TODO

No XFRM/IPsec/Wireless/GuestAP/WiFi6/RED/VLAN/LAG lookup, live gateway status, SD-WAN,
BGP or OSPF is implemented. Values directly returned by the four requested entities
are preserved without inventing additional interfaces.

stop_system_monitor.bat remains untouched. Its requested process-stop improvements
are retained separately in maintenance-todo.md, not implemented in this export change.

