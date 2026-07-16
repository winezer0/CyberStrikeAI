# Asset Management

[中文](../zh-CN/asset-management.md)

Asset management consolidates domains, IP addresses, ports, and services discovered through manual entry, FOFA, HTTP APIs, and Agent tasks into a maintainable baseline. It answers three questions: what assets exist, which assets have been assessed, and where risk is concentrated.

> This feature is designed for security testing and attack-surface governance. It is not a replacement for a full enterprise CMDB. Add and scan only systems you own or are explicitly authorized to test.

## Overview

Asset management provides three main views:

- **Overview**: asset totals, IPs, domains, ports, recent changes, scan coverage, and protocol distribution.
- **Asset inventory**: identity, service details, source, tags, project ownership, scan history, and risk state.
- **Reconnaissance**: search FOFA and save confirmed results individually or in batches.

Assets can launch single-target analysis or batch scans. After an Agent records findings and completes the scan callback, the inventory displays related vulnerability counts, risk level, and latest scan time.

## Asset fields

An asset can include:

- host, IP address, domain, port, and protocol;
- page title and service or product fingerprint;
- country/region, state/province, and city;
- source, source query, and tags;
- active or inactive status;
- project and owner;
- first seen, last seen, created, and updated timestamps;
- latest scan time and linked conversation, task queue, and subtask;
- related vulnerability count and current risk level.

At least one of `host`, `ip`, or `domain` is required.

## Build an asset baseline

### Add an asset manually

Go to **Asset Management → Asset Inventory** and select **Add Asset**. Supported target forms include:

```text
https://example.com:8443
example.com
192.0.2.10:443
[2001:db8::1]:443
```

The system attempts to identify the URL, domain, IP address, port, and protocol. You can then add a project, tags, title, service fingerprint, location, and status.

### Import from FOFA

1. Configure the FOFA email and API key in settings or the configuration file. You can also use the `FOFA_EMAIL` and `FOFA_API_KEY` environment variables.
2. Open **Asset Management → Reconnaissance**.
3. Enter or generate a FOFA query and confirm its scope.
4. Run the query, select results whose ownership has been verified, and choose **Save Selected**.
5. Review the created, updated, and skipped counts.

Internet search results are not automatically your assets. Narrow the query with organization domains, certificates, network ranges, or product fingerprints, then verify authorization before saving results.

## Normalization and deduplication

Different sources may describe the same target in different forms. The system:

- trims surrounding whitespace;
- normalizes IP addresses, domains, and protocols to lowercase;
- extracts hostname, protocol, and port from URL-like hosts;
- fills default HTTP/HTTPS ports when omitted;
- converts internationalized domains to ASCII/Punycode;
- removes empty or duplicate tags;
- supplies default source and status values.

Assets use “target + port + protocol” as the service-level deduplication key. The preferred target is the domain, followed by the IP address, then the host. As a result, `80/http` and `443/https` on the same host remain separate assets.

When an existing asset is imported again, non-empty incoming fields and the last-seen time are updated. Existing fields omitted by the new record and the original first-seen time are preserved.

## Search and filters

The Web UI searches hosts, IP addresses, domains, titles, services, and tags, with status and project filters. The backend and Agent tools additionally support:

- source, tags, port, and protocol;
- scanned and never-scanned states;
- first-seen, last-seen, and latest-scan time ranges;
- allowlisted sort fields such as latest scan time;
- paginated queries.

Sorting by latest scan time in ascending order places never-scanned assets first, making coverage gaps visible.

## Scanning and risk updates

### Scan one asset

Select **Scan** from the asset inventory. The system:

1. creates a conversation containing the target and asset ID;
2. links the conversation to the asset;
3. prompts the Agent to inspect exposed services and authorized risks;
4. stores confirmed findings with `record_vulnerability`;
5. updates scan state with `complete_asset_scan`.

Scan prompts support `{{asset_id}}`, `{{target}}`, `{{host}}`, `{{ip}}`, `{{domain}}`, and `{{port}}`. Adjust scope, ports, test intensity, and validation methods to match the authorization before starting.

### Batch scans

Select multiple assets and choose **Create Scan Task**. The system creates one subtask per asset and links each asset to its queue and subtask.

The current defaults use manual scheduling, one concurrent task, and Eino single-Agent mode to limit load on targets and the local host. You must still confirm the test window, request rate, permitted validation methods, and approval requirements.

### Risk calculation

Asset risk is calculated dynamically from open vulnerabilities in the latest linked scan:

- `critical`, `high`, `medium`, `low`, or `info`: an open finding at that level exists;
- `normal`: the asset was scanned and has no open risk;
- `unassessed`: no scan has completed.

Resolved, false-positive, and ignored findings remain in historical counts but no longer increase the current risk level.

## Agent tools

Six built-in tools expose asset operations to Agents:

- `create_asset`: create or deduplicate and update an asset;
- `get_asset`: retrieve full details by ID;
- `query_assets`: filter, sort, and paginate assets;
- `update_asset`: partially update an asset;
- `delete_asset`: delete an asset;
- `complete_asset_scan`: record scan completion.

`query_assets` returns 20 summaries by default and allows at most 50 per page. Use `get_asset` for full details so large inventories do not consume the model context.

## Access control

Asset permissions are separated into:

- `asset:read`: view assets and statistics;
- `asset:write`: create, import, edit, and update scan state;
- `asset:delete`: delete assets.

Server-side authorization considers the asset owner, explicit resource assignments, the linked project, and permission scope (`all`, `assigned`, or `own`). When a conversation is linked to a project, Agent asset queries are restricted to that project and tool arguments cannot widen the boundary.

## Recommended workflow

1. Define an explicitly authorized set of domains, IP addresses, or network ranges.
2. Add a few critical targets manually and verify normalization and deduplication.
3. Use tags to separate production, testing, critical-business, and internet-facing scopes.
4. Configure FOFA, begin with narrow queries, and verify ownership.
5. Test scanning and vulnerability callbacks on one low-risk target.
6. Use never-scanned and over-30-day filters to identify coverage gaps.
7. After validating the workflow, expand gradually with small batch tasks.

A small, verified baseline is usually more valuable than a large inventory with unclear ownership and inconsistent sources.
