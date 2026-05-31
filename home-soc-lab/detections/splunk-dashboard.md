# Splunk Home SOC Dashboard

Build in **Dashboards → Create Dashboard → New Dashboard** named `Home_SOC_Lab`.

## Panel 1 — Alerts by MITRE (24h)

```spl
index=sysmon OR index=wineventlog
[| inputlookup attack_notables.csv | fields rule_name
| rename rule_name as search
| format]
| stats count by mitre_id
| sort - count
```

Simpler lab version — alert count from saved searches:

```spl
index=sysmon earliest=-24h
| eval mitre_id=case(
    match(CommandLine,"EncodedCommand"),"T1059.001",
    match(TargetObject,"\\Run"),"T1547.001",
    DestinationIp="192.168.56.20","T1048.003",
    true(), "other")
| stats count by mitre_id
```

## Panel 2 — Top hosts

```spl
index=sysmon OR index=wineventlog earliest=-24h
| stats count by host
| sort - count
```

## Panel 3 — Sysmon volume timeline

```spl
index=sysmon earliest=-24h
| timechart span=1h count by EventCode
```

## Panel 4 — Real-time notables (single value + table)

**Table:**

```spl
index=sysmon OR index=wineventlog earliest=-15m
| eval alert=case(
    EventCode=1 AND match(CommandLine,"(?i)EncodedCommand"), "DET-EX-001",
    EventCode IN (12,13) AND match(TargetObject,"\\Run"), "DET-PE-001",
    EventCode=3 AND DestinationIp="192.168.56.20", "DET-EXF-001",
    EventCode=1 AND match(Image,"\\Downloads\\"), "DET-IA-001",
    EventCode=4698, "DET-PE-002",
    1=1, null())
| where isnotnull(alert)
| eval severity=case(alert="DET-EXF-001","High",alert="DET-EX-001","High",alert="DET-PE-001","High",1=1,"Medium")
| table _time host User alert severity Image CommandLine TargetObject DestinationIp
| sort - _time
```

## Real-time alert wiring

For each `DET-*` saved search in `detection-rules.md`:

1. Alert → **Add to Trigger** → **Per-result** or **Once** when count > 0
2. **Trigger Actions** → Log Event → `index=notable`
3. Dashboard Panel 4 searches `index=notable` if you enable:

```spl
index=notable earliest=-15m
| table _time rule_name mitre_id severity host message
| sort - _time
```

## Wazuh dashboard equivalent

- **Module**: Security Events → filter `group:attack_detected`
- **Panel**: MITRE technique from rule `description` field
- **Agent**: `WIN-VICTIM`

## Screenshot

Save dashboard full-page to `screenshots/dashboard_home_soc.png`.
