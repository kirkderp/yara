# kirkderp/yara - YARA Rules from derp.ca

YARA rules published alongside research on [derp.ca](https://www.derp.ca), a malware C2 tracker and threat intelligence project tracking active malware infrastructure.

Each rule lives in its own directory with a README.md that serves as the associated research post, including full analysis, IOCs, and detection guidance.

## Rules

| Directory | Family | Type |
|---|---|---|
| [vidar_v1_5_go](vidar_v1_5_go/) | Vidar v1.5 | Go-based infostealer |
| [eimeria_multi_stage_loader](eimeria_multi_stage_loader/) | Eimeria | Five-layer loader chain (RAR5 -> RunPE) |

## Rule Format

All rules follow the CCCS YARA validator standard and include YARAhub-compatible metadata:

```
meta:
    id = "<base62-uuid>"
    version = "1.0"
    date = "YYYY-MM-DD"
    status = "RELEASED"
    sharing = "TLP:CLEAR"
    author = "derp.ca"
    category = "MALWARE"
    triage_score = <0-10>
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "<md5>"
```

## Deployment

Rules are automatically deployed to:

- [YARAify](https://yaraify.abuse.ch/) (abuse.ch)
- [Triage](https://tria.ge) (hatching.cloud)
- This GitHub repository

## About derp.ca

[derp.ca](https://www.derp.ca) tracks malware C2 infrastructure and publishes technical malware analysis.
