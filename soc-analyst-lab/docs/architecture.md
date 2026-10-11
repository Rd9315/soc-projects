# Architecture

```text
CSV input ──> parser / timestamp normalization ──> detection rules
                                                    │
                                                    v
                                          normalized findings
                                             /          \
                                            v            v
                                      findings.json  incident_summary.md
                                            |
                                            v
                                      optional dashboard
```

## Design decisions
- The core analyzer uses the Python standard library so the basic workflow has no runtime dependencies.
- EVTX support is optional because it needs an additional package; the adapter retains raw XML for follow-up review.
- The dashboard is optional and reads generated JSON rather than owning the detection logic.
- Findings are leads for investigation. Rules do not automatically declare compromise or take containment actions.
