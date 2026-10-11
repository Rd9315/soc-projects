# Testing and validation

Run the automated tests:

```bash
python -m unittest discover -s tests -v
```

Run the sample dataset:

```bash
python src/soc_triage.py --input data/sample_events.csv --out reports
```

Optional dashboard:

```bash
python -m pip install -r requirements-dashboard.txt
streamlit run src/dashboard.py
```

Optional EVTX parser dependency:

```bash
python -m pip install -r requirements-evtx.txt
```

## Validation checklist
- [ ] Confirm Windows audit policy and provider/channel for each event.
- [ ] Test with benign admin activity as well as suspicious synthetic examples.
- [ ] Tune thresholds to the environment before using the rules operationally.
- [ ] Check timestamps/timezones and retain original evidence.
- [ ] Verify Sigma rules with a Sigma validator and adapt correlations to the target SIEM.
