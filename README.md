# Snort to MITRE Mapping Toolkit

This toolkit contains a set of Python scripts used to map Snort intrusion detection rules to the [MITRE ATT&CK](https://attack.mitre.org/) framework using heuristic methods, and then verify the integrity and completeness of the resulting mappings.

## Scripts

### `snortToMitre.py`

This is the **main script**. It performs the following tasks:
- Downloads MITRE ATT&CK tactics, techniques, and subtechniques.
- Parses a Snort rules file.
- Uses heuristic methods to map Snort rules to relevant MITRE ATT&CK tactics and techniques.
- Outputs the results in a structured JSON format.

---

### `checkDuplicates.py`

This script:
- Reads the JSON file produced by `snortToMitre.py`.
- Checks for any duplicate mappings (i.e., multiple rules matching the same tactic/technique).
- Helps identify redundant or overly broad heuristics in rule matching.

---

### `checkProcessedRules.py`

This script:
- Verifies that all Snort rules were processed by checking their `RuleIndex`.
- Compares the set of rule indices found in the JSON file with the expected sequence (typically `1` to `N`).
- Reports any missing indices, which likely correspond to skipped or unprocessed rules.

---

## Usage

1. Download and install MITRE python scripts - Python3 required!!:
   ```bash
   pip install mitreattack-python

2. Download snort rules (snort3-community.rules) and paste the file in the root directory.

3. Run the mapping process:
   ```bash
   python snortToMitre.py
