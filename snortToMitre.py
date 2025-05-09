from collections import Counter
from mitreattack.stix20 import MitreAttackData
import assignConfidenceToSnortRules as ac
import json
import os
import pandas as pd
import re
import requests

RESET = "\033[0m"
BLUE = "\033[34m"
BLUE_BOLD = "\033[1;34m"
GREEN = "\033[32m"
GREEN_BOLD = "\033[1;32m"
RED = "\033[31m"
RED_BOLD = "\033[1;31m"
YELLOW = "\033[33m"
YELLOW_BOLD = "\033[1;33m"

# MITRE heuristic keyword-to-technique mapping
MITRE_KEYWORDS = [
  # {
  #   # Credential Access
  #   'mimikatz': ('Credential Access', 'T1003'),
  #   'password': ('Credential Access', 'T1555'),
  #   'hashdump': ('Credential Access', 'T1003'),
  #   'creds': ('Credential Access', 'T1555'),

  #   # Execution
  #   'powershell': ('Execution', 'T1059.001'),
  #   'cmd': ('Execution', 'T1059.003'),
  #   'shell': ('Execution', 'T1059'),
  #   'wscript': ('Execution', 'T1059.005'),
  #   'bind': ('Execution', 'T1203'),

  #   # Persistence
  #   'autorun': ('Persistence', 'T1547.001'),
  #   'registry': ('Persistence', 'T1547.001'),
  #   'backdoor': ('Persistence', 'T1055'),
  #   'qaz': ('Persistence', 'T1059'),
  #   'scheduled': ('Persistence', 'T1053'),

  #   # Privilege Escalation
  #   'overflow': ('Privilege Escalation', 'T1068'),
  #   'elevation': ('Privilege Escalation', 'T1068'),
  #   'sudo': ('Privilege Escalation', 'T1548'),
  #   'solaris': ('Privilege Escalation', 'T1068'),
  #   'linux': ('Privilege Escalation', 'T1068'),
  #   'setuid': ('Privilege Escalation', 'T1548.001'),

  #   # Defense Evasion
  #   'obfuscation': ('Defense Evasion', 'T1027'),
  #   'encoded': ('Defense Evasion', 'T1027.002'),
  #   'bypass': ('Defense Evasion', 'T1562'),
  #   'packer': ('Defense Evasion', 'T1027.002'),

  #   # Discovery
  #   'scan': ('Discovery', 'T1046'),
  #   'enumeration': ('Discovery', 'T1046'),
  #   'named': ('Discovery', 'T1046'),
  #   'netstat': ('Discovery', 'T1049'),
  #   'query': ('Discovery', 'T1018'),

  #   # Lateral Movement
  #   'smb': ('Lateral Movement', 'T1021.002'),
  #   'psexec': ('Lateral Movement', 'T1570'),
  #   'remote': ('Lateral Movement', 'T1021'),

  #   # Collection
  #   'keylogger': ('Collection', 'T1056.001'),
  #   'clipboard': ('Collection', 'T1115'),

  #   # Exfiltration
  #   'ftp': ('Exfiltration', 'T1048'),
  #   'http': ('Exfiltration', 'T1048.003'),
  #   'dns': ('Exfiltration', 'T1048.002'),

  #   # Command and Control
  #   'cobaltstrike': ('Command and Control', 'T1219'),
  #   'netbus': ('Command and Control', 'T1219'),
  #   'deepthroat': ('Command and Control', 'T1219'),
  #   'shaft': ('Command and Control', 'T1095'),
  #   'gatecrasher': ('Command and Control', 'T1219'),
  #   'stacheldraht': ('Command and Control', 'T1095'),
  #   'tfn': ('Command and Control', 'T1095'),
  #   'trin00': ('Command and Control', 'T1095'),
  #   'mstream': ('Command and Control', 'T1095'),
  #   'irc': ('Command and Control', 'T1071.001'),
  #   'beacon': ('Command and Control', 'T1071'),

  #   # Impact
  #   'ddos': ('Impact', 'T1499'),
  #   'kill': ('Impact', 'T1489'),
  #   'wipe': ('Impact', 'T1485'),

  #   # Initial Access
  #   'exploit': ('Initial Access', 'T1203'),
  #   'phishing': ('Initial Access', 'T1566'),
  #   'trojan': ('Initial Access', 'T1204'),
  #   'infector': ('Initial Access', 'T1204.002'),

  #   # Collection/Recon Tools
  #   'nmap': ('Discovery', 'T1046'),
  #   'nessus': ('Discovery', 'T1046'),
  #   'portscan': ('Discovery', 'T1046'),

  #   # Miscellaneous
  #   'rootkit': ('Defense Evasion', 'T1014'),
  #   'logger': ('Collection', 'T1056'),
  #   'shellcode': ('Execution', 'T1059'),
  #   'admin': ('Privilege Escalation', 'T1078')
  # }
]

CONFIDENCE_SCORE = [
  # {
  #   "Technique/Subtechnique": "Exploitation for Public-Facing Application",
  #   "Technique ID": "T1190",
  #   "Confidence Score": 95,
  #   "Tactics Involved": ["Initial Access"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Protect", "Detect"],
  #   "Description": "Exploiting vulnerabilities in externally accessible applications."
  # },
  # {
  #   "Technique/Subtechnique": "Credential Dumping",
  #   "Technique ID": "T1003",
  #   "Confidence Score": 90,
  #   "Tactics Involved": ["Credential Access"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Harvesting credentials from local systems or remote services."
  # },
  # {
  #   "Technique/Subtechnique": "Command and Scripting Interpreter",
  #   "Technique ID": "T1059",
  #   "Confidence Score": 85,
  #   "Tactics Involved": ["Execution"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Abusing command-line interfaces to execute malicious commands."
  # },
  # {
  #   "Technique/Subtechnique": "Windows Management Instrumentation",
  #   "Technique ID": "T1047",
  #   "Confidence Score": 80,
  #   "Tactics Involved": ["Lateral Movement"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Using WMI to execute commands or gather information on remote machines."
  # },
  # {
  #   "Technique/Subtechnique": "PowerShell",
  #   "Technique ID": "T1086",
  #   "Confidence Score": 90,
  #   "Tactics Involved": ["Execution"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Using PowerShell scripts for system manipulation, often for persistence or lateral movement."
  # },
  # {
  #   "Technique/Subtechnique": "Sudo and Sudo Caching",
  #   "Technique ID": "T1169",
  #   "Confidence Score": 70,
  #   "Tactics Involved": ["Privilege Escalation"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Exploiting sudo or cached credentials to elevate privileges."
  # },
  # {
  #   "Technique/Subtechnique": "Input Capture",
  #   "Technique ID": "T1056",
  #   "Confidence Score": 80,
  #   "Tactics Involved": ["Collection"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Capturing user input from various devices to collect sensitive information."
  # },
  # {
  #   "Technique/Subtechnique": "Network Sniffing",
  #   "Technique ID": "T1040",
  #   "Confidence Score": 70,
  #   "Tactics Involved": ["Collection"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Intercepting network traffic to extract valuable data."
  # },
  # {
  #   "Technique/Subtechnique": "Exfiltration Over C2 Channel",
  #   "Technique ID": "T1041",
  #   "Confidence Score": 85,
  #   "Tactics Involved": ["Exfiltration"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Respond", "Recover"],
  #   "Description": "Using a command-and-control (C2) channel for data exfiltration."
  # },
  # {
  #   "Technique/Subtechnique": "Application Layer Protocol",
  #   "Technique ID": "T1071",
  #   "Confidence Score": 75,
  #   "Tactics Involved": ["Exfiltration"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Exfiltrating data via standard application protocols (e.g., HTTP, DNS)."
  # },
  # {
  #   "Technique/Subtechnique": "Scheduled Task/Job",
  #   "Technique ID": "T1053",
  #   "Confidence Score": 80,
  #   "Tactics Involved": ["Persistence"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Creating tasks to execute payloads at a specified time or interval."
  # },
  # {
  #   "Technique/Subtechnique": "Defacement",
  #   "Technique ID": "T1071.001",
  #   "Confidence Score": 85,
  #   "Tactics Involved": ["Impact"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Respond", "Recover"],
  #   "Description": "Altering the appearance of a website or online service to cause damage."
  # },
  # {
  #   "Technique/Subtechnique": "System Information Discovery",
  #   "Technique ID": "T1082",
  #   "Confidence Score": 75,
  #   "Tactics Involved": ["Discovery"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Gathering information about the system (e.g., OS version, hardware)."
  # },
  # {
  #   "Technique/Subtechnique": "Brute Force",
  #   "Technique ID": "T1110",
  #   "Confidence Score": 80,
  #   "Tactics Involved": ["Credential Access"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Using automated tools to guess user credentials through repeated login attempts."
  # },
  # {
  #   "Technique/Subtechnique": "Exploitation of Remote Services",
  #   "Technique ID": "T1210",
  #   "Confidence Score": 85,
  #   "Tactics Involved": ["Initial Access"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Protect", "Detect"],
  #   "Description": "Exploiting vulnerabilities in remote services to gain unauthorized access."
  # },
  # {
  #   "Technique/Subtechnique": "Spearphishing Attachment",
  #   "Technique ID": "T1193",
  #   "Confidence Score": 90,
  #   "Tactics Involved": ["Initial Access"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect", "Respond"],
  #   "Description": "Delivering malware via email attachments in targeted attacks."
  # },
  # {
  #   "Technique/Subtechnique": "Valid Accounts",
  #   "Technique ID": "T1078",
  #   "Confidence Score": 85,
  #   "Tactics Involved": ["Lateral Movement"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Using stolen or compromised valid credentials to move within the network."
  # },
  # {
  #   "Technique/Subtechnique": "Application Layer Protocol",
  #   "Technique ID": "T1071",
  #   "Confidence Score": 75,
  #   "Tactics Involved": ["Exfiltration"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Exfiltrating data using HTTP, FTP, DNS, etc., as a cover for malicious activity."
  # },
  # {
  #   "Technique/Subtechnique": "Data Staged",
  #   "Technique ID": "T1074",
  #   "Confidence Score": 75,
  #   "Tactics Involved": ["Exfiltration"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Detect"],
  #   "Description": "Preparing data for exfiltration by gathering and storing it temporarily."
  # },
  # {
  #   "Technique/Subtechnique": "System Shutdown/Reboot",
  #   "Technique ID": "T1089",
  #   "Confidence Score": 80,
  #   "Tactics Involved": ["Impact"],
  #   "Subtechnique ID": None,
  #   "NIST CSF Category": ["Respond", "Recover"],
  #   "Description": "Shutting down or rebooting systems as part of an attack's impact."
  # }
]

SNORT_TO_ATTACK = {
  # Execution
  r"cmd\.exe": [("Execution", "T1059.003", 90), ("Defense Evasion", "T1218.011", 60)],
  r"powershell": [("Execution", "T1059.001", 95), ("Defense Evasion", "T1564.001", 70)],
  r"\.bat": [("Execution", "T1059.003", 80), ("Persistence", "T1547.001", 70)],
  r".vbs|wscript|cscript": [("Execution", "T1059.005", 90), ("Persistence", "T1547.001", 60)],
  r"mshta\.exe": [("Execution", "T1218.005", 80)],
  r"rundll32": [("Execution", "T1218.011", 70), ("Defense Evasion", "T1071.001", 60)],
  r"python": [("Execution", "T1059.006", 85), ("Defense Evasion", "T1564.001", 65)],
  r"\(\)\s+\{": [("Execution", "T1059", 85)],  # Shellshock-style injection
  r"shellcode": [("Execution", "T1203", 85)],

  # Defense Evasion
  r"base64": [("Defense Evasion", "T1140", 90), ("Exfiltration", "T1041", 60)],
  r"netsh advfirewall": [("Defense Evasion", "T1562.004", 75)],
  r"vssadmin delete": [("Defense Evasion", "T1070.004", 80)],
  r"attrib\s\+h": [("Defense Evasion", "T1564.001", 70)],

  # Persistence
  r"schtasks": [("Persistence", "T1053.005", 80)],
  r"registry\W+startup": [("Persistence", "T1547.001", 90)],
  r"runonce": [("Persistence", "T1547.001", 85)],

  # Privilege Escalation
  r"token::": [("Privilege Escalation", "T1134.001", 90)],
  r"whoami": [("Privilege Escalation", "T1069.001", 70)],
  r"systeminfo": [("Privilege Escalation", "T1069.001", 60)],
  r"-froot|00|": [("Privilege Escalation", "T1068", 70)],

  # Credential Access
  r"lsass\.exe": [("Credential Access", "T1003.001", 95)],
  r"mimikatz": [("Credential Access", "T1003.001", 100)],
  r"NTDS.dit|SYSTEM hive": [("Credential Access", "T1003.003", 80)],
  r"pwdump|hashdump": [("Credential Access", "T1003", 85)],
  r"gid=": [("Credential Access", "T1003", 70)],
  r"identified by ": [("Credential Access", "T1003.001", 80)],
  r"login|passwd": [("Credential Access", "T1003", 85)],

  # Discovery
  r"net view|net group|net localgroup": [("Discovery", "T1087.001", 80)],
  r"ipconfig|arp|netstat": [("Discovery", "T1016", 75)],
  r"wmic": [("Discovery", "T1047", 70)],
  r"NTLM": [("Discovery", "T1040", 75)],

  # Lateral Movement
  r"psexec": [("Lateral Movement", "T1570", 90)],
  r"smb|445": [("Lateral Movement", "T1021.002", 90)],
  r"rdp|3389": [("Lateral Movement", "T1021.001", 85)],
  r"winrm": [("Lateral Movement", "T1021.006", 80)],
  r"ssh": [("Lateral Movement", "T1021.004", 75)],

  # Collection
  r"screen capture|screencapture": [("Collection", "T1113", 80)],
  r"keylogger": [("Collection", "T1056.001", 90)],

  # Exfiltration
  r"upload|sendto": [("Exfiltration", "T1041", 85)],
  r"dropbox|mega\.nz": [("Exfiltration", "T1567.002", 80)],
  r"http_uri.*\.php": [("Exfiltration", "T1041", 75)],

  # Command and Control (C2)
  r"ftp": [("Command and Control", "T1105", 80)],
  r"irc\.": [("Command and Control", "T1071.001", 70)],
  r"dns tunneling|dns query": [("Command and Control", "T1071.004", 85)],
  r"curl|wget|http": [("Command and Control", "T1105", 75)],
  r"DCC CHAT|DCC SEND": [("Command and Control", "T1071.001", 70)],
  r"NetBus": [("Command and Control", "T1219", 90)],

  # Impact
  r"del\s.*\*\.bak|delete shadow copies": [("Impact", "T1485", 90)],
  r"cipher /w:": [("Impact", "T1486", 80)],
  r"wiper|killdisk": [("Impact", "T1485", 95)],
  r"--backup-dir": [("Impact", "T1485", 80)],

  # Initial Access
  r"\.docm|\.xlsm": [("Initial Access", "T1566.001", 85)],
  r"macro|autoopen": [("Initial Access", "T1566.001", 80)],
  r"drive-by download|exploit kit": [("Initial Access", "T1189", 70)],
  r"phish": [("Initial Access", "T1566", 95)],
  r"%PDF-": [("Initial Access", "T1203", 80)],
  r"EMF|TWAIN": [("Initial Access", "T1203", 75)],
  r"%x %x": [("Execution", "T1203", 70)],
  r"DELETE FROM|union\s+select|where\s+\d+=\d+": [("Initial Access", "T1190", 85)],
}

def fetchMitreAttackInfo():
  file = "enterprise-attack.json"
  url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/{file}"
  r = requests.get(url)
  jsonFile = r.json()

  with open(file, "w") as f:
    json.dump(jsonFile, f)

  print(f"\nMITRE: {BLUE}{file}{RESET} has been downloaded successfully!\n")

  mitreAttackData = MitreAttackData(file)

  allTactics = mitreAttackData.get_tactics(remove_revoked_deprecated=True)
  allTechniques = mitreAttackData.get_techniques(remove_revoked_deprecated=True)

  print(f"ATT&CK tactics retrieved   : {RED_BOLD}{len(allTactics)}{RESET}")
  print(f"ATT&CK techniques retrieved: {RED_BOLD}{len(allTechniques)}{RESET}\n")

  return allTactics, allTechniques

def mapTacticsWithTechniques(allTactics):
  tacticMap = {}
  for tactic in allTactics:
    tacticId = tactic["external_references"][0]["external_id"]
    name = tactic["name"]
    tacticMap[tacticId] = name.title()
  return tacticMap

def mapTechniquesWithSubtechniques(allTechniques, tacticMap):
  techniqueMap = {}
  for technique in allTechniques:
    techniqueId = technique["external_references"][0]["external_id"]
    name = technique["name"]
    killChainPhases = technique["kill_chain_phases"]
    tactics = [phase["phase_name"] for phase in killChainPhases if phase["kill_chain_name"] == "mitre-attack"]
    tactics = [tactic.title().replace("-", " ") for tactic in tactics]
    tacticsCodes = sorted([code for code, tname in tacticMap.items() if tname in tactics])
    tacticsList = [(code, tacticMap[code]) for code in tacticsCodes]
    if "." in techniqueId:
      techniqueMap[techniqueId] = {
        "techniqueId": techniqueId.split(".")[0],
        "subtechniqueId": techniqueId,
        "name": name,
        "tactics": tacticsList,
        "confidence": 75,
      }
    else:
      techniqueMap[techniqueId] = {
        "techniqueId": techniqueId,
        "subtechniqueId": None,
        "name": name,
        "tactics": tacticsList,
        "confidence": 90,
      }
  return techniqueMap

def parseSnortRules(filePath, techniqueMap):
  results = []
  unmatchedRules = []
  ruleCounter = Counter()  # Track how many times a rule is processed
  totalRules = 0  # Variable to count the total number of rules processed
  matchedRules = 0  # Variable to count matched rules
  unmatchedRulesCount = 0  # Variable to count unmatched rules
  linesWritten = 0  # To track how many lines are written to files for each rule
  uniqueResults = set()  # To store unique entries (to avoid duplicates)
  multipleEntriesRules = []  # To store rules with multiple entries

  with open(filePath, "r", encoding="utf-8", errors="ignore") as f:
    for idx, line in enumerate(f):  # the index of each rule
      # enumerate index starts from 0 by default, +1 for the line number
      idx += 1
      line = line.strip()
      
      if not line or line.startswith("#"):
          continue
      
      totalRules += 1  # Increment total rules counter
      
      if line.startswith("alert") or line.startswith("drop") or line.startswith("reject"):
        score = ac.findRuleConfidenceByIndex(idx)

        matches = matchSnortToAttackMultilabel(line, score, techniqueMap)
        if matches:
          enrichedResults = enrichWithAttackInfo(matches)
          if len(enrichedResults) > 1:  # If multiple entries, add to the multipleEntriesRules
            multipleEntriesRules.append({"rule": line, "matches": enrichedResults})
          for enriched in enrichedResults:
            enriched["RuleIndex"] = idx  # Add the index of the rule
            # Add to the set to ensure uniqueness
            uniqueResults.add(json.dumps(enriched, sort_keys=True))  # Using JSON string to ensure uniqueness
          linesWritten += len(enrichedResults)  # Increment lines written for processed rule
          matchedRules += 1  # Increment matched rules counter
          for match in matches:
            ruleCounter[match["Pattern"]] += 1
        else:
          unmatchedRules.append(line)
          unmatchedRulesCount += 1  # Increment unmatched rules counter
      # if idx > 5:
      #   break
  return (
    results,
    unmatchedRules,
    ruleCounter,
    totalRules,
    matchedRules,
    unmatchedRulesCount,
    linesWritten,
    uniqueResults,
    multipleEntriesRules,
  )

def matchSnortToAttackMultilabel(ruleText, confidence, techniqueMap):
  results = []
  for pattern, mappings in SNORT_TO_ATTACK.items():
    if re.search(pattern, ruleText.lower()):
      ### using heuristic approach for confidence score
      for tactic, techniqueId, _ in mappings:
        if techniqueId in techniqueMap:
          techniqueInfo = techniqueMap[techniqueId]
          results.append({
            "Rule": ruleText,
            "Tactic": tactic,
            "TacticId": techniqueInfo['tactics'][0][0],
            "TechniqueId": techniqueInfo["techniqueId"],
            "TechniqueName": techniqueInfo["name"],
            "SubtechniqueId": techniqueInfo.get("subtechniqueId"),
            "SubtechniqueName": techniqueInfo["name"] if techniqueInfo.get("subtechniqueId") else None,
            "Pattern": pattern,
            "Confidence": confidence,
          })
  return results

def enrichWithAttackInfo(matches):
  return [
    {
      "Rule": m["Rule"],
      "Tactic": m["Tactic"],
      "TacticId": m["TacticId"],
      "TechniqueId": m["TechniqueId"],
      "TechniqueName": m["TechniqueName"],
      "SubtechniqueId": m["SubtechniqueId"],
      "SubtechniqueName": m["SubtechniqueName"],
      "Pattern": m["Pattern"],
      "Confidence": m["Confidence"],
      "MITREUrl": f"https://attack.mitre.org/techniques/{m['TechniqueId']}/",
    } for m in matches
  ]

def dfToJson(df, outputFile):
  df.to_json(outputFile, orient='records', indent=2)

def sortJsonByKey(inputPath, outputPath, sortKey):
  try:
    with open(inputPath, 'r') as file:
      data = json.load(file)

    if not isinstance(data, list):
      print("Error: JSON must be a list of objects.")
      return

    # Sort the list of dicts by the given key
    sortedData = sorted(data, key=lambda x: x.get(sortKey))

    with open(outputPath, 'w') as outFile:
      json.dump(sortedData, outFile, indent=2)

    print("Sorting completed successfully!\n")

  except FileNotFoundError:
    print(f"Error: File {BLUE}{inputPath}{RESET} not found.")
  except json.JSONDecodeError:
    print("Error: Failed to parse JSON.")
  except Exception as e:
    print(f"An error occurred: {RED}{e}{RESET}")

def printStatistics(data):
  # Display statistics
  print(f"Initial number of rules: {GREEN}{data['totalRules']}{RESET}")
  print(f"Processed rules with ATT&CK mappings: {GREEN}{data['matchedRules']}{RESET}")
  if len(data['unmatchedRules']) > 0:
    print(f"Unmatched rules: {GREEN}{data['unmatchedRulesCount']}{RESET}")
  else:
    print(f"{GREEN_BOLD}\nAll rules have been mapped successfully!{RESET}\n")
  print(f"Lines written to files (due to multiple entries from same rule): {RED}{data['linesWritten']}{RESET}")
  # print(f"Lines written to files (due to multiple entries from same rule): {RED}{linesWritten}{RESET}")
  
  # Display processed rules stats
  print(f"\n{YELLOW_BOLD}Processed Rules Statistics{RESET}")
  for pattern, count in data['ruleCounter'].items():
    print(f"{YELLOW}{pattern}{RESET}: {GREEN}{count}{RESET} time(s)")
  
  print(f"\nProcessed rules saved to {BLUE}{data['outputCsvFile']}{RESET} and {BLUE}{data['outputJsonFile']}{RESET}.")
  print(f"Unmatched rules saved to {BLUE}{data['unprocessedRules']}{RESET}.")
  print(
    f"Rules with multiple entries saved to {BLUE}{data['rulesWithMultipleEntriesCSVFile']}{RESET} and {BLUE}{data['rulesWithMultipleEntriesJSONFile']}{RESET}.\n"
  )

def main():
  outputMappingsDirectory = "mappings"
  outputCsvFile = "snort.rules.to.mitre.mapping.csv"
  outputJsonFile = "snort.rules.to.mitre.mapping.json"
  rulesFile = "snort3-community.rules"  # Update path if needed
  rulesWithMultipleEntriesCSVFile = "rules.with.multiple.entries.csv"
  rulesWithMultipleEntriesJSONFile = "rules.with.multiple.entries.json"
  sortKey = "RuleIndex"
  unprocessedRules = "unprocessed.snort.rules.txt"

  os.makedirs(outputMappingsDirectory, exist_ok=True)  # Ensure output directory exists

  outputCsvFilePath = os.path.join(outputMappingsDirectory, outputCsvFile)
  outputJsonFilePath = os.path.join(outputMappingsDirectory, outputJsonFile)
  unprocessedRules = os.path.join(outputMappingsDirectory, unprocessedRules)
  rulesWithMultipleEntriesCSVFile = os.path.join(outputMappingsDirectory, rulesWithMultipleEntriesCSVFile)
  rulesWithMultipleEntriesJSONFile = os.path.join(outputMappingsDirectory, rulesWithMultipleEntriesJSONFile)

  # Fetch from MITRE
  tactics, techniques = fetchMitreAttackInfo()
  tacticMap = mapTacticsWithTechniques(tactics)
  techniqueMap = mapTechniquesWithSubtechniques(techniques, tacticMap)
  
  # assign confidence (heuristics)
  ac.main(rulesFile)

  (
    results,
    unmatchedRules,
    ruleCounter,
    totalRules,
    matchedRules,
    unmatchedRulesCount,
    linesWritten,
    uniqueResults,
    multipleEntriesRules,
  ) = parseSnortRules(rulesFile, techniqueMap)
  
  # Ensure sum of processed and unmatched rules equals total rules
  assert matchedRules + unmatchedRulesCount == totalRules, "Mismatch in rule count!"
  
  # Convert the set of unique results back to a list and create DataFrame
  uniqueResultsList = [json.loads(item) for item in uniqueResults]
  df = pd.DataFrame(uniqueResultsList)
  
  # Save results to CSV
  df.to_csv(outputCsvFilePath, index=False)
  
  # Save DataFrame to JSON
  dfToJson(df, outputJsonFilePath)
  print(f"\nSorting {BLUE}{outputJsonFile}{RESET} by {YELLOW}{sortKey}{RESET} key.")
  sortJsonByKey(outputJsonFilePath, outputJsonFilePath, sortKey)
  
  # multipleEntriesRules
  df1 = pd.DataFrame(multipleEntriesRules)
  
  # Save results to CSV
  df1.to_csv(rulesWithMultipleEntriesCSVFile, index=False)
  
  # Save DataFrame to JSON
  dfToJson(df1, rulesWithMultipleEntriesJSONFile)
  
  # Write unmatched rules to a text file
  if len(unmatchedRules) > 0:
    with open(unprocessedRules, "w", encoding="utf-8") as f:
      for rule in unmatchedRules:
        f.write(rule + "\n")
  
  # Display statistics
  printObj = {}
  printObj["totalRules"] = totalRules
  printObj["matchedRules"] = matchedRules
  printObj["unmatchedRules"] = unmatchedRules
  printObj["unmatchedRulesCount"] = unmatchedRulesCount
  printObj["linesWritten"] = linesWritten
  printObj["outputCsvFile"] = outputCsvFile
  printObj["outputJsonFile"] = outputJsonFile
  printObj["unprocessedRules"] = unprocessedRules
  printObj["rulesWithMultipleEntriesCSVFile"] = rulesWithMultipleEntriesCSVFile
  printObj["rulesWithMultipleEntriesJSONFile"] = rulesWithMultipleEntriesJSONFile
  printObj["ruleCounter"] = ruleCounter

  printStatistics(printObj)


if __name__ == "__main__":
  main()
