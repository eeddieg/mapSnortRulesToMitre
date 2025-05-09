import json
import os 
import re

RESET = "\033[0m"
BLUE = "\033[34m"
RED = "\033[31m"
YELLOW = "\033[33m"
YELLOW_BOLD = "\033[1;33m"

outputDirectory = "confidence"
inputFile = "snort3-community.rules"        # Input file with rules
outputFile = "snort.confidence.scores.json" # JSON output file

def scoreSnortRule(ruleText):
  score = 0

  # Check for presence of 'msg'
  if 'msg:' in ruleText:
    score += 20

  # Check for presence of 'flow'
  if 'flow:' in ruleText:
    score += 5

  # Check for 'content' keyword usage
  if 'content:' in ruleText:
    score += 10

  # Check for presence of 'sid' and 'rev'
  if 'sid:' in ruleText and 'rev:' in ruleText:
    score += 15

  # Check for rule length
  ruleLength = len(ruleText)
  if ruleLength > 200:
    score += 5
  if ruleLength > 400:
    score += 5

  # Check for presence of 'pcre'
  if 'pcre:' in ruleText:
    score += 5

  # Check for presence of 'metadata'
  if 'metadata:' in ruleText:
    score += 5

  # Check for rule complexity (number of conditions)
  conditions = re.findall(r'\b(content|pcre|flow|http_uri|http_cookie|http_method)\b', ruleText)
  score += len(conditions)

  # Check for rule age (SID > 1000000)
  sidMatch = re.search(r'sid:(\d+);', ruleText)
  if sidMatch and int(sidMatch.group(1)) > 1000000:
    score += 5

  # Check for rule source (community rules)
  if 'ruleset community' in ruleText:
    score += 5

  # Cap score at 100
  if score > 100:
    score = 100

  # assert score <= 100, "Score exceeds 100"

  return score

def scoreRulesFromFile(filePath, outputPath):
  results = []
  uniqueScores = set()
  try:
    with open(filePath, 'r') as file:
      for idx, line in enumerate(file, start = 1):
        rule = line.strip()
        if not rule or rule.startswith('#'):
          continue  # skip empty lines or comments
        score = scoreSnortRule(rule)

        results.append({
          "snort_idx": idx,
          "snort_rule": rule,
          "confidence": score
        })
        uniqueScores.add(score)
        # print(f"Rule {idx} Score: {score}")

    uniqueValues = []
    for s in sorted(uniqueScores):
      uniqueValues.append(s)

    with open(outputPath, 'w') as jsonFile:
      json.dump(results, jsonFile, indent=2)

    print(f"Confidence JSON output written to {BLUE}{outputPath}{RESET}.")
    print(f"\n{YELLOW_BOLD}Unique Confidence Scores{RESET}:")
    print(uniqueValues)
    print("")
  except FileNotFoundError:
    print(f"Error: File {BLUE}{filePath}{RESET} not found.")
  except Exception as e:
    print(f"An error occurred: {e}")

def findRuleConfidenceByIndex(targetIndex):
  jsonPath = os.path.join(outputDirectory, outputFile)

  try:
    with open(jsonPath, 'r') as jsonFile:
      data = json.load(jsonFile)
      for rule in data:
        if rule.get("snort_idx") == targetIndex:
          # print("Match found:")
          # print(json.dumps(rule, indent=2))
          return rule.get("confidence")

      print(f"No rule found with snort_idx = {targetIndex}")
      return None
  except FileNotFoundError:
    print(f"Error: File {BLUE}{jsonPath}{RESET} not found.")
  except json.JSONDecodeError:
    print("Error: Failed to parse JSON.")
  except Exception as e:
    print(f"An error occurred: {RED}{e}{RESET}")
    return None

def main(inputFilePath):
  inputFilePath = (inputFilePath, inputFile)[len(inputFilePath) == 0]

  os.makedirs(outputDirectory, exist_ok=True)  # Ensure output directory exists
  outputFilePath = os.path.join(outputDirectory, outputFile)

  confidenceScores = scoreRulesFromFile(inputFilePath, outputFilePath)

if __name__ == "__main__":
  main()