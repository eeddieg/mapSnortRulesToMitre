import json
import os

RESET = "\033[0m"
BLUE = "\033[34m"
BLUE_BOLD = "\033[1;34m"
GREEN = "\033[32m"
GREEN_BOLD = "\033[1;32m"
RED = "\033[31m"
RED_BOLD = "\033[1;31m"
YELLOW = "\033[33m"
YELLOW_BOLD = "\033[1;33m"

def checkRuleIndices(jsonFilePath):
  try:
    with open(jsonFilePath, 'r') as file:
      ruleList = json.load(file)
  except FileNotFoundError:
    print("\nThe file does not exist!")
    exit(1)

  ruleIndices = set()
  for rule in ruleList:
    if 'RuleIndex' in rule and isinstance(rule['RuleIndex'], int):
      ruleIndices.add(rule['RuleIndex'])

  if not ruleIndices:
    print("\nNo valid RuleIndex entries found.")
    return

  minIndex = min(ruleIndices)
  maxIndex = max(ruleIndices)
  expectedIndices = set(range(1, maxIndex + 1))
  missingIndices = sorted(expectedIndices - ruleIndices)

  print(f"RuleIndex range in file: {GREEN}{minIndex}{RESET} to {GREEN}{maxIndex}{RESET}.\n")

  if missingIndices:
    print(f"Rules with indexes from {GREEN}{minIndex}{RESET} to {GREEN}{maxIndex}{RESET} have been processed successfully except rules with indexes: {RED}{missingIndices}{RESET}.")
  else:
    print(f"Rules with indexes from {GREEN}{minIndex}{RESET} to {GREEN}{maxIndex}{RESET} have been processed successfully!\n")


def main():
  outputMappingsDirectory = "mappings"
  outputJsonFile = "snort.rules.to.mitre.mapping.json"
  
  outputJsonFilePath = os.path.join(outputMappingsDirectory, outputJsonFile)

  checkRuleIndices(outputJsonFilePath)

if __name__ == "__main__":
  main()