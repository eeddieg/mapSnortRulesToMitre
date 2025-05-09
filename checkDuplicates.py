import json
import os
from collections import defaultdict

RESET = "\033[0m"
BLUE = "\033[34m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
YELLOW_BOLD = "\033[1;33m"

def findDuplicates(jsonPath, keyName):
  try:
    with open(jsonPath, 'r') as file:
      data = json.load(file)

    valueCount = defaultdict(list)

    # Index each item's value for the given key
    for idx, item in enumerate(data):
      value = item.get(keyName)
      valueCount[value].append(idx)

    # Find and report duplicates
    duplicates = {k: v for k, v in valueCount.items() if len(v) > 1}
    
    if duplicates:
      print(f"Duplicate values found for key {YELLOW_BOLD}{keyName}{RESET}:")
      for val in sorted(duplicates):
        indices = sorted(duplicates[val])
        print(f"Value {YELLOW}{val}{RESET} found at JSON indices: {GREEN}{indices}{RESET}.")

      print(f"\nTotal duplicate keys: {RED}{len(duplicates)}{RESET}\n")
    else:
      print(f"No duplicates found for key {YELLOW}{keyName}{RESET}.\n")

    return duplicates

  except FileNotFoundError:
    print(f"Error: File {BLUE}{jsonPath}{RESET} not found.\n")
  except json.JSONDecodeError:
    print("Error: Failed to parse JSON.\n")
  except Exception as e:
    print(f"An error occurred: {RED}{e}{RESET}\n")
    return None

def main():
  inputDir = "mappings"
  jsonFile = "snort.rules.to.mitre.mapping.json"
  
  jsonFilePath = os.path.join(inputDir, jsonFile)
  
  keyToCheck = "Rule"
  # keyToCheck = "RuleIndex"
  findDuplicates(jsonFilePath, keyToCheck)

if __name__ == "__main__":
  main()
