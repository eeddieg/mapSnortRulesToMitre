from dotenv import load_dotenv
from misp_stix_converter import MISPtoSTIX21Parser
from pymisp import ExpandedPyMISP
from pymisp import PyMISP
import json
import os

def getMispEvents(file):
  load_dotenv()

  # Initialize PyMISP with your MISP instance URL and API key
  mispUrl = os.getenv("MISP_URL")
  mispKey = os.getenv("MISP_KEY")
  mispVerifycert = False  # Set to True if your MISP instance uses SSL

  # misp = ExpandedPyMISP(mispUrl, mispKey, mispVerifycert)
  misp = PyMISP(mispUrl, mispKey, mispVerifycert)

  # Fetch events published within the last 24 hours
  events = misp.search(publish_timestamp='24h', limit=5)

  # print(events)
  event_dicts = events

  # Save events to a JSON file
  with open(file, 'w',  encoding='utf-8') as f:
    json.dump(event_dicts, f, indent=2)

def generateConfidence(technique_id, misp_events):
    """
    Generate a numerical confidence score between 0 and 100 for the given MITRE ATT&CK technique.
    
    Parameters:
        technique_id (str): The MITRE ATT&CK technique ID.
        misp_events (list): List of MISP events that are being analyzed.
        
    Returns:
        int: Confidence score between 0 and 100.
    """
    technique_count = 0  # Count how often this technique is mentioned
    event_confidence_total = 0  # Sum of confidence values of events that include this technique
    event_count = 0  # Total number of events that mention this technique

    for event in misp_events:
        for attribute in event.get('Attribute', []):
            if 'attack-pattern' in attribute.get('value', '') and technique_id in attribute.get('value', ''):
                technique_count += 1  # Count each time the technique is mentioned
                event_confidence_total += event.get('confidence', 50)  # Default confidence if not present
                event_count += 1

    # If no events mention this technique, return a confidence of 0
    if event_count == 0:
        return 0

    # Calculate the average confidence from events mentioning this technique
    average_event_confidence = event_confidence_total / event_count

    # Frequency-based scaling (e.g., more frequent techniques get a higher score)
    frequency_score = min(technique_count * 5, 100)  # Cap the frequency-based score to 100

    # Combine the frequency score and average event confidence
    combined_score = (frequency_score + average_event_confidence) / 2

    # Return the final confidence score, ensuring it is within 0 to 100
    return int(min(100, max(0, combined_score)))


def parseTechniquesFromMISP(misp_events_file):
    with open(misp_events_file, 'r') as file:
        misp_events = json.load(file)

    # Debugging step: print out the first event to check the structure
    print(misp_events[:1])  # Print the first event to inspect its structure

    # Initialize the parser
    parser = MISPtoSTIX21Parser()

    # Loop through each event in the list of MISP events
    for misp_event in misp_events:
        parser.parse_misp_event(misp_event)  # Parse each event individually

    # Debugging step: print out the parsed stix_objects
    print(parser.stix_objects)  # Check if STIX objects are being created

    # Extract techniques and confidence scores
    techniques = []
    for obj in parser.stix_objects:
        # Debugging step: print each STIX object to inspect it
        print(obj)  # Check the full object to inspect its structure

        if obj.get('type') == 'attack-pattern':  # MITRE ATT&CK Technique
            technique_id = obj.get('id')
            if technique_id:  # Ensure the technique ID is not None or empty
                confidence_score = generateConfidence(technique_id, misp_events)  # Pass the entire MISP event data

                technique = {
                    'technique': technique_id,
                    'confidence': confidence_score
                }
                techniques.append(technique)

    # Print the final techniques list
    print(techniques)
    return techniques

def save_techniques_to_file(techniques, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(techniques, f, indent=2)  # Writing to the file with indentation for readability
        print(f"Data written to {output_file}")



def main():
    mispEventsFile = "misp.events.json"
    outputFile = "techniques.with.confidence.json"

    # Get MISP event data from instance
    getMispEvents(mispEventsFile)

    # Parse MISP events and generate techniques with confidence scores
    techniques_with_confidence = parseTechniquesFromMISP(mispEventsFile)

    # Debugging step: ensure techniques list is not empty
    print(f"Techniques with confidence: {techniques_with_confidence}")

    # Save the techniques with confidence scores to the output file
    save_techniques_to_file(techniques_with_confidence, outputFile)

if __name__ == "__main__":
    main()
