#!/usr/bin/env python
import sys
import json
import requests
import os

def send_to_discord(webhook_url, json_payload, response_file):
    try:
        # Open the response file for writing with UTF-8 encoding
        with open(response_file, 'w', encoding='utf-8') as f:
            try:
                # Parse the JSON payload with UTF-8 encoding
                # Ensure the JSON payload is treated as UTF-8
                if isinstance(json_payload, bytes):
                    json_payload = json_payload.decode('utf-8')
                payload = json.loads(json_payload)

                # Send the request to Discord with UTF-8 encoding
                headers = {'Content-Type': 'application/json; charset=utf-8'}
                response = requests.post(webhook_url, json=payload, headers=headers)

                # Write the status code to the response file
                f.write(f"STATUS:{response.status_code}\n")

                # Write a short response preview if there's content
                if response.text:
                    preview = response.text[:100] + "..." if len(response.text) > 100 else response.text
                    f.write(f"RESPONSE:{preview}\n")

                # Return success
                return 0
            except Exception as e:
                # Write the error to the response file
                f.write(f"ERROR:{str(e)}\n")
                return 1
    except Exception as e:
        # If we can't even open the response file, there's not much we can do
        # Just exit silently with an error code
        return 1

if __name__ == "__main__":
    # Check if we have the right number of arguments
    if len(sys.argv) != 4:
        # Exit silently with an error code
        sys.exit(1)

    # Get the webhook URL, JSON payload, and response file from command-line arguments
    webhook_url = sys.argv[1]
    json_payload = sys.argv[2]
    response_file = sys.argv[3]

    # Send the request to Discord
    exit_code = send_to_discord(webhook_url, json_payload, response_file)
    sys.exit(exit_code)
