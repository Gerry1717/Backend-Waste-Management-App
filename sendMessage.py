import sys
import requests
import random

def generate_verification_code():
    return str(random.randint(100000, 999999))

def format_recipient_number(recipient_number):
    recipient_number = "".join(filter(str.isdigit, recipient_number))
    if recipient_number.startswith('0'):
        recipient_number = '44' + recipient_number[1:]
    return recipient_number

def send_verification_code(api_key, sender_id, recipient_number):
    recipient_number = format_recipient_number(recipient_number)
    verification_code = generate_verification_code()

    base_url = "https://api.infobip.com/sms/1/text/single"
    headers = {
        "Authorization": "App {}".format(api_key),
        "Content-Type": "application/json"
    }

    message = "Your verification code is: {}".format(verification_code)

    payload = {
        "from": sender_id,
        "to": recipient_number,
        "text": message
    }

    try:
        response = requests.post(base_url, headers=headers, json=payload)
        response.raise_for_status()
        return "Verification code sent successfully.", verification_code
    except requests.exceptions.RequestException as e:
        return "Error sending verification code: {}".format(e), None

# Replace this with your actual API credentials and sender ID
API_KEY = "<YOUR INFOBIP KEY from API>"
SENDER_ID = "<YOUR INFO BIP LONGNUMBER (SMS NUMBER)>"

# Check if the recipient number is provided as a command-line argument
if len(sys.argv) < 2:
    print("Error: Recipient number not provided.")
    print("Usage: python filename.py <recipient_number>")
    sys.exit(1)

# Get the recipient number from the command-line argument
recipient_number = sys.argv[1]

success_message, verification_code = send_verification_code(API_KEY, SENDER_ID, recipient_number)
if verification_code:
    print(success_message)
    print("Generated verification code:", verification_code)
else:
    print(success_message)
