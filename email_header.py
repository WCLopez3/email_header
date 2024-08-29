import email
from email import policy
from email.parser import BytesParser
import sys  # Import sys to handle command-line arguments

def main(file_path):
    # Read the .eml file
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract headers
    date = msg['date']
    subject = msg['subject']
    to = msg['to']
    from_ = msg['from']
    reply_to = msg['reply-to']
    return_path = msg['return-path']
    message_id = msg['message-id']
    auth_results = msg['authentication-results']

    # Format Authentication-Results for display
    formatted_auth_results = ''
    if auth_results:
        formatted_auth_results = ";\n ".join(auth_results.split(";"))

    # Print formatted output
    print(f"""(===Dates===)
Date: {date}

(===Reported By===)
To: {to}

(===From===)
From: {from_}

(===Subject===)
Subject: {subject}

(===Headers===)
Reply-To: {reply_to}
Return-Path: {return_path}
Message-ID: {message_id}
Authentication-Results:
{formatted_auth_results}

(===Attachments===)

(===PhishER Link===)


Investigation:
==============
    Analysis
        Body
        Sender
        URL
        PDF


URL added to Blocks
==============

Email domain block on SMTP (<RITM######)
==============

Email Purge/Delete (<RITM######)
==============

""")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
