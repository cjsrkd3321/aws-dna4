import json
import time
import boto3
import signal
import requests
from botocore.config import Config
from datetime import datetime, timedelta

### GLOBAL CONFIG ###
CLOUDTRAIL_URL = (
    "https://us-east-1.console.aws.amazon.com/cloudtrail/home?region=us-east-1#/events/"
)
SEARCH_HOURS = 120  # The search time range is 3 hours because (GMT + 9) + 3
SEARCH_CYCLE = 60  # by second
MY_IP = json.loads(requests.get("https://ipinfo.io/").text)["ip"]
DETECTED_EVENT_IDS = []
### GLOBAL CONFIG ###


# https://docs.python.org/ko/3/library/signal.html
def handler(signum, frame):
    for event_id in DETECTED_EVENT_IDS:
        print(CLOUDTRAIL_URL + event_id)
    exit()


signal.signal(signal.SIGINT, handler)  # CTRL + C
signal.signal(signal.SIGTERM, handler)  # For example, force termination using TASK MANAGER
signal.signal(signal.SIGTSTP, handler)  # CTRL + Z

if __name__ == "__main__":
    # The root account's console login events only occur in the us-east-1
    config = Config(region_name="us-east-1", signature_version="v4")
    cloudtrail = boto3.client("cloudtrail", config=config)

    while True:
        NOW = datetime.now()
        SEARCH_TIME_RANGE = timedelta(hours=SEARCH_HOURS)

        print(f"{NOW} Now working...")

        events = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
            StartTime=(NOW - SEARCH_TIME_RANGE),
            EndTime=NOW,
            MaxResults=5,
        )["Events"]

        for event in events:
            event_id = event["EventId"]
            event_time = event["EventTime"]
            event = json.loads(event["CloudTrailEvent"])
            [source_ip, user_agent, error, response] = [
                event["sourceIPAddress"],
                event["userAgent"],
                event.get("errorMessage", ""),
                event["responseElements"]["ConsoleLogin"],
            ]

            if (event_id not in DETECTED_EVENT_IDS) and (
                response != "Success" or source_ip != MY_IP
            ):
                print(
                    f"""\033[31m[DETECTED]\033[0m \033[32m{event_time}\033[0m \033[33m{source_ip}\033[0m \033[34m{user_agent}\033[0m \033[35m{error}\033[0m \033[36m{response}\033[0m"""
                )
                DETECTED_EVENT_IDS.append(event_id)

        time.sleep(SEARCH_CYCLE)
