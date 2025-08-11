import os
import yaml
import csv
import time
import re
from datetime import datetime
import requests
from pycentral.base import ArubaCentralBase

TOKEN_FILE = "input_token_only.yaml"

def prompt_for_credentials():
    print("Credentials file not found or incomplete. Please enter the following:")
    base_url = input("Enter Base URL (e.g., https://apigw-prod2.central.arubanetworks.com): ").strip()
    access_token = input("Enter Access Token: ").strip()
    client_id = input("Enter Client ID (optional, press enter to skip): ").strip() or None
    client_secret = input("Enter Client Secret (optional, press enter to skip): ").strip() or None
    refresh_token = input("Enter Refresh Token (optional, press enter to skip): ").strip() or None
    return base_url, access_token, client_id, client_secret, refresh_token

def save_credentials(data):
    with open(TOKEN_FILE, "w") as f:
        yaml.safe_dump(data, f)
    print(f"Credentials saved to {TOKEN_FILE}")

def load_credentials():
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE, "r") as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file '{TOKEN_FILE}': {e}")
            return None

def parse_duration(text):
    text = text.strip().lower()
    match = re.match(r"(\d+)\s*([smhdw])", text)
    if not match:
        raise ValueError("Invalid duration format")
    value, unit = match.groups()
    value = int(value)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return value * multipliers[unit]

def get_seconds_ago():
    print("Select time range for events:")
    print("1) Last 5 minutes")
    print("2) Last 1 hour")
    print("3) Last 24 hours")
    print("4) Last 1 week")
    print("5) Custom (e.g., 5m, 2h, 3d, 1w)")
    choice = input("Enter choice [1-5]: ").strip()
    if choice == "1":
        return 300
    elif choice == "2":
        return 3600
    elif choice == "3":
        return 86400
    elif choice == "4":
        return 604800
    elif choice == "5":
        user_input = input("Enter custom duration (e.g., 10m, 2h, 3d, 1w): ")
        try:
            return parse_duration(user_input)
        except Exception:
            print("Invalid input, defaulting to 5 minutes")
            return 300
    else:
        print("Invalid choice, defaulting to 5 minutes")
        return 300

def update_tokens(yaml_data, central_info, access_token_new, refresh_token_new=None):
    central_info["token"]["access_token"] = access_token_new
    if refresh_token_new:
        central_info["token"]["refresh_token"] = refresh_token_new
    yaml_data["central_info"] = central_info
    save_credentials(yaml_data)

def refresh_access_token(base_url, client_id, client_secret, old_refresh_token):
    if not old_refresh_token:
        print("No refresh token available for refresh attempt.")
        return None, None
    token_url = f"{base_url}/oauth2/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": old_refresh_token
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(token_url, data=data, headers=headers)
        resp.raise_for_status()
        token_data = resp.json()
        return token_data.get("access_token"), token_data.get("refresh_token", old_refresh_token)
    except Exception as e:
        print(f"Failed to refresh access token: {e}")
        return None, None

def safe_api_call(central, api_method, api_path, api_params, yaml_data, central_info):
    response = central.command(apiMethod=api_method, apiPath=api_path, apiParams=api_params)
    if isinstance(response, dict):
        error = response.get("error")
        msg = response.get("msg", {})
        error_desc = response.get("error_description", "").lower() if "error_description" in response else ""
        invalid_token = (
            error == "invalid_token" or
            (isinstance(msg, dict) and msg.get("error") == "invalid_token") or
            "invalid or has expired" in error_desc
        )
        if invalid_token:
            print("\nAccess token expired or invalid.")

            new_access_token = None
            new_refresh_token = None

            client_id = central_info.get("client_id")
            client_secret = central_info.get("client_secret")
            refresh_token = central_info.get("token", {}).get("refresh_token")

            if client_id and client_secret and refresh_token:
                print("Attempting token refresh...")
                new_access_token, new_refresh_token = refresh_access_token(
                    central_info["base_url"], client_id, client_secret, refresh_token
                )

            if not new_access_token:
                new_access_token = input("Please generate a new access token in Aruba Central and paste it here: ").strip()
                new_refresh_token = None

            if new_access_token:
                update_tokens(yaml_data, central_info, new_access_token, new_refresh_token)
                central.central_info["token"]["access_token"] = new_access_token
                if new_refresh_token:
                    central.central_info["token"]["refresh_token"] = new_refresh_token
                # Retry API call with new token
                response = central.command(apiMethod=api_method, apiPath=api_path, apiParams=api_params)
    return response

def convert_epoch_fields(event):
    # convert timestamp fields from epoch to readable string if present
    if "timestamp" in event and isinstance(event["timestamp"], int):
        ts = event["timestamp"]
        if ts > 1e12:  # probably milliseconds
            ts /= 1000
        event["timestamp"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    if "ts_ms" in event and isinstance(event["ts_ms"], int) and event["ts_ms"] > 0:
        ts = event["ts_ms"] / 1000
        event["ts_ms"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    return event

def main():
    # Load credentials
    yaml_data = load_credentials()
    if yaml_data is None:
        base_url, access_token, client_id, client_secret, refresh_token = prompt_for_credentials()
        yaml_data = {
            "central_info": {
                "base_url": base_url,
                "token": {"access_token": access_token, "refresh_token": refresh_token},
                "client_id": client_id,
                "client_secret": client_secret
            },
            "ssl_verify": True
        }
        save_credentials(yaml_data)

    central_info = yaml_data.get("central_info", {})
    token_info = central_info.get("token", {})
    base_url = central_info.get("base_url", "").strip()
    access_token = token_info.get("access_token", "").strip()
    refresh_token = token_info.get("refresh_token", None)
    client_id = central_info.get("client_id", None)
    client_secret = central_info.get("client_secret", None)
    ssl_verify = yaml_data.get("ssl_verify", True)

    # Validate credentials
    if not base_url or not access_token:
        print("Missing Base URL or Access Token. Please enter credentials.")
        base_url, access_token, client_id, client_secret, refresh_token = prompt_for_credentials()
        central_info["base_url"] = base_url
        central_info["token"] = {"access_token": access_token, "refresh_token": refresh_token}
        central_info["client_id"] = client_id
        central_info["client_secret"] = client_secret
        yaml_data["central_info"] = central_info
        save_credentials(yaml_data)

    central_info["base_url"] = base_url
    central_info["token"]["access_token"] = access_token
    central_info["token"]["refresh_token"] = refresh_token
    central_info["client_id"] = client_id
    central_info["client_secret"] = client_secret

    print(f"Loaded central_info: base_url={base_url}, ssl_verify={ssl_verify}")

    seconds_ago = get_seconds_ago()
    from_ts_epoch = int(time.time()) - seconds_ago

    from_dt = datetime.fromtimestamp(from_ts_epoch)
    to_dt = datetime.now()
    print(f"Querying events from {from_dt.strftime('%Y-%m-%d %H:%M:%S')} to {to_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    timestamp_str = datetime.now().strftime("%m-%d-%y_%H-%M-%S")
    output_file = f"events-output-{timestamp_str}.csv"

    central = ArubaCentralBase(central_info=central_info, ssl_verify=ssl_verify)

    api_path = "/monitoring/v2/events"
    api_method = "GET"
    limit = 1000
    offset = 0

    api_params = {
        "limit": limit,
        "offset": offset,
        "from_timestamp": from_ts_epoch
    }

    processed_events = 0
    api_calls = 0
    errors = 0
    start_time = time.time()

    with open(output_file, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = None

        while True:
            response = safe_api_call(central, api_method, api_path, api_params, yaml_data, central_info)
            api_calls += 1

            if response is None:
                errors += 1
                print(f"Error: No response from API at offset {api_params['offset']}.")
                break

            # Extract events list
            events = None
            if isinstance(response, dict):
                # Unwrap 'msg' if present
                if "msg" in response and isinstance(response["msg"], dict):
                    data = response["msg"]
                else:
                    data = response
                if "events" in data and isinstance(data["events"], list):
                    events = data["events"]

            if events is None:
                errors += 1
                print(f"Warning: Unexpected response structure at offset {api_params['offset']}: {response}")
                break

            if not events:
                if processed_events == 0:
                    print("No file was created because the event count was 0")
                else:
                    print("No more events returned, pagination complete.")
                break

            if writer is None:
                # Use keys from first batch to maintain order
                keys = []
                for ev in events:
                    if isinstance(ev, dict):
                        for k in ev.keys():
                            if k not in keys:
                                keys.append(k)
                if not keys:
                    print("No dict-like event objects to write to CSV.")
                    return
                writer = csv.DictWriter(csv_file, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()

            dict_rows = [convert_epoch_fields(ev.copy()) for ev in events if isinstance(ev, dict)]
            writer.writerows(dict_rows)
            processed_events += len(dict_rows)

            print(f"API call {api_calls}: Offset {api_params['offset']}, fetched {len(events)} events, total processed: {processed_events}")

            if len(events) < limit:
                print("Last page received, ending pagination.")
                break

            api_params["offset"] += limit

            time.sleep(0.5)

    elapsed = time.time() - start_time
    print(f"\n--- Summary ---")
    print(f"Total events processed: {processed_events}")
    print(f"Total API calls made: {api_calls}")
    print(f"Total errors encountered: {errors}")
    print(f"Total time elapsed: {elapsed:.2f} seconds")

    if processed_events > 0:
        print(f"All events written to {output_file}")

if __name__ == "__main__":
    main()
