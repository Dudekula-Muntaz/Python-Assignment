import os
print(f"current working directory:{os.getcwd()}")
import csv
from collections import Counter, defaultdict

# File names
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

def parse_log_file(file_name):
    try:
        with open(file_name, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: The log file '{file_name}' was not found.")
        return []

def count_requests_per_ip(logs):
    ip_counter = Counter()
    for log in logs:
        try:
            ip = log.split()[0]
            ip_counter[ip] += 1
        except IndexError:
            continue  # Skip malformed lines
    return ip_counter

def most_accessed_endpoint(logs):
    endpoint_counter = Counter()
    for log in logs:
        try:
            endpoint = log.split('"')[1].split()[1]
            endpoint_counter[endpoint] += 1
        except IndexError:
            continue  # Skip malformed lines
    return endpoint_counter.most_common(1)[0] if endpoint_counter else None

def detect_suspicious_activity(logs, threshold=10):
    failed_logins = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            try:
                ip = log.split()[0]
                failed_logins[ip] += 1
            except IndexError:
                continue  # Skip malformed lines
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(ip_requests, most_accessed, suspicious_activities):
    try:
        with open(OUTPUT_CSV, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Requests per IP
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_requests.items():
                writer.writerow([ip, count])
            
            writer.writerow([])
            
            # Most Accessed Endpoint
            writer.writerow(["Endpoint", "Access Count"])
            if most_accessed:
                writer.writerow([most_accessed[0], most_accessed[1]])
            else:
                writer.writerow(["No data", "No data"])
            
            writer.writerow([])
            
            # Suspicious Activity
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_activities.items():
                writer.writerow([ip, count])
    except Exception as e:
        print(f"Error saving results to CSV: {e}")

def main():
    print("Log Analysis Script")
    logs = parse_log_file(LOG_FILE)
    
    if not logs:
        print("No logs to process. Exiting.")
        return
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(logs)
    print("\nRequests per IP Address:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:20} {count}")
    
    # Most accessed endpoint
    most_accessed = most_accessed_endpoint(logs)
    if most_accessed:
        print(f"\nMost Frequently Accessed Endpoint: {most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("\nMost Frequently Accessed Endpoint: No data")
    
    # Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(logs)
    if suspicious_activities:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_activities.items():
            print(f"{ip:20} {count}")
    else:
        print("\nSuspicious Activity Detected: None")
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activities)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__": # type: ignore
    main()