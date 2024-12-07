import csv
from collections import defaultdict
import re

log_file = "sample.log"
output_csv = "log_analysis_results.csv"

failed_login_threshold = 10

request_counts = defaultdict(int)
endpoint_counts = defaultdict(int)
failed_login_attempts = defaultdict(int)

ip_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+)')
endpoint_pattern = re.compile(r'\"(?:GET|POST|PUT|DELETE|HEAD) (/\S*)')
failed_login_pattern = re.compile(r'401|Invalid credentials')

with open(log_file, "r") as file:
    for line in file:
        ip_match = ip_pattern.search(line)
        if ip_match:
            ip = ip_match.group(1)
            request_counts[ip] += 1

        endpoint_match = endpoint_pattern.search(line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1

        if failed_login_pattern.search(line):
            if ip_match:
                failed_login_attempts[ip] += 1

sorted_requests = sorted(request_counts.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_login_threshold}

print("IP Address Request Counts:")
for ip, count in sorted_requests:
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

with open(output_csv, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in sorted_requests:
        writer.writerow([ip, count])

    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

print(f"\nResults saved to {output_csv}.")


