import re
import pandas as pd
from collections import Counter

def parse_logfile(file_path):
    with open(file_path,'r') as file:
        lines=file.readlines()
    log_entries=[]
    for line in lines:
        match=re.match(r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+)',line) # regular expression for extracting Specific information 
        if match:
            log_entries.append(match.groupdict())
    return log_entries

def analyze_logs(log_entries):
    ip_counts=Counter(entry['ip'] for entry in log_entries) # count requests per IP
    endpoint_counts=Counter(entry['endpoint'] for entry in log_entries) # count requests per endpoint
    invalid_creds=Counter(entry['ip'] for entry in log_entries if entry['status']=='401') # count failed login attempts 
    threshold=10 # threshold value is used to identify suspicious ip
    suspicious_ips={ip: count for ip,count in invalid_creds.items() if count>threshold} # if the count of specific ip is more than threshould value will be treated as suspicious ip.
    return ip_counts,endpoint_counts,suspicious_ips

def save_results(ip_counts,endpoint_counts,suspicious_ips,out_file):
    ip_df=pd.DataFrame(ip_counts.items(),columns=['IP Address','Request Count']).sort_values(by='Request Count',ascending=False)
    endpoint_df=pd.DataFrame(endpoint_counts.items(),columns=['Endpoint','Access Count']).sort_values(by='Access Count', ascending=False)
    suspicious_ips_df=pd.DataFrame(suspicious_ips.items(),columns=['IP Address','Failed Login Count'])
    
    if ip_df.empty:
        print(f"\nRequests per IP:\n No information found\n")
    else:
        print(f"\n Requests per IP:\n{ip_df.to_string(index=False)}\n") # to_string method is used here to display only columns without the index numbers

    if endpoint_df.empty:
        print(f"\nMost Accessed Endpoint:\n No information found\n")
    else:
        print(f"\nMost Accessed Endpoint:\n{endpoint_df.to_string(index=False)}\n")

    if suspicious_ips_df.empty:
        print(f"\nSuspicious Activity:\n No information found\n")
    else:
        print(f"\nSuspicious Activity:\n{suspicious_ips_df.to_string(index=False)}")

    with pd.ExcelWriter(out_file) as writer: 
        ip_df.to_excel(writer,sheet_name='Requests per IP',index=False)
        endpoint_df.to_excel(writer,sheet_name='Most Accessed Endpoints',index=False)
        suspicious_ips_df.to_excel(writer,sheet_name='Suspicious Activity',index=False)
    print(f"Results saved to {out_file}")

def main():
    inp_file="sample.log"
    out_file="log_analysis_results.xlsx"
    log_entries=parse_logfile(inp_file)
    ip_counts,endpoint_counts,suspicious_ips=analyze_logs(log_entries)
    save_results(ip_counts,endpoint_counts,suspicious_ips,out_file)

if __name__=="__main__":
    main()
