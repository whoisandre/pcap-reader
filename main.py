from scapy.all import rdpcap
import requests
from scapy.layers.inet import IP

API_KEY = "your_api_key_here"

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()

            if 'data' in json_response and 'attributes' in json_response['data']:
                attributes = json_response['data']['attributes']
                malicious = attributes['last_analysis_stats']['malicious']
                reputation = attributes.get('reputation', 'No score available')

                return f"{ip} is {'malicious' if malicious > 0 else 'clean'}, Community Score: {reputation}"
            else:
                return f"Could not determine status for {ip}"
        else:
            return f"Error querying VirusTotal for {ip}: {response.status_code}"
    except Exception as e:
        return f"Exception occurred for {ip}: {e}"

def open_pcap(file_path):
    if file_path:
        packets = rdpcap(file_path)
        ip_addresses = set()
        for packet in packets:
            if IP in packet:
                ip_dst = packet[IP].dst
                ip_addresses.add(ip_dst)

        for ip in ip_addresses:
            result = check_ip_virustotal(ip)
            print(result)
    else:
        print("No file selected")

def main():

    if API_KEY == "your_api_key_here":
        print("Please enter your API key on the code before running this script.")
        exit()

    file_path = input("Enter the path of the pcap file: ").strip()

    if '"' in file_path:
        file_path = file_path.replace('"', '')
        print(f"Commas were found and removed from the file path. New path: {file_path}")

    open_pcap(file_path)

if __name__ == "__main__":
    main()
