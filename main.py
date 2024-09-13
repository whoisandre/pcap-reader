from scapy.all import rdpcap
import requests
from scapy.layers.inet import IP
import pandas as pd
import os

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
                country = attributes.get('country', 'Unknown')

                return {
                    'IP': ip,
                    'Status': 'Malicious' if malicious > 0 else 'Clean',
                    'Community Score': reputation,
                    'Country': country
                }
            else:
                return {
                    'IP': ip,
                    'Status': 'Unknown',
                    'Community Score': 'No score available',
                    'Country': 'Unknown'
                }
        else:
            return {
                'IP': ip,
                'Status': f"Error {response.status_code}",
                'Community Score': 'N/A',
                'Country': 'N/A'
            }
    except Exception as e:
        return {
            'IP': ip,
            'Status': 'Exception',
            'Community Score': str(e),
            'Country': 'N/A'
        }


def open_pcap(file_path):
    if file_path:
        packets = rdpcap(file_path)
        ip_addresses = set()
        for packet in packets:
            if IP in packet:
                ip_dst = packet[IP].dst
                ip_addresses.add(ip_dst)

        results = []
        for ip in ip_addresses:
            result = check_ip_virustotal(ip)
            print(f"{result['IP']} - {result['Status']} "
                  f"(Community Score: {result['Community Score']}, Country: {result['Country']})")
            results.append(result)

        return results
    else:
        print("No file selected")
        return []


def export_to_excel(results, save_path, file_name):
    df = pd.DataFrame(results)
    full_path = os.path.join(save_path, file_name)
    df.to_excel(full_path, index=False)
    print(f"Results exported to {full_path}")


def main():
    if API_KEY == "" or API_KEY == " " or API_KEY == "your_api_key_here":
        print("Please enter your API key in the code before running this script.")
        exit()

    file_path = input("Enter the path of the pcap file: ").strip()

    if '"' in file_path:
        file_path = file_path.replace('"', '')
        print(f'Quotes were found and removed from the file path. New path: {file_path}')

    results = open_pcap(file_path)

    if results:
        export_choice = input("Do you want to export the results to an Excel file? (y/n): ").strip().lower()

        if export_choice == "y":
            save_path = input("Enter the directory where you want to save the Excel file: ").strip()
            file_name = input("Enter the name of the Excel file: ").strip()

            if not file_name.endswith('.xlsx'):
                file_name += '.xlsx'

            if not os.path.exists(save_path):
                print("The directory does not exist. Please provide a valid directory.")
                return

            export_to_excel(results, save_path, file_name)
        else:
            print("Export to Excel skipped.")
    else:
        print("No results to export.")


if __name__ == "__main__":
    main()
