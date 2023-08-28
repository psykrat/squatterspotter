import requests
import dns.resolver
import re
import os
import webbrowser
import time
from dotenv import load_dotenv

load_dotenv()

# Constants
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
API_KEY = os.environ.get("OPENAI_API_KEY")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

def generate_domains_with_gpt(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}],
        "max_tokens": 500
    }

    try:
        response = requests.post(OPENAI_API_URL, headers=headers, json=data)
        response.raise_for_status()

        output = response.json()['choices'][0]['message']['content'].strip().split("\n")
        domain_variations = [re.sub(r'^\d+\.\s+', '', domain) for domain in output if len(domain) > 4 and "." in domain]
        return domain_variations

    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"Error using OpenAI API: {e}")
        return []

def is_ip_malicious(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "365",
        "verbose": True
    }

    try:
        response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params)
        response.raise_for_status()

        data = response.json()
        return data['data']['abuseConfidenceScore'] > 0, data['data']['abuseConfidenceScore']

    except requests.RequestException as e:
        print(f"Error querying AbuseIPDB: {e}")
        return False, 0

def domain_info(domain):
    info = {}

    try:
        info['A'] = [answer.address for answer in dns.resolver.resolve(domain, 'A')]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass  # Skip print statement if no A record is found
    except dns.exception.DNSException as e:
        print(f"General DNS Error for A record in domain {domain}: {e}")

    try:
        info['MX'] = [answer.exchange.to_text() for answer in dns.resolver.resolve(domain, 'MX')]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass  # Skip print statement if no MX record is found
    except dns.exception.DNSException as e:
        print(f"General DNS Error for MX record in domain {domain}: {e}")

    try:
        info['NS'] = [answer.target.to_text() for answer in dns.resolver.resolve(domain, 'NS')]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass  # Skip print statement if no NS record is found
    except dns.exception.DNSException as e:
        print(f"General DNS Error for NS record in domain {domain}: {e}")

    return info

def get_domain_info(variation, info):
    details = {
        'domain': variation,
        'A_records': info.get('A', []),
        'MX_records': info.get('MX', []),
        'NS_records': info.get('NS', []),
        'malicious_ips': [(ip, is_ip_malicious(ip)[1]) for ip in info.get('A', []) if is_ip_malicious(ip)[0]]  # Fetching the score from the function
    }
    return details

def generate_html_report(data_list):
    report = """
    <!DOCTYPE html>
    <pre style="font-family: 'Courier New', Courier, monospace;">
   ____               __  __          ____          __  __         
  / __/__ ___ _____ _/ /_/ /____ ____/ __/__  ___  / /_/ /____ ____
 _\ \/ _ `/ // / _ `/ __/ __/ -_) __/\ \/ _ \/ _ \/ __/ __/ -_) __/
/___/\_, /\_,_/\_,_/\__/\__/\__/_/ /___/ .__/\___/\__/\__/\__/_/   
      /_/                             /_/                          
</pre>
    <html lang="en">
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Domain Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background-color: #f7f9fc;
                    color: #333;
                }

                h1 {
                    color: #2c3e50;
                }

                h2 {
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }

                p {
                    padding: 5px 0;
                }

                .malicious-ip {
                    color: red;
                }

                hr {
                    margin: 20px 0;
                    border: 0;
                    border-top: 1px solid #eee;
                }

                .domain-section {
                    background-color: #fff;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
                }
            </style>
            <p class="byline">by: psykrat</p>
    """

    for data in data_list:
        report += '<div class="domain-section">'
        report += f"<h2>{data['domain']}</h2>"
        report += f"<p><strong>IP Addresses (A records):</strong> {', '.join(data['A_records'])}</p>"
        report += f"<p><strong>Mail Servers (MX records):</strong> {', '.join(data['MX_records'])}</p>"
        report += f"<p><strong>Name Servers (NS records):</strong> {', '.join(data['NS_records'])}</p>"

        for ip, score in data['malicious_ips']:
            report += f'<p class="malicious-ip">Malicious IP Detected: {ip} with confidence score: {score}%</p>'

        report += "</div>"

    report += """
        </body>
    </html>
    """

    return report

if __name__ == "__main__":
    
    domain = input("Enter the domain name to check for typosquatting: ").strip()

    custom_prompt_choice = input("Would you like to use a custom prompt? (yes/no): ").strip().lower()
    prompt = f"Generate as many possible typosquatting variations for the domain '{domain}':"
    if custom_prompt_choice == 'yes':
        prompt = input("Enter your custom prompt: ")

    domain_variations = generate_domains_with_gpt(prompt)

    data_list = []
    for variation in domain_variations:
        info = domain_info(variation)
        if info:
            data_list.append(get_domain_info(variation, info))

    report = generate_html_report(data_list)
    try:
        current_timestamp = int(time.time())
        filename = f"results_{current_timestamp}.html"

        with open(filename, "w") as f:
            f.write(report)
        webbrowser.open(filename)
    except Exception as e:
        print(f"Error generating or opening the report: {e}")
