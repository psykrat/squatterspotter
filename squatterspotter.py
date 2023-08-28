import requests
import dns.resolver
import re
import os
from dotenv import load_dotenv

load_dotenv()

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
        "max_tokens": 100
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
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        print(f"No A record found for {domain}: {e}")
    except dns.exception.DNSException as e:
        print(f"General DNS Error for A record in domain {domain}: {e}")

    try:
        info['MX'] = [answer.exchange.to_text() for answer in dns.resolver.resolve(domain, 'MX')]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        print(f"No MX record found for {domain}: {e}")
    except dns.exception.DNSException as e:
        print(f"General DNS Error for MX record in domain {domain}: {e}")

    try:
        info['NS'] = [answer.target.to_text() for answer in dns.resolver.resolve(domain, 'NS')]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        print(f"No NS record found for {domain}: {e}")
    except dns.exception.DNSException as e:
        print(f"General DNS Error for NS record in domain {domain}: {e}")

    return info

def display_domain_info(variation, info):
    print(f"[ALERT] Detected potential typosquatting domain: {variation}")
    print(f"IP Addresses (A records): {info.get('A', 'None')}")
    print(f"Mail Servers (MX records): {info.get('MX', 'None')}")
    print(f"Name Servers (NS records): {info.get('NS', 'None')}")
    
    malicious_ips = []
    for ip in info.get('A', []):
        is_malicious, score = is_ip_malicious(ip)
        if is_malicious:
            malicious_ips.append((ip, score))
            
    if malicious_ips:
        for ip, score in malicious_ips:
            print(f"Malicious IP Detected: {ip} with confidence score: {score}%")
    
    print('-' * 50)

if __name__ == "__main__":
    domain = input("Enter the domain name to check for typosquatting: ").strip()

    custom_prompt_choice = input("Would you like to use a custom prompt? (yes/no): ").strip().lower()
    prompt = f"Generate possible typosquatting variations for the domain '{domain}':"
    if custom_prompt_choice == 'yes':
        prompt = input("Enter your custom prompt: ")

    domain_variations = generate_domains_with_gpt(prompt)
    
    for variation in domain_variations:
        info = domain_info(variation)
        if info:
            display_domain_info(variation, info)
