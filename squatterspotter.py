import requests
import dns.resolver
import re

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
API_KEY = "sk-example"

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
        print("Sending prompt to OpenAI:", prompt)
        response = requests.post(OPENAI_API_URL, headers=headers, json=data)
        response.raise_for_status()

        output = response.json()['choices'][0]['message']['content'].strip().split("\n")
        domain_variations = [re.sub(r'^\d+\.\s+', '', domain) for domain in output]
        print("Response from GPT:", domain_variations)
        return domain_variations

    
    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"Error using OpenAI API: {e}")
        return []

def domain_info(domain):
    
    info = {}

    try:
        print(f"Checking A records for domain: {domain}")
        info['A'] = [answer.address for answer in dns.resolver.resolve(domain, 'A')]
        
        print(f"Checking MX records for domain: {domain}")
        info['MX'] = [answer.exchange.to_text() for answer in dns.resolver.resolve(domain, 'MX')]
        
        print(f"Checking NS records for domain: {domain}")
        info['NS'] = [answer.target.to_text() for answer in dns.resolver.resolve(domain, 'NS')]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        print(f"Exception for domain {domain}: {e}")
        return None
    except dns.exception.DNSException as e:
        print(f"General DNS Exception for domain {domain}: {e}")
        return None

    return info

def display_domain_info(variation, info):
    print(f"[ALERT] Detected potential typosquatting domain: {variation}")
    print(f"IP Addresses (A records): {info.get('A', 'None')}")
    print(f"Mail Servers (MX records): {info.get('MX', 'None')}")
    print(f"Name Servers (NS records): {info.get('NS', 'None')}")
    print('-' * 50)

if __name__ == "__main__":
    domain = input("Enter the domain name to check for typosquatting: ").strip()
    use_custom_prompt = input("Would you like to use a custom prompt? (yes/no): ").strip().lower()

    prompt = input("Enter your custom prompt: ") if use_custom_prompt == 'yes' else f"Generate possible typosquatting variations for the domain '{domain}':"

    domain_variations = generate_domains_with_gpt(prompt)
    
    for variation in domain_variations:
        print("Checking domain:", variation)
        info = domain_info(variation)
        if info:
            display_domain_info(variation, info)
