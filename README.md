# SquatterSpotter

This tool identifies potential typosquatting variations of a specified domain using OpenAI's GPT-3.5. It then checks these variations for associated DNS records like A, MX, and NS, and further inspects if the IPs associated with the domains are malicious using AbuseIPDB.

## Features

- **Domain Variation Generator**: Uses GPT to generate possible typosquatting domains.
- **DNS Records Checker**: Fetches DNS records (A, MX, NS) for the generated domain variations.
- **Malicious IP Detector**: Verifies if the IPs associated with the domain variations are malicious.

## Prerequisites

- Python 3.x
- An `.env` file in the root directory with the following keys:
  ```
  OPENAI_API_KEY=<Your OpenAI API Key>
  ABUSEIPDB_API_KEY=<Your AbuseIPDB API Key>
  ```

## Setup and Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/psykrat/squatterspotter
   cd <repository-dir>
   ```

2. **Install Dependencies**:
   ```bash
   pip install requests dnspython python-dotenv
   ```

## Usage

1. **Run the Script**:
   ```bash
   python squatterspotter_v2.py
   ```
   
2. **Input Domain**: Provide the domain name you want to check.

3. **Optional Custom Prompt**: Choose if you'd like to use a custom prompt for domain generation.

4. **View Results**: After the script finishes processing, a report will automatically open in your default web browser, presenting the details of the domain variations.


## Contributing

Feel free to fork, open issues, or submit pull requests. Any contribution is welcome!

## License

This tool is open-source and is available under the MIT License.

## Author

Created by `psykrat`
