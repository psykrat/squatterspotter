# SquatterSpotter

Welcome to **SquatterSpotter**! This tool helps you identify potential typosquatting domain variations of your main domain and fetches their DNS records.

## What It Does

**SquatterSpotter** checks for domain names that are similar to the one you provide, which could be impersonating or riding off the familiarity of your domain. For each identified domain variation, the tool also retrieves and displays its DNS records.

## Setup

1. Ensure you have Python installed on your machine.
2. Install the necessary Python packages by running:
   ```
   pip install requests dnspython
   ```

3. You'll also need an API key from OpenAI for the domain name generation functionality. Make sure to replace the placeholder in the script with your actual API key.

## Usage

1. Navigate to the directory where you've saved `squatterspotter.py`.
2. Open a terminal or command prompt in that directory.
3. Run the script with:
   ```
   python squatterspotter.py
   ```

4. Follow the on-screen prompts to input your domain and other preferences, and the tool will display potential typosquatting domains and their DNS records.

## License

This tool is open-source and free to use. If sharing or re-purposing, kindly give appropriate credit. Please note that while this tool aims to identify potential typosquatting domains, it might not catch all of them.
