# katana - Website Security Analysis With AI Agents

## AI Agents for Ultimate Vulnerability Detection

Welcome to Katana, the cutting-edge tool that uses multiple collaborative AI agents to actively detect website security issues. The ultimate synergy of advanced technology and intelligent agents to keep your online assets safe.

![AI Agents for Web security scanning](assets/Katana_Armur.png)

### Key Features

- **AI Agent Integration:** Uses AI to detect and analyze vulnerabilities in real-time.
- **Advanced Technology Stack:** Utilizing state-of-the-art tools and frameworks for robust security scanning.
- **Detailed Reporting:** Receive comprehensive reports with actionable insights to mitigate risks.


## Overview
This project performs a comprehensive security analysis of a website using various tools and APIs. The analysis includes network logs, DOM data extraction, and identification of potential vulnerabilities. The project uses the following tools and libraries:

- **Llama 3 8B**
- **Groq**
- **Google Colab Selenium**
- **Crew AI**
- **Exa AI**

## Setup Instructions
To set up the project, follow these steps:

1. Install the required packages:
    ```bash
    !pip -q install crewai duckduckgo-search
    !pip -q install 'crewai[tools]' decouple langchain-exa exa_py==1.0.7
    !pip install langchain_groq
    !pip install -q google-colab-selenium[undetected]
    !pip install beautifulsoup4
    ```

2. Obtain API keys for Groq and Exa:
    - [Groq API key](https://console.groq.com/)
    - [Exa API key](https://dashboard.exa.ai/playground/)

3. Load the API keys into environment variables:
    ```python
    import os
    from google.colab import userdata

    os.environ["GROQ_API_KEY"] = userdata.get('GROQ_API_KEY')
    os.environ["EXA_API_KEY"] = userdata.get('EXA_API_KEY')
    ```

## Usage Instructions
1. **Enter the URL for analysis**:
    ```python
    url = input("Enter Your URL: ")
    ```

2. **Extract Network Logs and DOM Data**:
    ```python
    import google_colab_selenium as gs
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

    options = Options()
    dc = DesiredCapabilities.CHROME
    dc["goog:loggingPrefs"] = {"browser":"ALL"}
    dc["goog:loggingPrefs"] = {"performance":"ALL"}

    driver = gs.Chrome(options=options)
    driver.get(url)
    try:
        logs = driver.get_log('performance')  # Initializing
    except:
        o=0
    driver.close()
    options = Options()
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--incognito")

    driver = gs.UndetectedChrome(options=options)
    driver.get(url)
    src = driver.page_source
    network_logs = driver.get_log('performance')

    network_list = list(network_logs)
    driver.quit()
    ```

3. **Analyze Network Data**:
    ```python
    import json
    import re
    from collections import defaultdict

    extracted_data = {
        'http_requests': [],
        'resources': [],
        'webview_actions': [],
    }

    def extract_meaning_from_log_strings(log_string):
        try:
            log_entry = json.loads(log_string)
            message = log_entry['message']
            params = message['params']

            if 'requestWillBeSent' in message['method']:
                request_data = {
                    'url': params['request']['url'],
                    'method': params['request']['method'],
                    'headers': params['request']['headers'],
                    'initiator': params['initiator']['url'] if 'initiator' in params else None,
                }
                extracted_data['http_requests'].append(request_data)
            elif 'responseReceived' in message['method']:
                response_data = {
                    'url': params['response']['url'],
                    'status_code': params['response']['status'],
                    'headers': params['response']['headers'],
                }
                extracted_data['http_requests'].append(response_data)

            if 'type' in params:
                resource_type = params['type']
                extracted_data['resources'].append({
                    'url': params['response']['url'],
                    'type': resource_type,
                })

            if 'domContentEventFired' in message['method']:
                extracted_data['webview_actions'].append({'action': 'DOMContentLoaded'})
            elif 'loadEventFired' in message['method']:
                extracted_data['webview_actions'].append({'action': 'loadEventFired'})

        except json.JSONDecodeError:
            pass

    for l in network_list:
        extract_meaning_from_log_strings((l['message']))

    def analyze_network_data(network_data):
        resource_counts = defaultdict(int)
        url_domains = defaultdict(set)
        http_request_observations = []
        third_party_domains = set()

        for data_point in network_data['http_requests']:
            url = data_point['url']
            resource_type = data_point.get('type', 'Unknown')
            resource_counts[resource_type] += 1

            match = re.search(r'https?://([^/]+)', url)
            if match:
                domain = match.group(1)
                url_domains[domain].add(url)

                if 'initiator' in data_point and domain != re.search(r'https?://([^/]+)', data_point['initiator']).group(1):
                    third_party_domains.add(domain)

            if 'headers' in data_point:
                headers = data_point['headers']
                if 'Content-Security-Policy' in headers:
                    csp_value = headers['Content-Security-Policy']
                    if 'unsafe-inline' in csp_value or 'unsafe-eval' in csp_value:
                        http_request_observations.append(f"Potentially insecure Content-Security-Policy: {csp_value} in request for {url}")
                if 'X-Frame-Options' in headers:
                    xfo_value = headers['X-Frame-Options']
                    if xfo_value.lower() != 'deny':
                        http_request_observations.append(f"Potentially insecure X-Frame-Options: {xfo_value} in request for {url}")

        num_domains = len(url_domains)
        most_frequent_domain = max(url_domains, key=lambda k: len(url_domains[k]))

        if 'resources' in network_data:
            for resource in network_data['resources']:
                url = resource['url']
                resource_type = resource['type']
                resource_counts[resource_type] += 1
                match = re.search(r'https?://([^/]+)', url)
                if match:
                    domain = match.group(1)
                    url_domains[domain].add(url)

        return {
            'resource_counts': dict(resource_counts),
            'url_domains': dict(url_domains),
            'http_request_observations': http_request_observations,
            'num_domains': num_domains,
            'most_frequent_domain': most_frequent_domain,
            'third_party_domains': list(third_party_domains)
        }

    total = analyze_network_data(extracted_data)
    print(extracted_data)
    print(total)
    ```

4. **Identify Vulnerable Tags**:
    ```python
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(src, 'html.parser')
    title = soup.title  # Get the page title
    links = soup.find_all('a')
    inputs = soup.find_all('input')
    forms = soup.find_all('form')
    scripts = soup.find_all('script')
    ```

5. **Network Access Result**:
    ```python
    Network_context = '''
    \n\n Network Logs + potential flaws:
    Observations : ''' + str(total['resource_counts']) + '''
    Flaws : ''' + str(network_issues)

    Code_context = '''\n Source Code :
    scripts : ''' + str(scripts)

    print(Network_context)
    ```

## Using EXA Search Tool
1. **Search Tool - EXA**:
    ```python
    from exa_py import Exa
    from langchain.agents import tool

    class ExaSearchTool:
        @tool
        def search(query: str):
            """Search for a webpage based on the query."""
            return ExaSearchTool._exa().search(f"{query}", use_autoprompt=True, num_results=3)

        @tool
        def search_and_contents(url: str):
            """
            Get the searches and contents of a given url
            """
            return ExaSearchTool._exa().search_and_contents(url, num_results=3)

        @tool
        def get_contents(ids: str):
            """Get the contents of a webpage.
            The ids must be passed in as a list, a list of ids returned from `search`.
            """
            ids = eval(ids)
            contents = str(ExaSearchTool._exa().get_contents(ids))
            print(contents)
            contents = contents.split("URL:")
            contents = [content[:1000] for content in contents]
            return "\n\n".join(contents)

        def tools():
            return [ExaSearchTool.search, ExaSearchTool.search_and_contents, ExaSearchTool.get_contents]

        def _exa():
            return Exa(api_key=os.environ["EXA_API_KEY"])
    ```

## Creating Groq Pipeline to Llama 3 8B
1. **Initialize Llama 3**:
    ```python
    from langchain_groq import ChatGroq
    llama3 = ChatGroq(
        api_key=os.environ["GROQ_API_KEY"],
        model_name="llama3-8b-8192"
    )
    ```

## Defining Security Analysis Agents
1. **Agents**:
    ```python
    from textwrap import dedent
    from crewai import Agent

    class SecurityAnalysisAgents:
        def industry_analysis_agent(self):
            return Agent(
                role='Industry Analyst',
                goal='Analyze the current
