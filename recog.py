import csv
import os


try:
    import requests
    from bs4 import BeautifulSoup
    import re
    import time
    import argparse
    import json
    import requests
    from fake_headers import Headers
    import socket
    import dns.resolver
    import dns.zone 
    import whois
    import ssl
    import datetime
    from scapy.all import traceroute
    from ipwhois import IPWhois
    from facebook_scraper import get_posts
    from getpass import getpass
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from bs4 import BeautifulSoup
    from selenium.common.exceptions import NoSuchElementException 
except ModuleNotFoundError:
    print("Please download dependencies from requirements.txt")
except Exception as ex:
    print(ex)


def recog_logo():
    recog_ascii_art = r"""
         _           _             _             _            _        
        /\ \        /\ \         /\ \           /\ \         /\ \      
       /  \ \      /  \ \       /  \ \         /  \ \       /  \ \     
      / /\ \ \    / /\ \ \     / /\ \ \       / /\ \ \     / /\ \_\    
     / / /\ \_\  / / /\ \_\   / / /\ \ \     / / /\ \ \   / / /\/_/    
    / / /_/ / / / /_/_ \/_/  / / /  \ \_\   / / /  \ \_\ / / / ______  
   / / /__\/ / / /____/\    / / /    \/_/  / / /   / / // / / /\_____\ 
  / / /_____/ / /\____\/   / / /          / / /   / / // / /  \/____ / 
 / / /\ \ \  / / /______  / / /________  / / /___/ / // / /_____/ / /  
/ / /  \ \ \/ / /_______\/ / /_________\/ / /____\/ // / /______\/ /   
\/_/    \_\/\/__________/\/____________/\/_________/ \/___________/  
                                            coded by @github kes-hav
                                                                        
                                                           
    """

    print(recog_ascii_art)
def get_geolocation(ip_address):
    try:
        ipwhois = IPWhois(ip_address)
        result = ipwhois.lookup_rdap()
        
        print("Geolocation (ipwhois):")
        print(f"IP Address: {result['query']}")

        if 'asn_description' in result:
            print(f"ASN Description: {result['asn_description']}")
        if 'asn_cidr' in result:
            print(f"ASN CIDR: {result['asn_cidr']}")
        if 'asn_country_code' in result:
            print(f"ASN Country Code: {result['asn_country_code']}")

        if 'asn_registry' in result:
            print(f"ASN Registry: {result['asn_registry']}")
        if 'network' in result:
            net = result['network']
            if 'city' in net:
                print(f"City: {net['city']}")
            if 'region' in net:
                print(f"Region: {net['region']}")
            if 'country' in net:
                print(f"Country: {net['country']}")
            if 'latitude' in net and 'longitude' in net:
                print(f"Location: {net['latitude']}, {net['longitude']}")
    except Exception as e:
        print(f"Geolocation retrieval failed for {ip_address}: {e}")
def perform_traceroute(domain):
    try:
        print("Traceroute:")
     
        result, unans = traceroute(domain, maxttl=30)
        
     
        for sent, received in result:
            print(f"{sent.ttl}: {received.src}")
    except Exception as e:
        print(f"Traceroute failed for {domain}: {e}")


def ssl_certificate_analysis(domain):
    try:
       
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
       
        print("SSL Certificate Analysis:")
        subject = dict(x[0] for x in cert["subject"])
        issuer = dict(x[0] for x in cert["issuer"])
        valid_from = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        valid_until = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        common_name = subject.get("commonName", "N/A")
        issuer_common_name = issuer.get("commonName", "N/A")
        version = cert.get("version", "N/A")
        serial_number = cert.get("serialNumber", "N/A")
        san_names = ", ".join(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")
        
        print(f"Common Name (CN): {common_name}")
        print(f"Issuer Common Name: {issuer_common_name}")
        print(f"Valid From: {valid_from}")
        print(f"Valid Until: {valid_until}")
        print(f"Certificate Version: {version}")
        print(f"Serial Number: {serial_number}")
        print(f"Subject Alternative Names (SANs): {san_names}")
    except ssl.SSLError as e:
        print(f"SSL certificate retrieval failed for {domain}: {e}")
    except Exception as e:
        print(f"SSL certificate analysis failed for {domain}: {e}")


def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"The IP address of {domain} is: {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"DNS lookup failed for {domain}: {e}")

def reverse_dns_lookup(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)
        print(f"The domain name associated with IP {ip_address} is: {domain_name[0]}")
    except socket.herror as e:
        print(f"Reverse DNS lookup failed for IP {ip_address}: {e}")

def check_common_subdomains(domain):
    common_subdomains = ["www", "mail", "ftp", "admin", "blog"]
    for subdomain in common_subdomains:
        subdomain_domain = f"{subdomain}.{domain}"
        try:
            ip_address = socket.gethostbyname(subdomain_domain)
            print(f"Found subdomain: {subdomain_domain} ({ip_address})")
        except socket.gaierror:
            pass


def scan_open_ports(ip_address):
    common_ports = {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP (Server)",
        68: "DHCP (Client)",
        69: "TFTP",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        115: "SFTP",
        119: "NNTP",
        123: "NTP",
        135: "MSRPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        179: "BGP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "Microsoft-DS",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "Microsoft SQL Server",
        1521: "Oracle",
        3306: "MySQL",
        3389: "Remote Desktop Protocol",
        5900: "VNC",
        8080: "HTTP (Proxy)",
    }

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    print(f"Port {port} is open on {ip_address}. Service: {common_ports[port]}")
        except Exception as e:
            print(f"An error occurred while scanning port {port}: {e}")




def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        print(f"MX Records for {domain}:")
        for mx in mx_records:
            print(f"{mx.preference} {mx.exchange}")
    except dns.resolver.NoAnswer:
        print(f"No MX records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except Exception as e:
        print(f"An error occurred while retrieving MX records for {domain}: {e}")

def perform_whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print("Whois Information:")
        print(f"Domain Name: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Updated Date: {w.updated_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Domain Status: {w.status}")
        print(f"Name Servers: {w.name_servers}")
        print(f"DNSSEC Enabled: {w.dnssec}")
    except Exception as e:
        print(f"Whois lookup failed for {domain}: {e}")


def scrape_website_details(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()

    if response.status_code == 200:
        page_content = response.text
    else:
        print(f"Failed to retrieve the page. Status code: {response.status_code}")
        return None

    soup = BeautifulSoup(page_content, 'html.parser')

    title = soup.find('title').text.strip()
    description = soup.find('meta', attrs={"name": "description"})['content'].strip()

    links = [link.get('href') for link in soup.find_all('a') if link.get('href')]

    # Extract text content
    paragraphs = [p.text.strip() for p in soup.find_all('p') if p.text.strip()]

    # Extract image URLs
    image_urls = [img.get('src') for img in soup.find_all('img') if img.get('src')]

    metadata = {}
    meta_tags = soup.find_all('meta')
    for tag in meta_tags:
        if 'name' in tag.attrs and 'content' in tag.attrs:
            metadata[tag.attrs['name']] = tag.attrs['content']

    # Extract social media links
    social_media_links = [a.get('href') for a in soup.find_all('a') if 'social' in str(a).lower()]

    # Extract data from a specific HTML table (if available)
    table_data = []
    table = soup.find('table')
    if table:
        rows = table.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            row_data = [cell.text.strip() for cell in cells]
            table_data.append(row_data)

    # Extract email addresses using regex
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    email_addresses = re.findall(email_pattern, page_content)

    # User-defined CSS selector to extract specific section of the website
    user_defined_selector = 'div.some-section'  # Replace this with your desired selector

    specific_section_data = []
    specific_section = soup.select(user_defined_selector)
    for section in specific_section:
        section_data = section.text.strip()
        specific_section_data.append(section_data)

    response_headers = response.headers


    status_code = response.status_code

    response_time = end_time - start_time

    # Extract JavaScript-based content
    js_content = []
    scripts = soup.find_all('script')
    for script in scripts:
        if script.get('src'):
            js_content.append(script.get('src'))
        else:
            js_content.append(script.text.strip())

    # Extract CSS stylesheets
    css_stylesheets = []
    styles = soup.find_all('link', rel='stylesheet')
    for style in styles:
        if style.get('href'):
            css_stylesheets.append(style.get('href'))

    # Extract form fields
    form_fields = []
    forms = soup.find_all('form')
    for form in forms:
        form_fields.append([field.get('name') for field in form.find_all('input') if field.get('name')])

    # Extract headers
    headers = response.headers

    related_articles = [a['href'] for a in soup.find_all('a', rel='related')]

    # Scrape contact information (example: phone number and address)
    contact_info = {}
    phone_numbers = re.findall(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', page_content)
    addresses = re.findall(r'\d+\s+\w+.*\s\w+\b', page_content)
    if phone_numbers:
        contact_info['phone_numbers'] = phone_numbers
    if addresses:
        contact_info['addresses'] = addresses

  

    website_details = {
        'title': title,
        'description': description,
        'urls': links,
        'text_content': paragraphs,
        'image_urls': image_urls,
        'metadata': metadata,
        'social_media_links': social_media_links,
        'table_data': table_data,
        'email_addresses': email_addresses,
        'specific_section_data': specific_section_data,
        'response_headers': headers,
        'status_code': status_code,
        'response_time': response_time,
        'js_content': js_content,
        'css_stylesheets': css_stylesheets,
        'form_fields': form_fields,
        'related_articles': related_articles,
        'contact_info': contact_info,
      
    }

    return website_details

def check_sql_injection_vulnerability(url):
    try:
        # Add a single quote to the end of the URL and check for SQL error messages
        payload = url + "'"
        response = requests.get(payload)
        page_content = response.text

        # Check for common SQL error messages
        sql_error_patterns = [
            r"SQL syntax",
            r"mysql_fetch_array",
            r"mysql_fetch_assoc",
            r"mysql_fetch_row",
            r"ORA-01756",
            r"Microsoft OLE DB Provider for ODBC Drivers",
        ]

        for pattern in sql_error_patterns:
            if re.search(pattern, page_content, re.IGNORECASE):
                return True

    except Exception as e:
        print(f"An error occurred while checking SQL Injection vulnerability for {url}: {e}")

    return False

def check_xss_vulnerability(url):
    try:
        # Add a script tag as user-supplied data and check for its execution
        payload = f"{url}?data=<script>alert('XSS')</script>"
        response = requests.get(payload)
        page_content = response.text

        # Check if the script is executed
        if "<script>alert('XSS')</script>" in page_content:
            return True

    except Exception as e:
        print(f"An error occurred while checking XSS vulnerability for {url}: {e}")

    return False

def check_csrf_vulnerability(url):
    try:
        response = requests.get(url)
        page_content = response.text

        soup = BeautifulSoup(page_content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            csrf_token = form.find('input', {'name': 'csrf_token'})
            if not csrf_token:
                return True

    except Exception as e:
        print(f"An error occurred while checking CSRF vulnerability for {url}: {e}")

    return False

def check_clickjacking_vulnerability(url):
    try:
        response = requests.get(url)
        headers = response.headers
        x_frame_options = headers.get("X-Frame-Options", "")
        
        if x_frame_options.lower() == "deny" or "sameorigin" in x_frame_options.lower():
            return False
        else:
            return True

    except Exception as e:
        print(f"An error occurred while checking Clickjacking vulnerability for {url}: {e}")
        return False

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        required_headers = [
            'Content-Security-Policy',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            # Add other required security headers here
        ]

        missing_headers = []
        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)

        return not bool(missing_headers), missing_headers

    except Exception as e:
        print(f"An error occurred while checking security headers for {url}: {e}")
        return False, []

def insta_scrap(proxy=None):
        recog_logo()
        username = input("Enter the Instagram username: ")
        result = Instagram.scrap(username, args.proxy)
        if result:
            print(result)



def webscrap():
    recog_logo()
    url = input("Enter the website link (e.g., https://www.example.com): ")
    details = scrape_website_details(url)
    if details:
        # Print website details ...
          if details:
            print("Website Details:")
            print(f"Title: {details['title']}")
            print(f"Description: {details['description']}")
            print("\nWebsite URLs:")
            for i, url in enumerate(details['urls'], start=1):
                print(f"{i}. {url}")

            print("\nText Content:")
            for i, content in enumerate(details['text_content'], start=1):
                print(f"{i}. {content}")

            print("\nImage URLs:")
            for i, image_url in enumerate(details['image_urls'], start=1):
                print(f"{i}. {image_url}")

            print("\nMetadata:")
            for key, value in details['metadata'].items():
                print(f"{key}: {value}")

            print("\nSocial Media Links:")
            for i, link in enumerate(details['social_media_links'], start=1):
                print(f"{i}. {link}")

            print("\nTable Data:")
            if details['table_data']:
                for i, row in enumerate(details['table_data'], start=1):
                    print(f"{i}. {row}")
            else:
                print("No table data found on the website.")

            print("\nEmail Addresses:")
            if details['email_addresses']:
                for i, email in enumerate(details['email_addresses'], start=1):
                    print(f"{i}. {email}")
            else:
                print("No email addresses found on the website.")

            print("\nSpecific Section Data:")
            if details['specific_section_data']:
                for i, section_data in enumerate(details['specific_section_data'], start=1):
                    print(f"{i}. {section_data}")
            else:
                print("No data found for the specific section.")

            print("\nHTTP Response Headers:")
            for key, value in details['response_headers'].items():
                print(f"{key}: {value}")

            print("\nStatus Code:", details['status_code'])
            print("Response Time (seconds):", details['response_time'])

            # print("\nJavaScript-based Content:")
            # for i, js_content in enumerate(details['js_content'], start=1):
            #     print(f"{i}. {js_content}")

            print("\nCSS Stylesheets:")
            for i, css_stylesheet in enumerate(details['css_stylesheets'], start=1):
                print(f"{i}. {css_stylesheet}")

            print("\nForm Fields:")
            if details['form_fields']:
                for i, fields in enumerate(details['form_fields'], start=1):
                    print(f"{i}. {', '.join(fields)}")
            else:
                print("No form fields found on the website.")

            print("\nRelated Articles:")
            for i, article in enumerate(details['related_articles'], start=1):
                print(f"{i}. {article}")

            print("\nContact Information:")
            for key, value in details['contact_info'].items():
                print(f"{key.capitalize()}: {', '.join(value)}")
        # Ask the user if they want to save the data to a CSV file
            save_csv = input("Do you want to save the website details in a CSV file? (y/n): ")
            if save_csv.lower() == "y":
                website_title = details['title'].strip().replace(" ", "_")
                filename = f"{website_title}_details.csv"

                try:
                    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                        fieldnames = ['Title', 'Description', 'URLs', 'Text Content', 'Image URLs', 'Metadata',
                                    'Social Media Links', 'Table Data', 'Email Addresses', 'Specific Section Data',
                                    'HTTP Response Headers', 'Status Code', 'Response Time', 'CSS Stylesheets',
                                    'Form Fields', 'Related Articles', 'Contact Information']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerow({
                            'Title': details['title'],
                            'Description': details['description'],
                            'URLs': ', '.join(details['urls']),
                            'Text Content': ', '.join(details['text_content']),
                            'Image URLs': ', '.join(details['image_urls']),
                            'Metadata': ', '.join(f"{key}: {value}" for key, value in details['metadata'].items()),
                            'Social Media Links': ', '.join(details['social_media_links']),
                            'Table Data': ', '.join(details['table_data']),
                            'Email Addresses': ', '.join(details['email_addresses']),
                            'Specific Section Data': ', '.join(details['specific_section_data']),
                            'HTTP Response Headers': ', '.join(f"{key}: {value}" for key, value in details['response_headers'].items()),
                            'Status Code': details['status_code'],
                            'Response Time': details['response_time'],
                            'CSS Stylesheets': ', '.join(details['css_stylesheets']),
                            'Form Fields': ', '.join(', '.join(fields) for fields in details['form_fields']),
                            'Related Articles': ', '.join(details['related_articles']),
                            'Contact Information': ', '.join(f"{key.capitalize()}: {', '.join(value)}" for key, value in details['contact_info'].items()),
                        })
                    print(f"Website details saved in {filename}")
                except Exception as e:
                    print(f"Error occurred while saving the CSV file: {e}")
            else:
                print("Website details were not saved.")
    else:
            print("Failed to scrape website details.")

def fb_comments():
    print('Enter Profile ID:')
    pro_id = input()
    print('Enter your Email or Phone Number:')
    em = input()
    password = getpass()
    posts = get_posts(pro_id, pages=4,credentials=(em,password),options={"comments":True})

    print("Fetching comments data...")
    all_comments = []

    for post in posts:
            post_text = post['post_text']
            comments_data = post['comments_full']

            for comment in comments_data:
                commenter_name = comment['commenter_name']
                comment_text = comment['comment_text'].replace("\n", "")

                comment_info = {
                    'Post Text': post_text,
                    'Commenter Name': commenter_name,
                    'Comment Text': comment_text
                }

                all_comments.append(comment_info)

                # Print the comment
                print(commenter_name, " : ", comment_text)

        # Ask user if they want to save the comments data in a CSV file
    save_csv = input("Do you want to save the comments data in a CSV file? (y/n): ")

    if save_csv.lower() == 'y':
            file_name = f"{pro_id}_comments.csv"
            with open(file_name, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Post Text', 'Commenter Name', 'Comment Text']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_comments)
            print(f"Comments data saved in '{file_name}'.")
    else:
            print("Comments data not saved.")

    
def tiktok():
    print('Enter username:')
    username = input()

    # Initialize the WebDriver with the appropriate driver (e.g., Chrome or Firefox)
    # Make sure to download the appropriate driver and specify its path.
    geckodriver_path = "geckodriver"  # Replace with the path to your geckodriver executable
    driver = webdriver.Firefox(executable_path=geckodriver_path)

    # Load the TikTok user profile page
    url = f"https://www.tiktok.com/@{username}"
    driver.get(url)

    # Wait for the page to load
    time.sleep(5)  # Adjust the waiting time as needed
    try:
        close_button = driver.find_element(By.CLASS_NAME, 'verify-bar-close--iconclose')
        close_button.click()
    except NoSuchElementException:
        pass
    # Scroll to the bottom of the page to load all the content (adjust the range according to your need)
    for _ in range(5):
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)

    page_source = driver.page_source
    soup = BeautifulSoup(page_source, 'html.parser')

    username_element = soup.find('h1', {'data-e2e': 'user-title'})

    # Extract the number of followers
    username_count = username_element.text if username_element else 'N/A'

    print(f"Username: {username_count}")

    userbio_element = soup.find('h2', {'data-e2e': 'user-bio'})

    # Extract the number of followers
    userbio_count = userbio_element.text if userbio_element else 'N/A'

    print(f"User bio: {userbio_count}")


    # Find the element with the specified data-e2e attribute
    followers_element = soup.find('strong', {'data-e2e': 'followers-count'})

    # Extract the number of followers
    followers_count = followers_element.text if followers_element else 'N/A'

    print(f"Number of Followers: {followers_count}")


    following_element = soup.find('strong', {'data-e2e': 'following-count'})

    # Extract the number of followers
    following_count = following_element.text if following_element else 'N/A'

    print(f"Number of Following: {following_count}")
    # Find the element with the specified data-e2e attribute
    likes_element = soup.find('strong', {'data-e2e': 'likes-count'})

    # Extract the number of followers
    likes_count = likes_element.text if likes_element else 'N/A'

    print(f"Number of Likes: {likes_count}")


    a_tags = soup.find_all('a')

    # Extract the href attributes and print them
    for a_tag in a_tags:
        href = a_tag.get('href')
        if href:
            print(f"Link: {href}")

    # Close the browser
    driver.quit()

        # Ask the user if they want to save the data to a CSV file
    save_csv = input("Do you want to save the TikTok data in a CSV file? (y/n): ")
    if save_csv.lower() == "y":
        profile_data = {
            "Username": username_count,
            "User bio": userbio_count,
            "Number of Followers": followers_count,
            "Number of Following": following_count,
            "Number of Likes": likes_count,
            "Links": [href for href in a_tags if a_tag.get('href')]
        }
        with open("tiktok_data.csv", "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["Username", "User bio", "Number of Followers", "Number of Following", "Number of Likes", "Links"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(profile_data)
        print("TikTok data saved in tiktok_data.csv")

def vuln_analysis():
     
    url = input("Enter the website link (e.g., https://www.example.com): ")

    if check_sql_injection_vulnerability(url):
        print("This website is vulnerable to SQL Injection.")
    else:
        print("This website is not vulnerable to SQL Injection.")

    if check_xss_vulnerability(url):
        print("This website is vulnerable to XSS.")
    else:
        print("This website is not vulnerable to XSS.")
    if check_csrf_vulnerability(url):
        print("This website is vulnerable to CSRF.")
    else:
        print("This website is not vulnerable to CSRF.")
    clickjacking_vulnerable = check_clickjacking_vulnerability(url)
    if clickjacking_vulnerable:
        print("This website is vulnerable to Clickjacking attacks.")
    else:
        print("This website is not vulnerable to Clickjacking.")

    secure, missing_headers = check_security_headers(url)
    if secure:
        print("This website has proper security headers.")
    else:
        print("This website is missing the following security headers:")
        for header in missing_headers:
            print(header)

def webdive():
    recog_logo()
    target_domain = input("Enter the target website (e.g., example.com): ")
    print("-----------")
    ip_address = dns_lookup( target_domain)
    if ip_address:
        check_common_subdomains( target_domain)
        reverse_dns_lookup(ip_address)
        perform_whois_lookup( target_domain)
        scan_open_ports(ip_address)  
        get_mx_records( target_domain)
        ssl_certificate_analysis( target_domain)
        perform_traceroute(ip_address)
        get_geolocation(ip_address) 

class Instagram:
    @staticmethod
    def build_param(username):
        params = {
            'username': username,
        }
        return params

    @staticmethod
    def build_headers(username):
        return {
            'authority': 'www.instagram.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'referer': f'https://www.instagram.com/{username}/',
            'sec-ch-prefers-color-scheme': 'dark',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Microsoft Edge";v="108"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': Headers().generate()['User-Agent'],
            'x-asbd-id': '198387',
            'x-csrftoken': 'VUm8uVUz0h2Y2CO1SwGgVAG3jQixNBmg',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': '0',
            'x-requested-with': 'XMLHttpRequest',
        }

    @staticmethod
    def make_request(url, params, headers, proxy=None):
        response = None
        if proxy:
            proxy_dict = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            response = requests.get(
                url, headers=headers, params=params, proxies=proxy_dict)
        else:
            response = requests.get(
                url, headers=headers, params=params)
        return response

    @staticmethod
    def scrap(username, proxy=None):
        try:
            headers = Instagram.build_headers(username)
            params = Instagram.build_param(username)
            response = Instagram.make_request('https://www.instagram.com/api/v1/users/web_profile_info/',
                                            headers=headers, params=params, proxy=proxy)
            if response.status_code == 200:
                profile_data = response.json()['data']['user']
                
                print("Profile data fetched successfully:")
                print(json.dumps(profile_data, indent=2))

                # Ask user if they want to save the profile data in a CSV file
                save_csv = input("Do you want to save the profile data in a CSV file? (y/n): ")

                if save_csv.lower() == 'y':
                    file_name = f"{username}_insta_profile.csv"
                    with open(file_name, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = profile_data.keys()
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerow(profile_data)
                    print(f"Profile data saved in '{file_name}'.")
                else:
                    print("Profile data not saved.")

            else:
                print('Error : ', response.status_code, response.text)
        except Exception as ex:
            print(ex)

    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Tool for web & social media scraping.")
    parser.add_argument("command", choices=["instagram", "webscrap", "webdive", "fbcomments", "vulnerability"], nargs='?', help="Specify 'instagram' to perform Instagram scraping, 'webscrap' to perform website scraping, 'webdive' to gather website information, 'fbcomments' to scrape Facebook comments, 'twitter' to scrape TikTok, or 'vulnerability' to perform vulnerability analysis on a website.")
    parser.add_argument("--proxy", help="Optional: Provide a proxy for the request in the format 'ip:port'. Only applicable for website scraping.")
    
    args = parser.parse_args()
    if args.command is None:
        recog_logo()
        print("Select an option:")
        print("1. Instagram Scraping")
        print("2. Website Scraping")
        print("3. Webdive")
        print("4. Facebook Comments Scraping")
        print("5. Twitter Scraping")
        print("6. Vulnerability Analysis - Perform vulnerability analysis on a website")

        try:
            option = int(input("Enter the number corresponding to your choice: "))
        except ValueError:
            print("Invalid input. Please enter a valid option (1 between 6).")
            exit()

        if option == 1:
            os.system('cls' if os.name == 'nt' else 'clear')
            insta_scrap(args.proxy)
        elif option == 2:
            os.system('cls' if os.name == 'nt' else 'clear')
            webscrap()
        elif option == 3:
            os.system('cls' if os.name == 'nt' else 'clear')
            webdive()
        elif option == 4:
            os.system('cls' if os.name == 'nt' else 'clear')
            fb_comments()
        elif option == 5:
            os.system('cls' if os.name == 'nt' else 'clear')
            tiktok()
        elif option == 6:
            os.system('cls' if os.name == 'nt' else 'clear')
            vuln_analysis()
        else:
            print("Invalid option. Please select a valid option (1 between 6).")
    else:
        if args.command == "instagram":
            insta_scrap(args.proxy)

        elif args.command == "webscrap":
            webscrap()
        elif args.command == "webdive":
            webdive()
        elif args.command == "fb":
            fb_comments()
        elif args.command == "tiktok":
            tiktok()
        elif args.command == "vulnerability":
            vuln_analysis()





        

