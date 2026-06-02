import requests
from bs4 import BeautifulSoup

URL = "https://r.jina.ai/https://www.trellix.com/downloads/security-updates/" # A website designed for practicing scraping

try:
    # Step 1: Fetch the HTML content
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, "html.parser")

    print(page.content)

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
