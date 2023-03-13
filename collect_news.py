import requests
from bs4 import BeautifulSoup

# URL of the website
url = "https://ukr.net/"

# Make a GET request to fetch the raw HTML content
html_content = requests.get(url).text

# Parse the html content
soup = BeautifulSoup(html_content, "lxml")

# News Headlines
news_headlines = soup.find_all("title")

# Print the news headlines
for headline in news_headlines:
    print(headline.text)
