import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List, Set
import re

class WebCrawler:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.visited_urls: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'XSS-Detector/1.0'
        })

    def extract_links(self, url: str) -> List[str]:
        try:
            response = self.session.get(url, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                if self.base_url in absolute_url:
                    links.append(absolute_url)
            return links
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")
            return []

    def crawl(self, max_depth: int = 3) -> Set[str]:
        to_visit = {(self.base_url, 0)}
        while to_visit:
            url, depth = to_visit.pop()
            if depth > max_depth:
                continue
            if url not in self.visited_urls:
                self.visited_urls.add(url)
                print(f"Crawling: {url}")
                links = self.extract_links(url)
                for link in links:
                    if link not in self.visited_urls:
                        to_visit.add((link, depth + 1))
        return self.visited_urls

    def find_forms(self, url: str) -> List[dict]:
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            for form in soup.find_all('form'):
                form_details = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                for input_tag in form.find_all('input'):
                    form_details['inputs'].append({
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type'),
                        'value': input_tag.get('value', '')
                    })
                forms.append(form_details)
            return forms
        except Exception as e:
            print(f"Error finding forms at {url}: {str(e)}")
            return []
