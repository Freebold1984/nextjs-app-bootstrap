import argparse
from .crawler import WebCrawler
from .detector import XSSDetector
import json
from datetime import datetime
import os

def generate_report(results: list, format: str = 'json') -> str:
    """Generate vulnerability report in specified format"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = {
        'metadata': {
            'timestamp': timestamp,
            'vulnerabilities_found': len(results),
            'tool_version': '1.0.0'
        },
        'findings': results
    }

    if format == 'json':
        return json.dumps(report, indent=2)
    elif format == 'html':
        return generate_html_report(report)
    else:
        return str(report)

def generate_html_report(report: dict) -> str:
    """Generate HTML formatted report"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Scan Report - {report['metadata']['timestamp']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; }}
            .critical {{ background-color: #ffebee; border-left: 5px solid #f44336; }}
            .high {{ background-color: #fff8e1; border-left: 5px solid #ffc107; }}
            .medium {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; }}
        </style>
    </head>
    <body>
        <h1>XSS Vulnerability Report</h1>
        <p>Generated on {report['metadata']['timestamp']}</p>
        <p>Total vulnerabilities found: {report['metadata']['vulnerabilities_found']}</p>
    """

    for finding in report['findings']:
        severity = 'critical' if finding['confidence'] > 0.9 else 'high' if finding['confidence'] > 0.7 else 'medium'
        html += f"""
        <div class="vulnerability {severity}">
            <h3>{finding['url']}</h3>
            <p><strong>Form Action:</strong> {finding['form_action']}</p>
            <p><strong>Input Field:</strong> {finding['input_name']}</p>
            <p><strong>Payload:</strong> <code>{finding['payload']}</code></p>
            <p><strong>Confidence:</strong> {finding['confidence']:.2f}</p>
            <p><strong>Type:</strong> {finding['type'].capitalize()} XSS</p>
        </div>
        """

    html += """
    </body>
    </html>
    """
    return html

def main():
    parser = argparse.ArgumentParser(description='AI-powered XSS Detection Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('url', nargs='?', help='Target URL to scan')
    group.add_argument('--test-payload', help='Test a specific payload')
    parser.add_argument('--depth', type=int, default=3, help='Crawling depth')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'html'], default='json', help='Report format')

    args = parser.parse_args()

    detector = XSSDetector()
    
    if args.test_payload:
        print(f"[*] Testing payload: {args.test_payload}")
        result = detector.detect_xss(args.test_payload)
        report = generate_report([{
            'url': 'TEST_PAYLOAD',
            'form_action': 'N/A',
            'input_name': 'N/A',
            'payload': args.test_payload,
            'confidence': 1.0 if result else 0.0,
            'type': 'reflected' if result else 'none'
        }], args.format)
    else:
        print(f"[*] Starting XSS scan for {args.url}")
        crawler = WebCrawler(args.url)
        
        # Crawl target website
        print("[*] Crawling website...")
        urls = crawler.crawl(args.depth)
        print(f"[*] Found {len(urls)} pages to scan")

        # Scan each page
        results = []
        for url in urls:
            print(f"[*] Scanning {url}")
            forms = crawler.find_forms(url)
            if forms:
                findings = detector.scan_page(url, forms)
                results.extend(findings)

        # Generate report
        report = generate_report(results, args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[*] Report saved to {args.output}")
    else:
        print(report)

if __name__ == '__main__':
    main()
