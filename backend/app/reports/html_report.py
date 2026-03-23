def build_html_report(result):
    return f"""
    <html>
      <head>
        <title>PhishGuard Report</title>
      </head>
      <body>
        <h1>PhishGuard Analysis Report</h1>
        <pre>{result}</pre>
      </body>
    </html>
    """
