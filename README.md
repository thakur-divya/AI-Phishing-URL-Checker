# AI-Based Phishing URL Detection & Risk Analysis Platform

An threat intelligence platform that analyzes URLs in real-time to detect zero-day phishing attacks. It utilizes a multi-tiered architecture combining traditional Machine Learning (XGBoost), Deep Learning (Character-level LSTM), Open Source Intelligence (OSINT), and dynamic DOM scraping.

## System Architecture: The 3-Tier Defense

To optimize for both speed and accuracy, the platform routes URLs through a progressive gating system. If a definitive threat is detected early, the scan short-circuits to save compute resources.

### Tier 1: Mathematical & Heuristic Analysis (< 50ms)

* **XGBoost ML Core:** Analyzes 18 distinct lexical features (URL length, directory depth, symbol counts) extracted from the URL string.

* **TensorFlow Sequence Core:** A Bidirectional LSTM Neural Network that treats the URL as a sequential character array to detect complex obfuscation patterns that traditional tabular models miss.

* **IP Masquerade Check:** Instantly flags URLs attempting to hide behind raw IPv4 addresses (e.g., `http://192.168.1.1/login.php`).

### Tier 2: Open Source Intelligence (OSINT) (1-2s)

* **Domain Age Verification:** Integrates with the `WHOIS` API to calculate the domain's age. Phishing domains are heavily penalized if they were registered within the last 30 days.

* **VirusTotal Threat Fusion:** Cross-references the URL against 70+ global security vendors using the VirusTotal v3 API.

### Tier 3: Payload & DOM Analysis (3-8s)

* **Static Scraping (`BeautifulSoup`):** Inspects the HTML for insecure `<input type="password">` forms on non-HTTPS connections.

* **Dynamic Headless Scraping (`Selenium`):** If heavy JavaScript obfuscation is detected, the system spins up a headless Chrome browser to fully render the DOM and hunt for invisible `<iframe>` traps and JS-rendered credential harvesting forms.

## Frontend Presentation

The platform features a responsive, **Glassmorphism-styled dashboard** built with HTML, CSS (Tailwind utilities), and vanilla JavaScript.

* **Dynamic Theming:** The UI automatically shifts its color palette (Green/Yellow/Red) based on the calculated Threat Risk Score.

* **Live Signal Tracking:** Displays exactly which intelligence signals (e.g., Domain Length, VirusTotal flags, Payload traps) contributed to the final verdict.

## Local Setup & Installation

**Prerequisites:** Python 3.11+ (Recommended for Apple Silicon / M-Series compatibility).

1. **Clone the repository:**

   ```bash
   git clone [https://github.com/Cy-Jones/AI-Phishing-URL-Checker.git](https://github.com/Cy-Jones/AI-Phishing-URL-Checker.git)
   cd AI-Phishing-URL-Checker
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the required dependencies:**

   ```bash
   pip install flask flask-cors pandas scikit-learn xgboost beautifulsoup4 selenium webdriver-manager python-whois requests tensorflow
   ```

4. **Configure Environment Variables:**

   Create a `.env` file in the root directory and add your VirusTotal API key:

   ```env
   VT_API_KEY=your_virustotal_api_key_here
   ```

5. **Run the Application:**

   ```bash
   python app.py
   ```

   *The server will start on `http://127.0.0.1:5001`. (Port 5001 is used to bypass macOS AirPlay port collisions).*


