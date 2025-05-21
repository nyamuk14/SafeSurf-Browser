# SafeSurf Browser

> ⚠️ **Project Status:** This project is still under active development and maintenance.

---

**SafeSurf** is a secure desktop web browser built using Electron, designed to protect users from phishing threats, unsafe downloads, and insecure HTTP connections.

## Features

- Real-time phishing detection using Google Safe Browsing & VirusTotal APIs  
- Safe download management with malware scanning via URLHaus  
- Automatic redirection from HTTP to HTTPS

## 📦 Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/nyamuk14/SafeSurf-Browser.git
   cd SafeSurf-Browser
   ```

2. Install dependencies:

    ```bash
    npm install
    ```

3. Set up API keys:

   Create `.env` file and add your API keys:

   ```bash
   GOOGLE_SAFE_BROWSING_API_KEY=your-gsb-key
   VIRUS_TOTAL_API_KEY=your-vt-key
   ```

4. Run the app:

   ```bash
    npm start
   ```

## 📜 License

This project is open-sourced under the MIT License.
