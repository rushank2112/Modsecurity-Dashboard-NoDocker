# ModSecurity WAF with FastAPI Dashboard – PinewoodStore Example

This project demonstrates a **Dockerized deployment of ModSecurity** as a Web Application Firewall (WAF), integrated with a custom **FastAPI-based monitoring dashboard**. The example application used is **PinewoodStore**, but the setup can be adapted to protect **any other web application** by modifying configuration.

---

## 📦 Project Structure

```
modsec-docker/
├── apache-modsec/
│   ├── apache-config/
│   │   └── myapp.conf        # Apache virtual host & ModSecurity rules for PinewoodStore
│   └── Dockerfile            # Builds Apache + ModSecurity container
├── dashboard/
│   ├── main.py               # FastAPI dashboard backend
│   ├── templates/            # Jinja2 HTML templates for logs and dashboard
│   └── requirements.txt      # Python dependencies
├── docker-compose.yml        # Defines WAF and dashboard services
└── README.md                 # You are here
```

---

## 🚀 How It Works

* **ModSecurity (Apache module)** is installed directly on your Linux host. It inspects incoming HTTP traffic and blocks malicious requests based on rule sets (like OWASP CRS).
* Your web application (if any) is configured to sit **behind the Apache WAF**, so all traffic is filtered before reaching it.
* The **FastAPI dashboard** runs as a separate Python application on your host, reading directly from the ModSecurity audit log file (`/var/log/apache2/modsec_audit.log`). It parses and categorizes traffic:
    * ✅ Normal Traffic
    * 🚫 Blocked Requests (rule violations like 406, 414)
    * 🔒 Attack Attempts (403 Forbidden)
* Logs can be **exported as CSV or PDF**, and cleared via a **Reset** function on the dashboard.

---

## 🔧 Building and Running (Manual Setup)

This section details how to set up and run the Modsecurity Dashboard and its underlying ModSecurity WAF directly on a Linux host, without Docker.

**Operating System:** These instructions are primarily for **Ubuntu/Debian-based Linux distributions**. Adaptations may be needed for other operating systems.

**Prerequisites:**

* A fresh Ubuntu/Debian system (physical or virtual machine).
* `sudo` privileges.
* Basic familiarity with Linux command line and Apache configuration.

---

### **Part 1: Setup Apache2 with ModSecurity and OWASP CRS**

This sets up your Web Application Firewall (WAF).

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/enochgitgamefied/Modsecurity-Dashboard-NoDocker.git](https://github.com/enochgitgamefied/Modsecurity-Dashboard-NoDocker.git)
    cd Modsecurity-Dashboard-NoDocker
    ```

2.  **Install Apache2 and ModSecurity Components:**

    ```bash
    sudo apt update
    sudo apt install -y apache2 libapache2-mod-security2 modsecurity-crs
    ```

3.  **Enable Apache Modules and Restart:**

    ```bash
    sudo a2enmod rewrite proxy proxy_http ssl # Enable if you plan to use SSL
    sudo systemctl restart apache2
    ```

4.  **Configure ModSecurity Core:**

    * **Activate Recommended Configuration:**
        ```bash
        sudo mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        ```

    * **Enable ModSecurity Engine:**
        Open `/etc/modsecurity/modsecurity.conf` and change the `SecRuleEngine` directive from `DetectionOnly` to `On`.
        ```bash
        sudo nano /etc/modsecurity/modsecurity.conf
        # Change:
        # SecRuleEngine DetectionOnly
        # To:
        SecRuleEngine On
        ```

    * **Configure Audit Logging (Crucial for Dashboard):**
        Ensure these lines are present and configured for serial logging to a single file, as the dashboard expects this format.
        ```bash
        # In /etc/modsecurity/modsecurity.conf
        SecAuditEngine On
        SecAuditLogType Serial
        SecAuditLog /var/log/apache2/modsec_audit.log # This is the file the dashboard will read
        SecAuditLogParts ABCEFHIJZ # Basic parts needed for dashboard analysis
        ```
        Make a note of `/var/log/apache2/modsec_audit.log` as you'll need it for dashboard setup confirmation.

5.  **Configure OWASP Core Rule Set (CRS):**

    * The `modsecurity-crs` package usually handles this by placing a `crs-setup.conf` in `/usr/share/modsecurity-crs/`.
    * Ensure your Apache virtual host includes these rules.

6.  **Create/Adjust Apache WAF Virtual Host Configuration:**

    You'll create a new Apache Virtual Host file for your protected application.

    ```bash
    sudo nano /etc/apache2/sites-available/001-modsec-waf.conf
    ```
    Add the following content (replace `your_modsec_domain.com` with your desired domain or IP address, or `localhost` for local testing):

    ```apache
    <VirtualHost *:80>
        ServerName your_modsec_domain.com
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        <IfModule security2_module>
            SecRuleEngine On
            # Include the main ModSecurity configuration
            Include /etc/modsecurity/modsecurity.conf

            # Include the CRS setup and rules
            IncludeOptional /usr/share/modsecurity-crs/crs-setup.conf
            IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
        </IfModule>

        # Optional: Reverse proxy to your backend application
        # Replace http://your_app_host:your_app_port/ with your actual application's address
        # For simple testing, you can point this to a basic HTTP server or leave it out if just testing ModSec rules
        ProxyRequests Off
        ProxyPreserveHost On
        ProxyPass / http://localhost:8081/ # Example: point to a dummy local app or default Apache page
        ProxyPassReverse / http://localhost:8081/

        # If not using ProxyPass, define your DocumentRoot for static content
        # DocumentRoot /var/www/html
    </VirtualHost>
    ```

7.  **Enable Virtual Host and Restart Apache:**

    ```bash
    sudo a2ensite 001-modsec-waf.conf
    sudo a2dissite 000-default.conf # Disable default site to avoid conflicts
    sudo apache2ctl configtest # Check for syntax errors
    sudo systemctl restart apache2
    ```

---

### **Part 2: Setup and Run the FastAPI Dashboard**

This part sets up the GUI for viewing ModSecurity logs and managing rules.

1.  **Install Python 3.9+ and pip:**

    ```bash
    sudo apt install -y python3 python3-pip python3-venv
    ```

2.  **Install WeasyPrint System Dependencies:**
    The dashboard uses `WeasyPrint` (for PDF export), which requires several system-level libraries.

    ```bash
    sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
    # Optional, but often needed by other WeasyPrint features:
    sudo apt install -y libharfbuzz0b libjpeg-dev libopenjp2-7-dev libwebp-dev
    ```

3.  **Navigate to Dashboard Directory and Setup Virtual Environment:**

    ```bash
    cd dashboard # Assuming you are in the root of the cloned repo
    python3 -m venv venv
    source venv/bin/activate
    ```

4.  **Install Python Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

5.  **Configure Dashboard Log Permissions:**

    * **Grant Dashboard Read Permissions:** The user running the dashboard (your current user if you run it directly, or a service user if daemonized) needs read access to the log file.
        ```bash
        sudo chmod o+r /var/log/apache2/modsec_audit.log
        ```
        (This command assumes `www-data:adm` ownership for the log file and your user is not in the `adm` group. If your user is in `adm`, `sudo chmod g+r /var/log/apache2/modsec_audit.log` would suffice.)

6.  **Run the Dashboard Application:**

    With your virtual environment activated (`(venv)` prefix in your prompt), execute:

    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000
    ```

---

### **View the Dashboard**

Once `uvicorn` is running, open your web browser and visit:

```
http://localhost:8000
```

Here, you'll see:

* Realtime stats on request types
* Breakdown of blocked and attack traffic
* Filtered views and export options

---

## 🔁 Switching to a Different App

To use this WAF with a different web application:

1.  **Edit Apache Virtual Host:**
    Modify the `ProxyPass` and `ProxyPassReverse` directives in `/etc/apache2/sites-available/001-modsec-waf.conf` to forward traffic to your new application's address.
2.  **Reload Apache:**
    ```bash
    sudo systemctl reload apache2
    ```
    The FastAPI dashboard remains unchanged — it will continue to parse the ModSecurity audit logs generated by Apache, regardless of the backend application.

---

## 📄 Features

* ✅ **WAF Protection** with Apache + ModSecurity
* 🖥️ **FastAPI Dashboard** for inspection and monitoring
* 📊 Export to **CSV** / **PDF**
* ♻️ **Reset logs** for clean testing
* 🔧 Easily adaptable to **any backend**

---

## 📂 Logs Location

ModSecurity audit logs are generated by Apache and stored on the host system at:
`/var/log/apache2/modsec_audit.log`

This file is directly read by the FastAPI dashboard for real-time analysis. Ensure the user running the dashboard has read permissions to this file.

---

## 🛡️ Requirements

* **Operating System:** Ubuntu/Debian Linux (recommended for these instructions).
* **Apache2:** Web server.
* **ModSecurity:** Web Application Firewall module for Apache.
* **OWASP Core Rule Set (CRS):** Default rules for ModSecurity.
* **Python 3.9+:** For the FastAPI dashboard.
* **Python Libraries:** Installed via `pip install -r requirements.txt`.
* **System Libraries for WeasyPrint:** `libpango-1.0-0`, `libpangoft2-1.0-0`, `libcairo2`, `libgdk-pixbuf2.0-0`, `libffi-dev`, `shared-mime-info`, etc.
* Basic knowledge of Apache configuration and Linux command line.

---

## 📘 Example Use Case

This setup can be used to protect any web application. In a typical scenario:

* Common attacks like SQLi or XSS are blocked by ModSecurity.
* Attack traffic shows up as 403 in the dashboard.
* Blocked but non-malicious anomalies may show up as 406/414 depending on rules.

## 🤝 License

MIT or your preferred open-source license.

---

<img width="1280" alt="image" src="https://github.com/user-attachments/assets/9c61f416-7af3-449b-9a73-0aa788e65cc0" />

<img width="1280" alt="image" src="https://github.com/user-attachments/assets/7c8f5372-70ea-4c31-84e4-4dc924d84bd6" />

### New Feature - WAF Rule Management Console
![Modsecurity Frontend Dashboard with Rule Managment Feature](https://github.com/user-attachments/assets/182dd96e-fa26-411b-81f8-6e655a5a62ed)

### Feature Upgrade - Create custom Rule form the Dashboard
<img width="1280" alt="image" src="https://github.com/user-attachments/assets/57626234-4596-4684-919d-83e3856b2e94" />









