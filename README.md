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

* **ModSecurity (Apache module)** inspects incoming HTTP traffic and blocks malicious requests based on rule sets.
* **PinewoodStore** (example web app) is placed **behind the WAF**, so all traffic is filtered before reaching it.
* The **FastAPI dashboard** reads from `modsec_audit.log`, parses and categorizes traffic:

  * ✅ Normal Traffic
  * 🚫 Blocked Requests (rule violations like 406, 414)
  * 🔒 Attack Attempts (403 Forbidden)
* Logs can be **exported as CSV or PDF**, and cleared via a **Reset** function.

---

## 🔧 Building and Running

### 1. Clone the Repository

```bash
git clone https://github.com/yourname/modsec-docker
cd modsec-docker
```

### 2. Adjust Apache WAF Config

Edit the virtual host and WAF rule configuration file:

```bash
apache-modsec/apache-config/myapp.conf
```

Replace `PinewoodStore`-specific routing with your application’s reverse proxy rules if needed.

### 3. Launch the Environment

```bash
docker-compose up --build
```

This will spin up:

* `waf`: Apache2 + ModSecurity container
* `dashboard`: FastAPI log viewer and export interface (accessible at `http://localhost:8000`)

### 4. View the Dashboard

Open your browser and visit:

```
http://localhost:8000
```

Here, you'll see:

* Realtime stats on request types
* Breakdown of blocked and attack traffic
* Filtered views and export options

---

## 🔁 Switching to a Different App

To use this WAF stack for **another web application**:

1. Replace `PinewoodStore` config with your app’s setup:

   * Edit `apache-config/myapp.conf` to forward traffic to your app.
   * Ensure ports and domain names match your backend.
2. Rebuild and restart:

```bash
docker-compose down
docker-compose up --build
```

The FastAPI dashboard remains unchanged — it will parse any standard ModSecurity audit log.

---

## 📄 Features

* ✅ **WAF Protection** with Apache + ModSecurity
* 🖥️ **FastAPI Dashboard** for inspection and monitoring
* 📊 Export to **CSV** / **PDF**
* ♻️ **Reset logs** for clean testing
* 🔧 Easily adaptable to **any backend**

---

## 📂 Logs Location

ModSecurity logs are stored inside the container:

```
/var/log/apache2/modsec_audit.log
```

This file is **mounted and readable** by the dashboard for real-time analysis.

---

## 🛡️ Requirements

* Docker + Docker Compose
* Python 3.9+ (if running the dashboard outside Docker)
* Basic knowledge of Apache reverse proxy setup

---

## 📘 Example Use Case

This setup is currently demonstrated with the **PinewoodStore** app — an e-commerce demo — where:

* Common attacks like SQLi or XSS are blocked by ModSecurity.
* Attack traffic shows up as 403 in the dashboard.
* Blocked but non-malicious anomalies show up as 406/414.

## 🤝 License

MIT or your preferred open-source license.

Top
<img width="1280" alt="image" src="https://github.com/user-attachments/assets/9c61f416-7af3-449b-9a73-0aa788e65cc0" />


Bottom
<img width="1280" alt="image" src="https://github.com/user-attachments/assets/7c8f5372-70ea-4c31-84e4-4dc924d84bd6" />

New Feature - WAF Rule Management Console
![Modsecurity Frontend Dashboard with Rule Managment Feature](https://github.com/user-attachments/assets/182dd96e-fa26-411b-81f8-6e655a5a62ed)

Feature Upgrade - Create custom Rule form the Dashboard

<img width="1280" alt="image" src="https://github.com/user-attachments/assets/57626234-4596-4684-919d-83e3856b2e94" />










