# Kerio Control UTM → Wazuh SIEM

**English** | [Русский](README.ru.md)

Stream critical security events from **Kerio Control UTM** (Intrusion Prevention System (IPS), Gateway Antivirus, network attacks, and Anti-hammering / brute-force protection) into **Wazuh SIEM**: Syslog collection over UDP 514, log normalization, detection rules, and event correlation. Alerts with severity level 10 and above are forwarded to Telegram.

Compatibility: Kerio Control 9.x, Wazuh 4.x.

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Wazuh Manager Installation](#2-wazuh-manager-installation)
3. [Kerio Control Configuration](#3-kerio-control-configuration)
4. [Verification](#4-verification)
5. [deploy.sh Commands](#5-deploysh-commands)
6. [Detection Rules](#6-detection-rules)
7. [Rollback and Updates](#7-rollback-and-updates)

---

## 1. Requirements

- **Wazuh manager** 4.x (Linux systemd, `bash`, `python3`, `iproute2`, root privileges).
- **Kerio Control UTM** 9.x with administrator console access.
- Network connectivity from Kerio Control to Wazuh manager over **UDP port 514**.

---

## 2. Wazuh Manager Installation

Run on the Wazuh server:

```bash
cd kerio-control-integration-with-wazuh-siem
cp config.env.example config.env
sudo chown root:root config.env && sudo chmod 600 config.env
sudo nano config.env
```

Configure:
- `KERIO_IP`: Kerio Control IP address or CIDR network sending syslog (e.g. `192.0.2.1` or `192.0.2.0/24`).
- `LISTEN_IP`: Wazuh Manager IP to bind the listener to (e.g. `192.0.2.10` or `0.0.0.0`).

Deploy:

```bash
# 1. Preview changes (dry-run):
sudo ./deploy.sh plan

# 2. Install (atomic backup, logtest validation, manager restart):
sudo ./deploy.sh install
```

---

## 3. Kerio Control Configuration

In the Kerio Control web administration interface:

1. Open **Logs** (sheet icon on the far left bar).
2. Right-click on the **Security** log and choose **Log Settings...**.
3. Go to the **External Logging** tab:
   - Check **Enable Syslog logging**;
   - **Syslog server**: enter `LISTEN_IP` of your Wazuh Manager;
   - **Facility**: keep default `16: Local use 0`;
   - **Application**: type `KerioControl`.
4. Click **OK**.

---

## 4. Verification

Run automated validation:
```bash
sudo ./deploy.sh verify
```

Tail real-time alerts:
```bash
sudo tail -F /var/ossec/logs/alerts/alerts.json | grep --line-buffered '"kerio"' \
  | jq -c '{rule: .rule.id, level: .rule.level, desc: .rule.description, src: .data.srcip, threat: .data.kerio.threat}'
```

---

## 5. deploy.sh Commands

| Command | Action |
|---|---|
| `sudo ./deploy.sh plan` | Show diff without making changes |
| `sudo ./deploy.sh install` | Install / update with validation and automatic backup |
| `sudo ./deploy.sh test` | Run test cases through `wazuh-logtest` |
| `sudo ./deploy.sh verify` | Validate daemon state, listening ports, rules and logs |
| `sudo ./deploy.sh rollback` | Revert changes and clean up integration |

---

## 6. Detection Rules

Rule ID range: `100800`–`100899`.

By default, Wazuh forwards alerts with severity **Level 10 and above** to external integrations (including Telegram). High-frequency events (such as Spamhaus reputation drops, internal port scans, and routine software policy warnings) are classified at **Level 6** to ensure complete indexing and searchability in Wazuh Indexer without causing alert fatigue in Telegram.

| Rule ID | Level | Description | Telegram Alert |
|---|---|---|---|
| **100800** | 0 | Base Kerio Control event | No |
| **100809** | 5 | Base IPS dispatcher | No |
| **100801** | 6 | IPS Alert (Medium/Low severity: policy warnings, obsolete software, SNI lookups) | No |
| **100807** | 10 | IPS Alert [High] (critical threat / policy violation alert) | **Yes** |
| **100802** | 10 | IPS Packet Drop (exploit, active network attack) | **Yes** |
| **100803** | 6 | Reputation Blacklist Drop (Spamhaus DROP, Botnet C2, Dshield) | No |
| **100805** | 6 | Port Scan detected | No |
| **100806** | 11 | Gateway Antivirus blocked malware | **Yes** |
| **100804** | 12 | IP blocked for password guessing (Anti-hammering) | **Yes** |
| **100810** | 13 | Correlation: repeated attacks/drops from single source in 2 min (3+ events) | **Yes (Critical)** |

---

## 7. Rollback and Updates

All configuration backups are automatically stored in `/root/kerio-control-integration-with-wazuh-siem-backups/`.

To completely revert the integration:
```bash
sudo ./deploy.sh rollback
```

Or restore a specific backup timestamp:
```bash
sudo ./deploy.sh rollback --from-backup /root/kerio-control-integration-with-wazuh-siem-backups/<TIMESTAMP>
```
