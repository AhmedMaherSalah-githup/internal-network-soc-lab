# Internal Network Security & SOC Lab

A lightweight, isolated Docker lab demonstrating internal network reconnaissance, HTTP log collection, and basic SOC detection using Python.

## Project Objectives

- Build an isolated Docker network for authorized testing.
- Deploy a lightweight HTTP target.
- Generate HTTP activity and collect structured JSON Lines logs.
- Detect possible endpoint reconnaissance using source IP, unique paths, and a time window.
- Validate detection logic with automated tests.

## Architecture

```text
Ubuntu Host
    |
    +-- Docker internal network: soc-internal
          |
          +-- soc-target (HTTP server, TCP/8080)
          |
          +-- soc-tester (authorized test client)
```

The target's HTTP port is not published to the host. The lab uses an internal Docker network to limit external connectivity.

## Technology Stack

- Ubuntu Linux
- Docker
- Python 3
- HTTP server and JSON Lines logging
- Nmap for authorized service discovery
- Python `unittest` for automated testing

## Detection Logic

The analyzer groups valid HTTP events by source IP and checks whether a source requests at least **five unique paths within a five-minute window**.

This is a heuristic for possible endpoint reconnaissance, not proof of malicious activity. Legitimate clients may trigger similar patterns, so alerts require investigation.

Timestamps are normalized to UTC. Timestamps without an explicit timezone are interpreted as UTC.

## Setup

### 1. Build the target image

Run from the directory containing the `Dockerfile`:

```bash
sudo docker build -t soc-lab-target:1.0 .
```

### 2. Create the isolated network

Run this only if the network does not already exist:

```bash
sudo docker network create --driver bridge --internal soc-internal
```

### 3. Start the target

```bash
sudo docker run -d --name soc-target \
  --network soc-internal \
  --restart unless-stopped \
  soc-lab-target:1.0
```

### 4. Start the tester

```bash
sudo docker run -dit --name soc-tester \
  --network soc-internal \
  --entrypoint sh python:3.12-alpine
```

If a container with the same name already exists, inspect it before attempting to create another one.

## Collect and Analyze Logs

Export the target's JSON log events:

```bash
sudo docker logs soc-target 2>&1 | grep '^{' > sample_logs.jsonl
```

Analyze the saved sample:

```bash
python3 log_analyzer.py sample_logs.jsonl
```

## Automated Tests

Run the test suite:

```bash
python3 -m unittest -v test_log_analyzer.py
```

The six tests cover:

- Reconnaissance detection within the configured time window
- No alert when requests are spread beyond the window
- Invalid JSON handling
- Invalid timestamp handling
- Mixed timezone formats
- Missing log file handling

## Limitations

- The HTTP server returns HTTP 200 for every path. A successful response does not prove that an application endpoint exists.
- The detection rule uses a fixed threshold and time window.
- The analyzer is a learning tool, not a production SIEM or a complete incident detection system.
- The lab does not demonstrate detection of every type of network scan.
- Results depend on the quality and completeness of the collected logs.

## Safety

All testing is intended for this isolated lab environment. Do not scan systems without explicit authorization.
