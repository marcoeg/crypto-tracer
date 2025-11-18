# crypto-tracer JSON Output Examples

## Quick Start

Run the demo to see all JSON output formats:
```bash
./build/demo_json_output
```

## Output Formats

### 1. JSON Stream Format (Compact)
**Use case**: Real-time monitoring, log streaming, high-volume events

One JSON object per line, compact format:
```json
{"event_type":"file_open","timestamp":"2021-01-01T00:00:00.000000Z","pid":1234,"uid":1000,"process":"nginx","exe":"/usr/sbin/nginx","file":"/etc/ssl/certs/server.crt","file_type":"certificate","flags":"O_RDONLY","result":3}
{"event_type":"lib_load","timestamp":"2021-01-01T00:00:00.000000Z","pid":1234,"uid":1000,"process":"nginx","exe":"/usr/sbin/nginx","library":"/usr/lib/x86_64-linux-gnu/libssl.so.1.1","library_name":"libssl"}
```

### 2. JSON Array Format
**Use case**: Batch processing, complete event sets

Valid JSON array with proper formatting:
```json
[
  {
    "event_type": "process_exec",
    "timestamp": "2021-01-01T00:00:00.000000Z",
    "pid": 5678,
    "uid": 1000,
    "process": "openssl",
    "exe": "/usr/bin/openssl",
    "cmdline": "openssl s_client -connect example.com:443"
  },
  {
    "event_type": "api_call",
    "timestamp": "2021-01-01T00:00:00.000000Z",
    "pid": 5678,
    "uid": 1000,
    "process": "openssl",
    "exe": "/usr/bin/openssl",
    "function_name": "SSL_connect",
    "library": "libssl"
  }
]
```

### 3. Profile Document (Pretty Format)
**Use case**: Process profiling, detailed analysis

Complete process profile with all crypto activity:
```json
{
  "profile_version": "1.0",
  "generated_at": "2021-01-01T00:00:00.000000Z",
  "duration_seconds": 30,
  "process": {
    "pid": 1234,
    "name": "nginx",
    "exe": "/usr/sbin/nginx",
    "cmdline": "nginx: master process /usr/sbin/nginx -g daemon off;",
    "uid": 33,
    "gid": 33,
    "start_time": "2021-01-01T00:00:00.000000Z"
  },
  "libraries": [
    {
      "name": "libssl",
      "path": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
      "load_time": "2021-01-01T00:00:00.000000Z"
    }
  ],
  "files_accessed": [
    {
      "path": "/etc/ssl/certs/server.crt",
      "type": "certificate",
      "access_count": 1,
      "first_access": "2021-01-01T00:00:00.000000Z",
      "last_access": "2021-01-01T00:00:00.000000Z",
      "mode": "read"
    }
  ],
  "api_calls": [
    {
      "function_name": "SSL_CTX_new",
      "count": 1
    }
  ],
  "statistics": {
    "total_events": 15,
    "libraries_loaded": 2,
    "files_accessed": 3,
    "api_calls_made": 10
  }
}
```

### 4. Snapshot Document (Pretty Format)
**Use case**: System-wide inventory, compliance reporting

Complete system snapshot with all crypto-using processes:
```json
{
  "snapshot_version": "1.0",
  "generated_at": "2021-01-01T00:00:00.000000Z",
  "hostname": "web-server-01",
  "kernel": "5.15.0-generic",
  "processes": [
    {
      "pid": 1234,
      "name": "nginx",
      "exe": "/usr/sbin/nginx",
      "running_as": "www-data",
      "libraries": [
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"
      ],
      "open_crypto_files": [
        "/etc/ssl/certs/server.crt",
        "/etc/ssl/private/server.key"
      ]
    }
  ],
  "summary": {
    "total_processes": 2,
    "total_libraries": 3,
    "total_files": 2
  }
}
```

## Event Types

### file_open
Tracks access to cryptographic files (certificates, keys, keystores):
```json
{
  "event_type": "file_open",
  "timestamp": "2021-01-01T00:00:00.000000Z",
  "pid": 1234,
  "uid": 1000,
  "process": "nginx",
  "exe": "/usr/sbin/nginx",
  "file": "/etc/ssl/certs/server.crt",
  "file_type": "certificate",
  "flags": "O_RDONLY",
  "result": 3
}
```

### lib_load
Tracks loading of cryptographic libraries:
```json
{
  "event_type": "lib_load",
  "timestamp": "2021-01-01T00:00:00.000000Z",
  "pid": 1234,
  "uid": 1000,
  "process": "nginx",
  "exe": "/usr/sbin/nginx",
  "library": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
  "library_name": "libssl"
}
```

### process_exec
Tracks process execution:
```json
{
  "event_type": "process_exec",
  "timestamp": "2021-01-01T00:00:00.000000Z",
  "pid": 5678,
  "uid": 1000,
  "process": "openssl",
  "exe": "/usr/bin/openssl",
  "cmdline": "openssl s_client -connect example.com:443"
}
```

### process_exit
Tracks process termination:
```json
{
  "event_type": "process_exit",
  "timestamp": "2021-01-01T00:00:00.000000Z",
  "pid": 5678,
  "uid": 1000,
  "process": "openssl",
  "exit_code": 0
}
```

### api_call
Tracks OpenSSL API calls (optional feature):
```json
{
  "event_type": "api_call",
  "timestamp": "2021-01-01T00:00:00.000000Z",
  "pid": 5678,
  "uid": 1000,
  "process": "openssl",
  "exe": "/usr/bin/openssl",
  "function_name": "SSL_connect",
  "library": "libssl"
}
```

## Using jq for Analysis

### Extract specific fields
```bash
# Get all file paths
./build/demo_json_output | grep file_open | jq -r '.file'

# Get all processes
./build/demo_json_output | grep event_type | jq -r '.process' | sort -u

# Get timestamps
./build/demo_json_output | grep event_type | jq -r '.timestamp'
```

### Count events by type
```bash
./build/demo_json_output | grep event_type | jq -r '.event_type' | sort | uniq -c
```

### Format output
```bash
# Pretty-print any JSON
./build/demo_json_output | grep '^{"event_type"' | jq '.'

# Custom formatting
./build/demo_json_output | grep lib_load | jq -r '"\(.process) loaded \(.library_name)"'
```

### Filter events
```bash
# Only file_open events
./build/demo_json_output | grep event_type | jq 'select(.event_type == "file_open")'

# Only events from specific PID
./build/demo_json_output | grep event_type | jq 'select(.pid == 1234)'
```

## Integration Examples

### Send to log aggregation
```bash
crypto-tracer monitor | tee -a /var/log/crypto-tracer.log
```

### Parse with Python
```python
import json
import sys

for line in sys.stdin:
    event = json.loads(line)
    print(f"{event['timestamp']}: {event['process']} - {event['event_type']}")
```

### Store in database
```bash
crypto-tracer monitor | while read line; do
    echo "$line" | jq -c '.' | curl -X POST http://localhost:9200/crypto-events/_doc -H 'Content-Type: application/json' -d @-
done
```

## Features

✅ **Valid JSON**: All output is parseable by standard JSON parsers  
✅ **ISO 8601 Timestamps**: Microsecond precision (YYYY-MM-DDTHH:MM:SS.ssssssZ)  
✅ **Proper Escaping**: Special characters and control characters handled correctly  
✅ **Consistent Schema**: Same structure across all output types  
✅ **Multiple Formats**: Stream, array, and pretty-print options  
✅ **Complete Data**: All relevant metadata included in events  

## Future Commands (when implemented)

```bash
# Monitor all crypto activity
crypto-tracer monitor

# Monitor with filters
crypto-tracer monitor --pid 1234 --duration 60

# Profile a specific process
crypto-tracer profile --pid 1234 --duration 30

# Take a system snapshot
crypto-tracer snapshot

# Output to file
crypto-tracer monitor --output events.json --format json-array
```
