# Troubleshooting

## Common Issues

### liboqs not loading
```
RuntimeError: liboqs.so not found
```

**Solution**:
```bash
# Verify install
ldconfig -p | grep oqs
ls /usr/local/lib/liboqs*
ls vendor/oqs/lib/liboqs*

# Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$(pwd)/vendor/oqs/lib:$LD_LIBRARY_PATH"
```

### DeepSeek LLM not responding
```
RuntimeError: DeepSeek Harness not available
```

**Solution**:
```bash
# Set API key
export DEEPSEEK_API_KEY="nvapi-..."
# OR for NVIDIA integrate:
export NVIDIA_API_KEY="nvapi-..."
```

### YARA rules not loading
```
ERROR: invalid rule
```

**Solution**:
```bash
# Test rule syntax
yara -w rules/test.yar /dev/null

# Check imports
yara --version
```

### Database locked
```
sqlite3.OperationalError: database is locked
```

**Solution**:
```bash
# Check for running processes
ps aux | grep goodware

# Wait 5s, retry
```

### Port already in use
```
OSError: [Errno 98] Address already in use
```

**Solution**:
```bash
# Find process
lsof -i :8443
# Or change port in config
```

## Performance Tuning

### Sensor Tuning
Edit `config/goodware.yaml`:
```yaml
sensors:
  filesystem:
    interval: 30  # seconds between scans
    paths: [/etc, /usr/local/bin]
  process:
    interval: 5
    whitelist: [/usr/bin/systemd, /sbin/init]
```

### ML Tuning
```yaml
prediction:
  model: threat_predictor.joblib
  threshold: 0.85  # higher = fewer false positives
```

### Effector Tuning
```yaml
effector:
  firewall:
    rate_limit: 100  # rules per minute
  quarantine:
    auto_quarantine_threshold: 90  # risk score
```

