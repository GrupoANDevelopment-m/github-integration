"""
Advanced Example: Real-time monitoring dashboard.

Connects to /ws/events and renders events as they happen.
"""
import asyncio
import websockets
import json

async def monitor():
    uri = "ws://localhost:8443/ws/events"
    async with websockets.connect(uri) as ws:
        print("Connected. Listening for events...")
        while True:
            msg = await ws.recv()
            event = json.loads(msg)
            
            severity = event.get('severity', 'unknown')
            etype = event.get('type', 'unknown')
            
            color = {
                'critical': '\033[91m',  # red
                'high': '\033[93m',       # yellow
                'medium': '\033[33m',     # orange
                'low': '\033[32m',        # green
            }.get(severity, '\033[0m')
            
            print(f"{color}[{severity:8}] {etype:30} - {event.get('source', '?')}\033[0m")

asyncio.run(monitor())
