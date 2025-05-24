import asyncio
import websockets
import json
from datetime import datetime
from threat_detector import ThreatDetector
from response_engine import ResponseEngine

class WebSocketServer:
    def __init__(self, host='0.0.0.0', port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.threat_detector = ThreatDetector()
        self.response_engine = ResponseEngine()
        
    async def register(self, websocket):
        self.clients.add(websocket)
        try:
            # Send initial state
            await websocket.send(json.dumps({
                'type': 'init',
                'data': {
                    'risk_assessment': self.threat_detector.get_risk_assessment(),
                    'system_status': self.response_engine.get_system_status()
                }
            }))
        except websockets.exceptions.ConnectionClosed:
            pass
        
    async def unregister(self, websocket):
        self.clients.remove(websocket)
        
    async def broadcast(self, message):
        if self.clients:
            await asyncio.gather(
                *[client.send(json.dumps(message)) for client in self.clients]
            )
            
    async def handle_client(self, websocket, path=None):
        # Add CORS headers to the WebSocket connection
        websocket.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': '*',
            'Access-Control-Allow-Headers': '*'
        }
        
        await self.register(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data['type'] == 'action':
                        await self.handle_action(data)
                except json.JSONDecodeError:
                    print(f"Invalid JSON received: {message}")
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)
            
    async def handle_action(self, data):
        action = data.get('action')
        alert_id = data.get('alert_id')
        
        if action and alert_id:
            if action == 'acknowledge':
                self.response_engine.acknowledge_alert(alert_id)
            elif action == 'block_ip':
                ip = data.get('ip')
                if ip:
                    self.response_engine.block_ip(ip)
                    
            # Broadcast the action result
            await self.broadcast({
                'type': 'action_result',
                'data': {
                    'action': action,
                    'alert_id': alert_id,
                    'status': 'success',
                    'timestamp': datetime.now().isoformat()
                }
            })
            
    async def monitor_threats(self):
        while True:
            # Get latest risk assessment
            risk_assessment = self.threat_detector.get_risk_assessment()
            
            # Get alerts
            alerts = self.response_engine.get_alerts()
            if alerts:
                await self.broadcast({
                    'type': 'alerts',
                    'data': alerts
                })
            
            # Check for high-risk items
            if risk_assessment['high_risk_users'] or risk_assessment['high_risk_ips']:
                await self.broadcast({
                    'type': 'risk_update',
                    'data': risk_assessment
                })
                
            # Get system status
            system_status = self.response_engine.get_system_status()
            if system_status['status'] != 'normal':
                await self.broadcast({
                    'type': 'status_update',
                    'data': system_status
                })
                
            await asyncio.sleep(5)  # Check every 5 seconds
            
    async def start(self):
        async with websockets.serve(self.handle_client, self.host, self.port):
            print(f"WebSocket server started on ws://{self.host}:{self.port}")
            await self.monitor_threats()
            
def run_websocket_server():
    server = WebSocketServer()
    asyncio.run(server.start())
    
if __name__ == "__main__":
    run_websocket_server() 