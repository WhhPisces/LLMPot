"""
蜜罐管理和监控Dashboard
Honeypot Management and Monitoring Dashboard
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from flask import Flask, render_template, jsonify, request, websocket
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import logging

from honeypot.client import Client
from honeypot.request import Request
from honeypot.deployment.config import ConfigManager


class HoneypotDashboard:
    """蜜罐监控面板"""
    
    def __init__(self, config_path: str = None):
        self.app = Flask(__name__)
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        self.db_client = None
        self.setup_routes()
        
    async def init_database(self):
        """初始化数据库连接"""
        try:
            self.db_client = AsyncIOMotorClient(self.config.database.mongodb_url)
            db = self.db_client[self.config.database.database_name]
            await init_beanie(database=db, document_models=[Client, Request])
            logging.info("Dashboard database initialized")
        except Exception as e:
            logging.error(f"Dashboard database initialization failed: {e}")
    
    def setup_routes(self):
        """设置路由"""
        
        @self.app.route('/')
        def index():
            """主页"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/config')
        def get_config():
            """获取配置信息"""
            return jsonify({
                'name': self.config.name,
                'description': self.config.description,
                'protocols': [
                    {
                        'name': p.name,
                        'port': p.port,
                        'enabled': p.enabled,
                        'llm_enabled': p.llm_enabled
                    } for p in self.config.protocols
                ],
                'llm': {
                    'model_type': self.config.llm.model_type,
                    'device': self.config.llm.device
                }
            })
        
        @self.app.route('/api/stats')
        def get_stats():
            """获取统计信息"""
            return asyncio.run(self._get_stats())
        
        @self.app.route('/api/clients')
        def get_clients():
            """获取客户端列表"""
            return asyncio.run(self._get_clients())
        
        @self.app.route('/api/requests')
        def get_requests():
            """获取请求列表"""
            page = request.args.get('page', 1, type=int)
            limit = request.args.get('limit', 50, type=int)
            protocol = request.args.get('protocol', '')
            return asyncio.run(self._get_requests(page, limit, protocol))
        
        @self.app.route('/api/attacks')
        def get_attacks():
            """获取攻击事件"""
            return asyncio.run(self._get_attacks())
        
        @self.app.route('/api/timeline')
        def get_timeline():
            """获取时间线数据"""
            hours = request.args.get('hours', 24, type=int)
            return asyncio.run(self._get_timeline(hours))
        
        @self.app.route('/api/protocols')
        def get_protocol_stats():
            """获取协议统计"""
            return asyncio.run(self._get_protocol_stats())
    
    async def _get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        try:
            await self.init_database()
            
            # 基本统计
            total_clients = await Client.count()
            total_requests = await Request.count()
            
            # 最近24小时的请求
            since_24h = datetime.now() - timedelta(hours=24)
            recent_requests = await Request.find(
                Request.request_time >= since_24h
            ).count()
            
            # 可疑请求
            suspicious_requests = await Request.find(
                Request.is_suspicious == True
            ).count()
            
            # 攻击类型统计
            attack_types = await Request.aggregate([
                {"$match": {"is_suspicious": True}},
                {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]).to_list()
            
            return {
                'total_clients': total_clients,
                'total_requests': total_requests,
                'recent_requests': recent_requests,
                'suspicious_requests': suspicious_requests,
                'attack_types': attack_types
            }
        except Exception as e:
            logging.error(f"Error getting stats: {e}")
            return {'error': str(e)}
    
    async def _get_clients(self) -> Dict[str, Any]:
        """获取客户端列表"""
        try:
            await self.init_database()
            
            clients = await Client.find().limit(100).to_list()
            client_data = []
            
            for client in clients:
                request_count = await Request.find(
                    Request.client == client.ip
                ).count()
                
                suspicious_count = await Request.find(
                    Request.client == client.ip,
                    Request.is_suspicious == True
                ).count()
                
                client_data.append({
                    'ip': client.ip,
                    'first_contact': client.first_contact.isoformat(),
                    'request_count': request_count,
                    'suspicious_count': suspicious_count,
                    'risk_level': 'high' if suspicious_count > 10 else 'medium' if suspicious_count > 0 else 'low'
                })
            
            return {'clients': client_data}
        except Exception as e:
            logging.error(f"Error getting clients: {e}")
            return {'error': str(e)}
    
    async def _get_requests(self, page: int, limit: int, protocol: str = '') -> Dict[str, Any]:
        """获取请求列表"""
        try:
            await self.init_database()
            
            query = {}
            if protocol:
                query['protocol'] = protocol
            
            skip = (page - 1) * limit
            requests = await Request.find(query).skip(skip).limit(limit).sort([("request_time", -1)]).to_list()
            
            request_data = []
            for req in requests:
                request_data.append({
                    'id': str(req.id),
                    'client': req.client,
                    'protocol': req.protocol,
                    'request': req.request[:100] + '...' if len(req.request) > 100 else req.request,
                    'response': req.response[:100] + '...' if len(req.response) > 100 else req.response,
                    'request_time': req.request_time.isoformat(),
                    'is_suspicious': req.is_suspicious,
                    'attack_type': req.attack_type,
                    'severity': req.severity
                })
            
            total = await Request.find(query).count()
            
            return {
                'requests': request_data,
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit
            }
        except Exception as e:
            logging.error(f"Error getting requests: {e}")
            return {'error': str(e)}
    
    async def _get_attacks(self) -> Dict[str, Any]:
        """获取攻击事件"""
        try:
            await self.init_database()
            
            # 获取最近的攻击
            attacks = await Request.find(
                Request.is_suspicious == True
            ).sort([("request_time", -1)]).limit(100).to_list()
            
            attack_data = []
            for attack in attacks:
                attack_data.append({
                    'timestamp': attack.request_time.isoformat(),
                    'client_ip': attack.client,
                    'protocol': attack.protocol,
                    'attack_type': attack.attack_type,
                    'severity': attack.severity,
                    'request': attack.request[:200] + '...' if len(attack.request) > 200 else attack.request
                })
            
            return {'attacks': attack_data}
        except Exception as e:
            logging.error(f"Error getting attacks: {e}")
            return {'error': str(e)}
    
    async def _get_timeline(self, hours: int) -> Dict[str, Any]:
        """获取时间线数据"""
        try:
            await self.init_database()
            
            since = datetime.now() - timedelta(hours=hours)
            
            # 按小时统计请求
            pipeline = [
                {"$match": {"request_time": {"$gte": since}}},
                {
                    "$group": {
                        "_id": {
                            "hour": {"$hour": "$request_time"},
                            "day": {"$dayOfMonth": "$request_time"},
                            "month": {"$month": "$request_time"},
                            "year": {"$year": "$request_time"}
                        },
                        "total_requests": {"$sum": 1},
                        "suspicious_requests": {
                            "$sum": {"$cond": [{"$eq": ["$is_suspicious", True]}, 1, 0]}
                        }
                    }
                },
                {"$sort": {"_id": 1}}
            ]
            
            timeline_data = await Request.aggregate(pipeline).to_list()
            
            # 转换为图表数据格式
            chart_data = []
            for item in timeline_data:
                timestamp = datetime(
                    item['_id']['year'],
                    item['_id']['month'],
                    item['_id']['day'],
                    item['_id']['hour']
                )
                chart_data.append({
                    'timestamp': timestamp.isoformat(),
                    'total_requests': item['total_requests'],
                    'suspicious_requests': item['suspicious_requests']
                })
            
            return {'timeline': chart_data}
        except Exception as e:
            logging.error(f"Error getting timeline: {e}")
            return {'error': str(e)}
    
    async def _get_protocol_stats(self) -> Dict[str, Any]:
        """获取协议统计"""
        try:
            await self.init_database()
            
            # 按协议统计
            pipeline = [
                {
                    "$group": {
                        "_id": "$protocol",
                        "total_requests": {"$sum": 1},
                        "suspicious_requests": {
                            "$sum": {"$cond": [{"$eq": ["$is_suspicious", True]}, 1, 0]}
                        }
                    }
                }
            ]
            
            protocol_stats = await Request.aggregate(pipeline).to_list()
            
            return {'protocol_stats': protocol_stats}
        except Exception as e:
            logging.error(f"Error getting protocol stats: {e}")
            return {'error': str(e)}
    
    def run(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
        """运行Dashboard"""
        self.app.run(host=host, port=port, debug=debug)


def create_dashboard_html():
    """创建Dashboard HTML模板"""
    html_content = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>工控网络蜜罐监控面板</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .table-container {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .high-risk { color: #e74c3c; }
        .medium-risk { color: #f39c12; }
        .low-risk { color: #27ae60; }
        .suspicious { background-color: #fff3cd; }
        .attack-type {
            display: inline-block;
            padding: 2px 8px;
            background-color: #e74c3c;
            color: white;
            border-radius: 4px;
            font-size: 0.8em;
        }
        .refresh-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .refresh-btn:hover {
            background: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>工控网络蜜罐监控面板</h1>
            <p id="config-info">加载中...</p>
        </div>
        
        <button class="refresh-btn" onclick="refreshData()">刷新数据</button>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="total-clients">-</div>
                <div class="stat-label">总客户端数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-requests">-</div>
                <div class="stat-label">总请求数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="recent-requests">-</div>
                <div class="stat-label">24小时请求</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="suspicious-requests">-</div>
                <div class="stat-label">可疑请求</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>请求时间线</h3>
            <canvas id="timelineChart"></canvas>
        </div>
        
        <div class="table-container">
            <h3 style="padding: 20px 20px 0 20px;">最近攻击事件</h3>
            <table id="attacks-table">
                <thead>
                    <tr>
                        <th>时间</th>
                        <th>客户端IP</th>
                        <th>协议</th>
                        <th>攻击类型</th>
                        <th>严重程度</th>
                        <th>请求数据</th>
                    </tr>
                </thead>
                <tbody id="attacks-tbody">
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let timelineChart;
        
        async function fetchData(url) {
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                console.error('Error fetching data:', error);
                return null;
            }
        }
        
        async function loadConfig() {
            const config = await fetchData('/api/config');
            if (config) {
                document.getElementById('config-info').textContent = 
                    `${config.name} - ${config.description}`;
            }
        }
        
        async function loadStats() {
            const stats = await fetchData('/api/stats');
            if (stats) {
                document.getElementById('total-clients').textContent = stats.total_clients || 0;
                document.getElementById('total-requests').textContent = stats.total_requests || 0;
                document.getElementById('recent-requests').textContent = stats.recent_requests || 0;
                document.getElementById('suspicious-requests').textContent = stats.suspicious_requests || 0;
            }
        }
        
        async function loadTimeline() {
            const data = await fetchData('/api/timeline');
            if (data && data.timeline) {
                updateTimelineChart(data.timeline);
            }
        }
        
        async function loadAttacks() {
            const data = await fetchData('/api/attacks');
            if (data && data.attacks) {
                updateAttacksTable(data.attacks);
            }
        }
        
        function updateTimelineChart(data) {
            const ctx = document.getElementById('timelineChart').getContext('2d');
            
            if (timelineChart) {
                timelineChart.destroy();
            }
            
            timelineChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.map(item => new Date(item.timestamp).toLocaleString()),
                    datasets: [{
                        label: '总请求',
                        data: data.map(item => item.total_requests),
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        fill: true
                    }, {
                        label: '可疑请求',
                        data: data.map(item => item.suspicious_requests),
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        function updateAttacksTable(attacks) {
            const tbody = document.getElementById('attacks-tbody');
            tbody.innerHTML = '';
            
            attacks.forEach(attack => {
                const row = document.createElement('tr');
                if (attack.severity === 'high') {
                    row.className = 'suspicious';
                }
                
                row.innerHTML = `
                    <td>${new Date(attack.timestamp).toLocaleString()}</td>
                    <td>${attack.client_ip}</td>
                    <td>${attack.protocol}</td>
                    <td><span class="attack-type">${attack.attack_type}</span></td>
                    <td class="${attack.severity}-risk">${attack.severity}</td>
                    <td>${attack.request}</td>
                `;
                
                tbody.appendChild(row);
            });
        }
        
        async function refreshData() {
            await loadConfig();
            await loadStats();
            await loadTimeline();
            await loadAttacks();
        }
        
        // 初始加载
        refreshData();
        
        // 定时刷新
        setInterval(refreshData, 30000); // 30秒刷新一次
    </script>
</body>
</html>
    """
    return html_content


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="蜜罐监控Dashboard")
    parser.add_argument("--config", "-c", help="配置文件路径")
    parser.add_argument("--host", default="0.0.0.0", help="绑定地址")
    parser.add_argument("--port", type=int, default=8080, help="端口")
    parser.add_argument("--debug", action="store_true", help="调试模式")
    
    args = parser.parse_args()
    
    # 创建templates目录和HTML文件
    import os
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    html_path = os.path.join(templates_dir, 'dashboard.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(create_dashboard_html())
    
    # 启动Dashboard
    dashboard = HoneypotDashboard(args.config)
    dashboard.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()