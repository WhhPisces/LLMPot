"""
LLM增强的工控协议蜜罐服务器
LLM-Enhanced Industrial Control Protocol Honeypot Server
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from collections import defaultdict

import torch
from transformers import ByT5Tokenizer, T5ForConditionalGeneration
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

from honeypot.deployment.config import HoneypotConfig, ProtocolConfig
from honeypot.client import Client
from honeypot.request import Request
from finetune.utils.inference_runner import ModelLoader
from finetune.model.finetuner_model import FinetunerModel, DatasetModel
from honeypot.deployment.protocols import PROTOCOL_HANDLERS, ProtocolHandler


@dataclass
class AttackEvent:
    """攻击事件"""
    timestamp: datetime
    client_ip: str
    protocol: str
    request_data: str
    response_data: str
    attack_type: str
    severity: str
    description: str


class SecurityMonitor:
    """安全监控器"""
    
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.blocked_ips = set()
        self.failed_attempts = defaultdict(int)
        self.rate_limits = defaultdict(list)
        self.attack_events = []
        
    def is_blocked(self, ip: str) -> bool:
        """检查IP是否被阻止"""
        return ip in self.blocked_ips
    
    def check_rate_limit(self, ip: str) -> bool:
        """检查速率限制"""
        if not self.config.security.enable_rate_limiting:
            return True
            
        now = time.time()
        window = self.config.security.rate_limit_window
        
        # 清理过期的请求记录
        self.rate_limits[ip] = [t for t in self.rate_limits[ip] if now - t < window]
        
        # 检查是否超过限制
        if len(self.rate_limits[ip]) >= self.config.security.rate_limit_requests:
            self.block_ip(ip, "Rate limit exceeded")
            return False
            
        self.rate_limits[ip].append(now)
        return True
    
    def block_ip(self, ip: str, reason: str):
        """阻止IP"""
        self.blocked_ips.add(ip)
        logging.warning(f"IP {ip} blocked: {reason}")
        
        # 记录攻击事件
        event = AttackEvent(
            timestamp=datetime.now(),
            client_ip=ip,
            protocol="system",
            request_data="",
            response_data="",
            attack_type="rate_limit",
            severity="medium",
            description=reason
        )
        self.attack_events.append(event)
    
    def record_failed_attempt(self, ip: str):
        """记录失败尝试"""
        self.failed_attempts[ip] += 1
        if self.failed_attempts[ip] >= self.config.security.max_failed_attempts:
            self.block_ip(ip, f"Too many failed attempts: {self.failed_attempts[ip]}")
    
    def analyze_request(self, ip: str, protocol: str, request_data: str) -> Dict[str, Any]:
        """分析请求，检测潜在攻击"""
        analysis = {
            'is_suspicious': False,
            'attack_type': None,
            'severity': 'low',
            'description': ''
        }
        
        # 检查异常长度的请求
        if len(request_data) > 1000:
            analysis['is_suspicious'] = True
            analysis['attack_type'] = 'oversized_request'
            analysis['severity'] = 'medium'
            analysis['description'] = f'Request too large: {len(request_data)} bytes'
        
        # 检查异常字符
        if any(c in request_data for c in ['<', '>', '&', '"', "'"]):
            analysis['is_suspicious'] = True
            analysis['attack_type'] = 'injection_attempt'
            analysis['severity'] = 'high'
            analysis['description'] = 'Potential injection attack detected'
        
        # 记录可疑活动
        if analysis['is_suspicious']:
            event = AttackEvent(
                timestamp=datetime.now(),
                client_ip=ip,
                protocol=protocol,
                request_data=request_data,
                response_data="",
                attack_type=analysis['attack_type'],
                severity=analysis['severity'],
                description=analysis['description']
            )
            self.attack_events.append(event)
            
        return analysis


class LLMResponseGenerator:
    """LLM响应生成器"""
    
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.model_loader = None
        self.device = torch.device(config.llm.device if torch.cuda.is_available() else "cpu")
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    async def initialize(self):
        """初始化LLM模型"""
        try:
            # 加载预训练模型配置
            finetuner_config = {
                "model_type": "google",
                "model_name": self.config.llm.model_type,
                "datasets": [{
                    "protocol": "mbtcp",
                    "size": 3200,
                    "functions": [1, 5, 15, 3, 6, 16],
                    "values": {"low": 0, "high": 65535},
                    "addresses": {"low": 0, "high": 39},
                    "client": "boundaries_client",
                    "server": {
                        "name": "no_logic_server",
                        "coils": 40,
                        "registers": 40
                    },
                    "context": 0,
                    "multi_elements": 3
                }]
            }
            
            finetuner_model = FinetunerModel(experiment="honeypot", **finetuner_config)
            self.model_loader = ModelLoader(finetuner_model, 0)
            logging.info("LLM model initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize LLM model: {e}")
            self.model_loader = None
    
    async def generate_response(self, protocol: str, request_data: str, client_ip: str) -> str:
        """生成响应"""
        if not self.model_loader:
            return self._generate_fallback_response(protocol, request_data)
        
        try:
            # 在线程池中运行LLM推理
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                self.executor,
                self.model_loader.predict,
                request_data
            )
            
            logging.info(f"LLM response generated for {client_ip}: {request_data[:50]}...")
            return response
            
        except Exception as e:
            logging.error(f"LLM response generation failed: {e}")
            return self._generate_fallback_response(protocol, request_data)
    
    def _generate_fallback_response(self, protocol: str, request_data: str) -> str:
        """生成回退响应"""
        if protocol == "modbus_tcp":
            # 简单的Modbus TCP响应
            if len(request_data) >= 12:
                try:
                    # 解析Modbus TCP头部
                    transaction_id = request_data[:4]
                    protocol_id = "0000"
                    length = "0006"
                    unit_id = request_data[12:14] if len(request_data) > 12 else "01"
                    function_code = request_data[14:16] if len(request_data) > 14 else "03"
                    
                    # 构造响应
                    response = transaction_id + protocol_id + length + unit_id + function_code + "02" + "0000"
                    return response
                except:
                    pass
        
        return "0000000000060103020000"  # 默认响应


class ProtocolHandler:
    """协议处理器基类"""
    
    def __init__(self, config: ProtocolConfig, llm_generator: LLMResponseGenerator, 
                 security_monitor: SecurityMonitor):
        self.config = config
        self.llm_generator = llm_generator
        self.security_monitor = security_monitor
        self.clients = {}
        self.db_client = None
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理连接"""
        client_ip = writer.get_extra_info('peername')[0]
        
        # 安全检查
        if self.security_monitor.is_blocked(client_ip):
            writer.close()
            await writer.wait_closed()
            return
            
        if not self.security_monitor.check_rate_limit(client_ip):
            writer.close()
            await writer.wait_closed()
            return
        
        logging.info(f"New connection from {client_ip} on protocol {self.config.name}")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                request_hex = data.hex()
                logging.info(f"Received from {client_ip}: {request_hex}")
                
                # 安全分析
                analysis = self.security_monitor.analyze_request(client_ip, self.config.name, request_hex)
                
                # 生成响应
                if self.config.llm_enabled:
                    response_hex = await self.llm_generator.generate_response(
                        self.config.name, request_hex, client_ip
                    )
                else:
                    response_hex = self._generate_static_response(request_hex)
                
                # 发送响应
                try:
                    response_bytes = bytes.fromhex(response_hex)
                    writer.write(response_bytes)
                    await writer.drain()
                    
                    # 记录到数据库
                    await self._log_interaction(client_ip, request_hex, response_hex, analysis)
                    
                except Exception as e:
                    logging.error(f"Error sending response: {e}")
                    break
                    
        except Exception as e:
            logging.error(f"Error handling connection from {client_ip}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _log_interaction(self, client_ip: str, request: str, response: str, analysis: Dict):
        """记录交互到数据库"""
        try:
            # 创建或更新客户端记录
            client = await Client.find_one(Client.ip == client_ip)
            if not client:
                client = Client(ip=client_ip)
                await client.save()
            
            # 创建请求记录
            request_record = Request(
                client=client_ip,
                client_id=str(client.id),
                client_port=0,
                request=request,
                response=response,
                protocol=self.config.name,
                request_time=datetime.now(),
                is_suspicious=analysis.get('is_suspicious', False),
                attack_type=analysis.get('attack_type', ''),
                severity=analysis.get('severity', 'low')
            )
            
            await request_record.save()
            
        except Exception as e:
            logging.error(f"Failed to log interaction: {e}")
    
    def _generate_static_response(self, request_hex: str) -> str:
        """生成静态响应"""
        return "0000000000060103020000"  # 默认响应


class HoneypotServer:
    """蜜罐服务器主类"""
    
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.security_monitor = SecurityMonitor(config)
        self.llm_generator = LLMResponseGenerator(config)
        self.protocol_handlers = {}
        self.servers = []
        
    async def initialize(self):
        """初始化服务器"""
        # 初始化数据库连接
        await self._init_database()
        
        # 初始化LLM生成器
        await self.llm_generator.initialize()
        
        # 初始化协议处理器
        for protocol_config in self.config.protocols:
            if protocol_config.enabled:
                handler_class = PROTOCOL_HANDLERS.get(protocol_config.name, ProtocolHandler)
                handler = handler_class(protocol_config, self.llm_generator, self.security_monitor)
                self.protocol_handlers[protocol_config.name] = handler
        
        logging.info("Honeypot server initialized successfully")
    
    async def _init_database(self):
        """初始化数据库"""
        try:
            client = AsyncIOMotorClient(self.config.database.mongodb_url)
            db = client[self.config.database.database_name]
            await init_beanie(database=db, document_models=[Client, Request])
            logging.info("Database initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
    
    async def start(self):
        """启动服务器"""
        logging.info(f"Starting honeypot server: {self.config.name}")
        
        # 启动各协议服务器
        for protocol_name, handler in self.protocol_handlers.items():
            protocol_config = None
            for p in self.config.protocols:
                if p.name == protocol_name:
                    protocol_config = p
                    break
            
            if protocol_config and protocol_config.enabled:
                server = await asyncio.start_server(
                    handler.handle_connection,
                    self.config.bind_address,
                    protocol_config.port
                )
                self.servers.append(server)
                logging.info(f"Protocol {protocol_name} server started on port {protocol_config.port}")
        
        # 启动监控任务
        asyncio.create_task(self._monitoring_loop())
        
        # 等待服务器
        await asyncio.gather(*[server.serve_forever() for server in self.servers])
    
    async def _monitoring_loop(self):
        """监控循环"""
        while True:
            try:
                await asyncio.sleep(60)  # 每分钟检查一次
                
                # 清理过期的阻止IP
                # 这里可以添加更多监控逻辑
                
                # 记录统计信息
                total_attacks = len(self.security_monitor.attack_events)
                blocked_ips = len(self.security_monitor.blocked_ips)
                logging.info(f"Security status - Total attacks: {total_attacks}, Blocked IPs: {blocked_ips}")
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
    
    async def stop(self):
        """停止服务器"""
        logging.info("Stopping honeypot server...")
        for server in self.servers:
            server.close()
            await server.wait_closed()
        logging.info("Honeypot server stopped")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_attacks': len(self.security_monitor.attack_events),
            'blocked_ips': len(self.security_monitor.blocked_ips),
            'active_protocols': len([p for p in self.config.protocols if p.enabled]),
            'recent_attacks': [
                {
                    'timestamp': event.timestamp.isoformat(),
                    'client_ip': event.client_ip,
                    'protocol': event.protocol,
                    'attack_type': event.attack_type,
                    'severity': event.severity
                }
                for event in self.security_monitor.attack_events[-10:]  # 最近10个攻击
            ]
        }


# 为了兼容现有代码，添加一些辅助函数
def create_default_honeypot_config() -> HoneypotConfig:
    """创建默认蜜罐配置"""
    from honeypot.deployment.config import ConfigManager
    manager = ConfigManager()
    return manager._create_default_config()


async def start_honeypot(config_path: str = None):
    """启动蜜罐服务器"""
    from honeypot.deployment.config import ConfigManager
    
    # 加载配置
    manager = ConfigManager(config_path)
    config = manager.load_config()
    
    # 创建并启动服务器
    server = HoneypotServer(config)
    await server.initialize()
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logging.info("Received interrupt signal")
    finally:
        await server.stop()


if __name__ == "__main__":
    import sys
    
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 启动蜜罐
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(start_honeypot(config_path))