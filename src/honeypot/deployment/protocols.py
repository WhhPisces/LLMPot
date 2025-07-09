"""
多协议工控蜜罐服务器实现
Multi-Protocol Industrial Control Honeypot Server Implementation
"""
import asyncio
import logging
import struct
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import socket

# 避免循环导入，在运行时导入
# from honeypot.deployment.server import ProtocolHandler
from honeypot.deployment.config import ProtocolConfig


class ProtocolHandler:
    """协议处理器基类"""
    
    def __init__(self, config: ProtocolConfig, llm_generator, security_monitor):
        self.config = config
        self.llm_generator = llm_generator
        self.security_monitor = security_monitor
        self.clients = {}
        self.db_client = None
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理连接 - 在子类中实现"""
        raise NotImplementedError("Subclasses must implement handle_connection")
    
    async def _log_interaction(self, client_ip: str, request: str, response: str, analysis: Dict):
        """记录交互到数据库"""
        try:
            # 这里需要导入数据库模型
            from honeypot.client import Client
            from honeypot.request import Request
            
            # 创建或更新客户端记录
            client = await Client.find_one(Client.ip == client_ip)
            if not client:
                client = Client(ip=client_ip)
                await client.save()
            
            # 创建请求记录
            request_record = Request(
                client=client_ip,
                client_id=str(client.id),
                client_port=0,  # 暂时设为0
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


class ModbusTCPHandler(ProtocolHandler):
    """Modbus TCP协议处理器"""
    
    def __init__(self, config: ProtocolConfig, llm_generator, security_monitor):
        super().__init__(config, llm_generator, security_monitor)
        self.device_info = config.protocol_specific.get('device_info', {})
        self.registers = config.protocol_specific.get('holding_registers', 100)
        self.coils = config.protocol_specific.get('coils', 100)
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理Modbus TCP连接"""
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
        
        logging.info(f"New Modbus TCP connection from {client_ip}")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                request_hex = data.hex()
                logging.info(f"Modbus TCP request from {client_ip}: {request_hex}")
                
                # 解析Modbus TCP请求
                parsed_request = self._parse_modbus_request(data)
                
                # 安全分析
                analysis = self.security_monitor.analyze_request(client_ip, self.config.name, request_hex)
                
                # 检查特定的Modbus攻击模式
                modbus_analysis = self._analyze_modbus_request(parsed_request)
                if modbus_analysis['is_suspicious']:
                    analysis.update(modbus_analysis)
                
                # 生成响应
                if self.config.llm_enabled:
                    response_hex = await self.llm_generator.generate_response(
                        self.config.name, request_hex, client_ip
                    )
                    try:
                        response_bytes = bytes.fromhex(response_hex)
                    except ValueError:
                        response_bytes = self._generate_modbus_response(parsed_request)
                else:
                    response_bytes = self._generate_modbus_response(parsed_request)
                
                # 发送响应
                writer.write(response_bytes)
                await writer.drain()
                
                # 记录到数据库
                await self._log_interaction(client_ip, request_hex, response_bytes.hex(), analysis)
                
        except Exception as e:
            logging.error(f"Error handling Modbus TCP connection from {client_ip}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _parse_modbus_request(self, data: bytes) -> Dict[str, Any]:
        """解析Modbus TCP请求"""
        if len(data) < 8:
            return {'error': 'Invalid length'}
        
        try:
            # Modbus TCP头部
            transaction_id = struct.unpack('>H', data[0:2])[0]
            protocol_id = struct.unpack('>H', data[2:4])[0]
            length = struct.unpack('>H', data[4:6])[0]
            unit_id = data[6]
            
            if protocol_id != 0:
                return {'error': 'Invalid protocol ID'}
            
            if len(data) < 8:
                return {'error': 'Incomplete request'}
            
            function_code = data[7]
            
            return {
                'transaction_id': transaction_id,
                'protocol_id': protocol_id,
                'length': length,
                'unit_id': unit_id,
                'function_code': function_code,
                'data': data[8:] if len(data) > 8 else b''
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_modbus_request(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """分析Modbus请求的安全性"""
        analysis = {
            'is_suspicious': False,
            'attack_type': None,
            'severity': 'low',
            'description': ''
        }
        
        if 'error' in parsed_request:
            analysis['is_suspicious'] = True
            analysis['attack_type'] = 'malformed_request'
            analysis['severity'] = 'medium'
            analysis['description'] = f"Malformed Modbus request: {parsed_request['error']}"
            return analysis
        
        function_code = parsed_request.get('function_code', 0)
        
        # 检查异常功能码
        if function_code > 127:  # 错误响应
            analysis['is_suspicious'] = True
            analysis['attack_type'] = 'error_response'
            analysis['severity'] = 'low'
            analysis['description'] = f"Error response function code: {function_code}"
        
        # 检查可能的攻击功能码
        dangerous_functions = [8, 11, 12, 17, 20, 21, 22, 23, 24, 43]
        if function_code in dangerous_functions:
            analysis['is_suspicious'] = True
            analysis['attack_type'] = 'dangerous_function'
            analysis['severity'] = 'high'
            analysis['description'] = f"Dangerous function code: {function_code}"
        
        return analysis
    
    def _generate_modbus_response(self, parsed_request: Dict[str, Any]) -> bytes:
        """生成Modbus TCP响应"""
        if 'error' in parsed_request:
            # 生成错误响应
            return b'\x00\x00\x00\x00\x00\x03\x01\x81\x01'
        
        transaction_id = parsed_request.get('transaction_id', 0)
        unit_id = parsed_request.get('unit_id', 1)
        function_code = parsed_request.get('function_code', 3)
        
        # 构造响应头部
        response_header = struct.pack('>HH', transaction_id, 0)  # Transaction ID, Protocol ID
        
        # 根据功能码生成响应
        if function_code == 1:  # Read Coils
            response_data = bytes([unit_id, function_code, 1, 0x55])  # 示例数据
        elif function_code == 2:  # Read Discrete Inputs
            response_data = bytes([unit_id, function_code, 1, 0xAA])  # 示例数据
        elif function_code == 3:  # Read Holding Registers
            response_data = bytes([unit_id, function_code, 2, 0x00, 0x00])  # 示例数据
        elif function_code == 4:  # Read Input Registers
            response_data = bytes([unit_id, function_code, 2, 0x00, 0x00])  # 示例数据
        elif function_code == 5:  # Write Single Coil
            response_data = bytes([unit_id, function_code, 0x00, 0x00, 0xFF, 0x00])  # 回显
        elif function_code == 6:  # Write Single Register
            response_data = bytes([unit_id, function_code, 0x00, 0x00, 0x00, 0x00])  # 回显
        elif function_code == 15:  # Write Multiple Coils
            response_data = bytes([unit_id, function_code, 0x00, 0x00, 0x00, 0x08])  # 回显
        elif function_code == 16:  # Write Multiple Registers
            response_data = bytes([unit_id, function_code, 0x00, 0x00, 0x00, 0x02])  # 回显
        else:
            # 不支持的功能码
            response_data = bytes([unit_id, function_code + 0x80, 0x01])  # 异常响应
        
        length = len(response_data)
        response = response_header + struct.pack('>H', length) + response_data
        
        return response


class S7CommHandler(ProtocolHandler):
    """S7Comm协议处理器"""
    
    def __init__(self, config: ProtocolConfig, llm_generator, security_monitor):
        super().__init__(config, llm_generator, security_monitor)
        self.rack = config.protocol_specific.get('rack', 0)
        self.slot = config.protocol_specific.get('slot', 2)
        self.cpu_type = config.protocol_specific.get('cpu_type', 'CPU 1214C')
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理S7Comm连接"""
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
        
        logging.info(f"New S7Comm connection from {client_ip}")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                request_hex = data.hex()
                logging.info(f"S7Comm request from {client_ip}: {request_hex}")
                
                # 解析S7Comm请求
                parsed_request = self._parse_s7comm_request(data)
                
                # 安全分析
                analysis = self.security_monitor.analyze_request(client_ip, self.config.name, request_hex)
                
                # 生成响应
                if self.config.llm_enabled:
                    response_hex = await self.llm_generator.generate_response(
                        self.config.name, request_hex, client_ip
                    )
                    try:
                        response_bytes = bytes.fromhex(response_hex)
                    except ValueError:
                        response_bytes = self._generate_s7comm_response(parsed_request)
                else:
                    response_bytes = self._generate_s7comm_response(parsed_request)
                
                # 发送响应
                writer.write(response_bytes)
                await writer.drain()
                
                # 记录到数据库
                await self._log_interaction(client_ip, request_hex, response_bytes.hex(), analysis)
                
        except Exception as e:
            logging.error(f"Error handling S7Comm connection from {client_ip}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _parse_s7comm_request(self, data: bytes) -> Dict[str, Any]:
        """解析S7Comm请求"""
        if len(data) < 4:
            return {'error': 'Invalid length'}
        
        try:
            # TPKT头部
            if data[0] != 0x03 or data[1] != 0x00:
                return {'error': 'Invalid TPKT header'}
            
            length = struct.unpack('>H', data[2:4])[0]
            
            # COTP头部
            if len(data) < 7:
                return {'error': 'Incomplete COTP header'}
            
            return {
                'tpkt_length': length,
                'raw_data': data
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_s7comm_response(self, parsed_request: Dict[str, Any]) -> bytes:
        """生成S7Comm响应"""
        if 'error' in parsed_request:
            # 生成错误响应
            return b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'
        
        # 简单的S7Comm响应
        response = b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'
        
        return response


class DNP3Handler(ProtocolHandler):
    """DNP3协议处理器"""
    
    def __init__(self, config: ProtocolConfig, llm_generator, security_monitor):
        super().__init__(config, llm_generator, security_monitor)
        self.link_address = config.protocol_specific.get('link_address', 10)
        self.master_address = config.protocol_specific.get('master_address', 1)
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理DNP3连接"""
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
        
        logging.info(f"New DNP3 connection from {client_ip}")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                request_hex = data.hex()
                logging.info(f"DNP3 request from {client_ip}: {request_hex}")
                
                # 解析DNP3请求
                parsed_request = self._parse_dnp3_request(data)
                
                # 安全分析
                analysis = self.security_monitor.analyze_request(client_ip, self.config.name, request_hex)
                
                # 生成响应
                if self.config.llm_enabled:
                    response_hex = await self.llm_generator.generate_response(
                        self.config.name, request_hex, client_ip
                    )
                    try:
                        response_bytes = bytes.fromhex(response_hex)
                    except ValueError:
                        response_bytes = self._generate_dnp3_response(parsed_request)
                else:
                    response_bytes = self._generate_dnp3_response(parsed_request)
                
                # 发送响应
                writer.write(response_bytes)
                await writer.drain()
                
                # 记录到数据库
                await self._log_interaction(client_ip, request_hex, response_bytes.hex(), analysis)
                
        except Exception as e:
            logging.error(f"Error handling DNP3 connection from {client_ip}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _parse_dnp3_request(self, data: bytes) -> Dict[str, Any]:
        """解析DNP3请求"""
        if len(data) < 10:
            return {'error': 'Invalid length'}
        
        try:
            # DNP3头部
            if data[0] != 0x05 or data[1] != 0x64:
                return {'error': 'Invalid DNP3 header'}
            
            length = data[2]
            control = data[3]
            dest = struct.unpack('<H', data[4:6])[0]
            src = struct.unpack('<H', data[6:8])[0]
            
            return {
                'length': length,
                'control': control,
                'destination': dest,
                'source': src,
                'raw_data': data
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_dnp3_response(self, parsed_request: Dict[str, Any]) -> bytes:
        """生成DNP3响应"""
        if 'error' in parsed_request:
            # 生成错误响应
            return b'\x05\x64\x08\x44\x01\x00\x0a\x00\x00\x00'
        
        # 简单的DNP3响应
        dest = parsed_request.get('source', 1)
        src = parsed_request.get('destination', 10)
        
        response = bytearray([0x05, 0x64, 0x08, 0x44])  # 头部
        response.extend(struct.pack('<H', dest))  # 目标地址
        response.extend(struct.pack('<H', src))   # 源地址
        response.extend([0x00, 0x00])  # CRC占位符
        
        return bytes(response)


# 协议处理器映射
PROTOCOL_HANDLERS = {
    'modbus_tcp': ModbusTCPHandler,
    's7comm': S7CommHandler,
    'dnp3': DNP3Handler,
}