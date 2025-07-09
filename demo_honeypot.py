#!/usr/bin/env python3
"""
工控网络蜜罐系统演示脚本
Industrial Control Network Honeypot Demo Script
"""
import asyncio
import json
import time
from pathlib import Path
import sys

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent / 'src'))

async def demo_modbus_client():
    """演示Modbus TCP客户端"""
    print("🔧 演示Modbus TCP客户端连接...")
    
    try:
        # 连接到蜜罐
        reader, writer = await asyncio.open_connection('localhost', 502)
        
        # 发送Modbus TCP请求 (读取保持寄存器)
        # Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0006
        # Unit ID: 0x01, Function Code: 0x03, Start Address: 0x0000, Quantity: 0x0001
        modbus_request = bytes.fromhex('0001000000060103000000001')
        
        print(f"📤 发送Modbus请求: {modbus_request.hex()}")
        writer.write(modbus_request)
        await writer.drain()
        
        # 接收响应
        response = await reader.read(1024)
        print(f"📥 接收到响应: {response.hex()}")
        
        # 关闭连接
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        print(f"❌ Modbus客户端错误: {e}")

async def demo_s7comm_client():
    """演示S7Comm客户端"""
    print("\n🔧 演示S7Comm客户端连接...")
    
    try:
        # 连接到蜜罐
        reader, writer = await asyncio.open_connection('localhost', 102)
        
        # 发送S7Comm连接请求
        # TPKT Header + COTP Connection Request
        s7comm_request = bytes.fromhex('0300001611e00000000100c1020100c2020102c0010a')
        
        print(f"📤 发送S7Comm请求: {s7comm_request.hex()}")
        writer.write(s7comm_request)
        await writer.drain()
        
        # 接收响应
        response = await reader.read(1024)
        print(f"📥 接收到响应: {response.hex()}")
        
        # 关闭连接
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        print(f"❌ S7Comm客户端错误: {e}")

def demo_config_management():
    """演示配置管理"""
    print("\n⚙️ 演示配置管理...")
    
    try:
        from honeypot.deployment.config import ConfigManager
        
        # 创建配置管理器
        manager = ConfigManager()
        config = manager._create_default_config()
        
        print(f"📋 蜜罐名称: {config.name}")
        print(f"📋 协议数量: {len(config.protocols)}")
        
        # 显示协议信息
        for protocol in config.protocols:
            status = "✅ 启用" if protocol.enabled else "❌ 禁用"
            print(f"   {protocol.name}: 端口 {protocol.port} - {status}")
        
        print(f"📋 LLM模型: {config.llm.model_type}")
        print(f"📋 安全设置: 速率限制 {'✅' if config.security.enable_rate_limiting else '❌'}")
        
    except Exception as e:
        print(f"❌ 配置管理错误: {e}")

def demo_protocol_handlers():
    """演示协议处理器"""
    print("\n🔌 演示协议处理器...")
    
    try:
        from honeypot.deployment.protocols import PROTOCOL_HANDLERS
        
        print(f"📋 可用协议处理器: {len(PROTOCOL_HANDLERS)}")
        for name, handler_class in PROTOCOL_HANDLERS.items():
            print(f"   {name}: {handler_class.__name__}")
        
        # 演示Modbus请求解析
        from honeypot.deployment.protocols import ModbusTCPHandler
        from honeypot.deployment.config import ProtocolConfig
        
        # 创建配置
        config = ProtocolConfig(
            name="modbus_tcp",
            port=502,
            protocol_specific={"coils": 100, "holding_registers": 100}
        )
        
        # 创建处理器
        handler = ModbusTCPHandler(config, None, None)
        
        # 解析示例请求
        test_request = bytes.fromhex('0001000000060103000000001')
        parsed = handler._parse_modbus_request(test_request)
        
        print(f"📋 Modbus请求解析结果:")
        print(f"   事务ID: {parsed.get('transaction_id', 'N/A')}")
        print(f"   功能码: {parsed.get('function_code', 'N/A')}")
        print(f"   单元ID: {parsed.get('unit_id', 'N/A')}")
        
    except Exception as e:
        print(f"❌ 协议处理器错误: {e}")

async def demo_security_monitoring():
    """演示安全监控"""
    print("\n🛡️ 演示安全监控...")
    
    try:
        from honeypot.deployment.server import SecurityMonitor
        from honeypot.deployment.config import HoneypotConfig
        
        # 创建配置
        config = HoneypotConfig(
            name="Demo Honeypot",
            description="演示蜜罐"
        )
        
        # 创建安全监控器
        monitor = SecurityMonitor(config)
        
        # 模拟IP访问
        test_ip = "192.168.1.100"
        
        # 检查速率限制
        for i in range(5):
            allowed = monitor.check_rate_limit(test_ip)
            print(f"   请求 {i+1}: {'✅ 允许' if allowed else '❌ 阻止'}")
            time.sleep(0.1)
        
        # 分析请求
        analysis = monitor.analyze_request(test_ip, "modbus_tcp", "0001000000060103000000001")
        print(f"📋 请求分析结果:")
        print(f"   可疑: {'是' if analysis['is_suspicious'] else '否'}")
        print(f"   攻击类型: {analysis.get('attack_type', 'N/A')}")
        print(f"   严重程度: {analysis.get('severity', 'N/A')}")
        
    except Exception as e:
        print(f"❌ 安全监控错误: {e}")

def demo_database_models():
    """演示数据库模型"""
    print("\n💾 演示数据库模型...")
    
    try:
        from honeypot.client import Client
        from honeypot.request import Request
        from datetime import datetime
        
        print(f"📋 数据库模型:")
        print(f"   客户端模型: {Client.__name__}")
        print(f"   请求模型: {Request.__name__}")
        
        # 创建示例客户端
        client = Client(ip="192.168.1.100")
        print(f"   示例客户端: {client.ip}")
        
        # 创建示例请求
        request = Request(
            client="192.168.1.100",
            client_port=12345,
            request="0001000000060103000000001",
            response="000100000006010302000000",
            protocol="modbus_tcp",
            is_suspicious=False
        )
        print(f"   示例请求: {request.protocol} - {request.request[:20]}...")
        
    except Exception as e:
        print(f"❌ 数据库模型错误: {e}")

async def main():
    """主演示函数"""
    print("🎯 工控网络蜜罐系统演示")
    print("=" * 60)
    
    # 1. 配置管理演示
    demo_config_management()
    
    # 2. 协议处理器演示
    demo_protocol_handlers()
    
    # 3. 安全监控演示
    await demo_security_monitoring()
    
    # 4. 数据库模型演示
    demo_database_models()
    
    # 5. 客户端连接演示（需要蜜罐运行）
    print("\n🌐 客户端连接演示（需要蜜罐运行）")
    print("请先启动蜜罐服务器，然后运行以下演示:")
    print("python3 start_honeypot_quick.py")
    print()
    
    # 尝试连接演示
    try:
        await asyncio.wait_for(demo_modbus_client(), timeout=5)
        await asyncio.wait_for(demo_s7comm_client(), timeout=5)
    except asyncio.TimeoutError:
        print("⚠️ 连接超时，请确保蜜罐服务器已启动")
    except Exception as e:
        print(f"⚠️ 连接演示跳过: {e}")
    
    print("\n✅ 演示完成!")
    print("\n📚 更多信息请查看:")
    print("   - HONEYPOT_README.md")
    print("   - HONEYPOT_DEPLOYMENT_GUIDE.md")
    print("   - honeypot_config_example.yaml")

if __name__ == "__main__":
    asyncio.run(main())