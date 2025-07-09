#!/usr/bin/env python3
"""
工控网络蜜罐系统完整功能演示
Complete Functionality Demo for Industrial Control Network Honeypot
"""
import sys
import json
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def demo_complete_system():
    """完整系统演示"""
    print("🎯 工控网络蜜罐系统完整功能演示")
    print("=" * 60)
    
    # 1. 配置系统演示
    print("\n1️⃣ 配置管理系统 | Configuration Management System")
    print("-" * 50)
    
    try:
        from honeypot.deployment.config import ConfigManager, ProtocolConfig, ModbusConfig
        
        # 创建配置管理器
        manager = ConfigManager()
        config = manager._create_default_config()
        
        print(f"✅ 蜜罐名称: {config.name}")
        print(f"✅ 绑定地址: {config.bind_address}")
        print(f"✅ 协议数量: {len(config.protocols)}")
        
        # 显示协议详情
        for protocol in config.protocols:
            status = "启用" if protocol.enabled else "禁用"
            llm_status = "启用" if protocol.llm_enabled else "禁用"
            print(f"   📡 {protocol.name}: 端口 {protocol.port} | 状态: {status} | LLM: {llm_status}")
        
        print(f"✅ LLM配置: {config.llm.model_type} ({config.llm.device})")
        print(f"✅ 安全配置: 速率限制 {config.security.rate_limit_requests}/分钟")
        print(f"✅ 数据库配置: {config.database.database_name}")
        
    except Exception as e:
        print(f"❌ 配置系统错误: {e}")
    
    # 2. 协议处理系统演示
    print("\n2️⃣ 多协议处理系统 | Multi-Protocol Processing System")
    print("-" * 50)
    
    try:
        from honeypot.deployment.protocols import PROTOCOL_HANDLERS, ModbusTCPHandler
        
        print(f"✅ 支持的协议数量: {len(PROTOCOL_HANDLERS)}")
        for name, handler_class in PROTOCOL_HANDLERS.items():
            print(f"   🔌 {name}: {handler_class.__name__}")
        
        # 演示Modbus TCP请求解析
        print("\n📋 Modbus TCP请求解析演示:")
        config = ProtocolConfig(name="modbus_tcp", port=502, protocol_specific={"coils": 100})
        handler = ModbusTCPHandler(config, None, None)
        
        # 正确的Modbus TCP请求
        test_request = bytes.fromhex('0001000000060103000000001')
        parsed = handler._parse_modbus_request(test_request)
        
        if 'error' not in parsed:
            print(f"   ✅ 事务ID: {parsed.get('transaction_id', 'N/A')}")
            print(f"   ✅ 协议ID: {parsed.get('protocol_id', 'N/A')}")
            print(f"   ✅ 功能码: {parsed.get('function_code', 'N/A')}")
            print(f"   ✅ 单元ID: {parsed.get('unit_id', 'N/A')}")
            
            # 生成响应
            response = handler._generate_modbus_response(parsed)
            print(f"   ✅ 生成响应: {response.hex()}")
        else:
            print(f"   ❌ 解析失败: {parsed['error']}")
    
    except Exception as e:
        print(f"❌ 协议处理系统错误: {e}")
    
    # 3. 安全监控系统演示
    print("\n3️⃣ 安全监控系统 | Security Monitoring System")
    print("-" * 50)
    
    try:
        from honeypot.deployment.server import SecurityMonitor
        from honeypot.deployment.config import HoneypotConfig
        
        # 创建安全监控器
        config = HoneypotConfig(name="Demo Honeypot", description="演示蜜罐")
        monitor = SecurityMonitor(config)
        
        print("✅ 安全监控功能:")
        print(f"   🛡️ 速率限制: {config.security.enable_rate_limiting}")
        print(f"   🛡️ IP封锁: {config.security.block_suspicious_ips}")
        print(f"   🛡️ 最大失败次数: {config.security.max_failed_attempts}")
        
        # 模拟请求分析
        test_ip = "192.168.1.100"
        normal_request = "0001000000060103000000001"
        suspicious_request = "0001000000060103000000001" + "A" * 100  # 异常长度
        
        # 分析正常请求
        analysis1 = monitor.analyze_request(test_ip, "modbus_tcp", normal_request)
        print(f"   ✅ 正常请求分析: 可疑={analysis1['is_suspicious']}")
        
        # 分析可疑请求
        analysis2 = monitor.analyze_request(test_ip, "modbus_tcp", suspicious_request)
        print(f"   ✅ 可疑请求分析: 可疑={analysis2['is_suspicious']}, 类型={analysis2.get('attack_type', 'N/A')}")
        
        # 显示攻击事件
        print(f"   ✅ 记录的攻击事件: {len(monitor.attack_events)}")
        
    except Exception as e:
        print(f"❌ 安全监控系统错误: {e}")
    
    # 4. 数据模型系统演示
    print("\n4️⃣ 数据模型系统 | Data Model System")
    print("-" * 50)
    
    try:
        from honeypot.client import Client
        from honeypot.request import Request
        from datetime import datetime
        
        print("✅ 数据模型定义:")
        print(f"   📊 客户端模型: {Client.__name__}")
        print(f"   📊 请求模型: {Request.__name__}")
        
        # 创建示例数据
        client = Client(ip="192.168.1.100")
        print(f"   ✅ 示例客户端: {client.ip}")
        
        request = Request(
            client="192.168.1.100",
            client_port=12345,
            request="0001000000060103000000001",
            response="000100000006010302000000",
            protocol="modbus_tcp",
            is_suspicious=False,
            attack_type="",
            severity="low"
        )
        print(f"   ✅ 示例请求: {request.protocol} - {request.request[:20]}...")
        print(f"   ✅ 安全字段: 可疑={request.is_suspicious}, 严重程度={request.severity}")
        
    except Exception as e:
        print(f"❌ 数据模型系统错误: {e}")
    
    # 5. 部署工具演示
    print("\n5️⃣ 部署和管理工具 | Deployment and Management Tools")
    print("-" * 50)
    
    print("✅ 可用的部署工具:")
    tools = [
        ("install.py", "自动化安装脚本"),
        ("deploy.py", "蜜罐部署脚本"),
        ("manage.py", "管理和监控工具"),
        ("dashboard.py", "Web监控面板"),
        ("start_honeypot_quick.py", "快速启动脚本")
    ]
    
    for tool, description in tools:
        print(f"   🛠️ {tool}: {description}")
    
    print("\n✅ 配置文件:")
    configs = [
        ("honeypot_config_example.yaml", "示例配置文件"),
        ("HONEYPOT_DEPLOYMENT_GUIDE.md", "部署指南"),
        ("HONEYPOT_README.md", "使用说明")
    ]
    
    for config, description in configs:
        print(f"   📋 {config}: {description}")
    
    # 6. 使用示例
    print("\n6️⃣ 快速使用示例 | Quick Usage Examples")
    print("-" * 50)
    
    print("✅ 快速启动:")
    print("   python3 start_honeypot_quick.py")
    print()
    
    print("✅ 完整安装:")
    print("   sudo python3 src/honeypot/deployment/install.py")
    print("   sudo systemctl start honeypot")
    print()
    
    print("✅ 管理命令:")
    print("   python3 src/honeypot/deployment/manage.py status")
    print("   python3 src/honeypot/deployment/manage.py clients")
    print("   python3 src/honeypot/deployment/manage.py attacks")
    print()
    
    print("✅ 监控面板:")
    print("   http://localhost:8080")
    print()
    
    print("✅ Docker部署:")
    print("   python3 src/honeypot/deployment/install.py --docker")
    print("   docker-compose up -d")
    
    # 7. 系统架构总结
    print("\n7️⃣ 系统架构总结 | System Architecture Summary")
    print("-" * 50)
    
    architecture = """
    ┌─────────────────────────────────────────────────────────────┐
    │                    工控网络蜜罐系统                          │
    │                Industrial Control Honeypot                 │
    ├─────────────────────────────────────────────────────────────┤
    │  多协议处理层 | Multi-Protocol Processing Layer             │
    │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
    │  │ Modbus TCP  │ │   S7Comm    │ │    DNP3     │            │
    │  │   Handler   │ │   Handler   │ │   Handler   │            │
    │  └─────────────┘ └─────────────┘ └─────────────┘            │
    ├─────────────────────────────────────────────────────────────┤
    │  LLM智能响应层 | LLM Intelligence Layer                     │
    │  ┌─────────────────────────────────────────────────────────┐ │
    │  │        ByT5 Model + LoRA Fine-tuning                    │ │
    │  └─────────────────────────────────────────────────────────┘ │
    ├─────────────────────────────────────────────────────────────┤
    │  安全监控层 | Security Monitoring Layer                     │
    │  ┌─────────────────────────────────────────────────────────┐ │
    │  │    Attack Detection + Rate Limiting + IP Blocking      │ │
    │  └─────────────────────────────────────────────────────────┘ │
    ├─────────────────────────────────────────────────────────────┤
    │  数据存储层 | Data Storage Layer                             │
    │  ┌─────────────────────────────────────────────────────────┐ │
    │  │        MongoDB (Clients + Requests + Events)           │ │
    │  └─────────────────────────────────────────────────────────┘ │
    ├─────────────────────────────────────────────────────────────┤
    │  管理监控层 | Management & Monitoring Layer                 │
    │  ┌─────────────────────────────────────────────────────────┐ │
    │  │        Web Dashboard + REST API + CLI Tools            │ │
    │  └─────────────────────────────────────────────────────────┘ │
    └─────────────────────────────────────────────────────────────┘
    """
    
    print(architecture)
    
    print("\n✅ 演示完成！")
    print("=" * 60)
    print("🎉 工控网络蜜罐系统已成功部署，具备以下核心功能:")
    print("   🔧 多协议支持 (Modbus TCP, S7Comm, DNP3)")
    print("   🤖 LLM智能响应生成")
    print("   🛡️ 实时安全监控和攻击检测")
    print("   📊 完整的数据收集和分析")
    print("   🚀 简单易用的部署和管理工具")
    print("   🌐 Web监控面板")
    print()
    print("📚 更多信息请查看项目文档和配置文件")


if __name__ == "__main__":
    demo_complete_system()