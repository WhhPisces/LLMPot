#!/usr/bin/env python3
"""
工控网络蜜罐部署脚本
Industrial Control Network Honeypot Deployment Script
"""
import argparse
import asyncio
import logging
import sys
import os
import signal
from pathlib import Path
import yaml
import json
from typing import Dict, Any

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from honeypot.deployment.config import ConfigManager, HoneypotConfig
from honeypot.deployment.server import HoneypotServer


class HoneypotDeployment:
    """蜜罐部署管理器"""
    
    def __init__(self):
        self.server = None
        self.config = None
        self.running = False
        
    def setup_logging(self, log_level: str = "INFO", log_file: str = None):
        """设置日志"""
        level = getattr(logging, log_level.upper())
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 配置根日志记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # 文件处理器
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    
    def load_config(self, config_path: str) -> HoneypotConfig:
        """加载配置"""
        manager = ConfigManager(config_path)
        self.config = manager.load_config()
        return self.config
    
    def create_sample_config(self, output_path: str):
        """创建示例配置文件"""
        manager = ConfigManager()
        config = manager._create_default_config()
        
        # 添加一些示例配置
        config.description = "示例工控网络蜜罐配置 - Sample Industrial Control Network Honeypot Configuration"
        
        # 更新协议配置
        for protocol in config.protocols:
            if protocol.name == "modbus_tcp":
                protocol.protocol_specific.update({
                    "device_info": {
                        "vendor": "Schneider Electric",
                        "product_code": "TM221CE16R",
                        "vendor_url": "https://www.schneider-electric.com",
                        "product_name": "Modicon M221 Logic Controller",
                        "model_name": "TM221CE16R",
                        "revision": "1.0.0.0"
                    }
                })
        
        # 保存配置
        manager.config = config
        manager.config_path = output_path
        manager.save_config()
        
        print(f"示例配置文件已创建: {output_path}")
        print("请根据您的需求修改配置文件，然后使用 --config 参数启动蜜罐")
    
    def validate_config(self, config: HoneypotConfig) -> bool:
        """验证配置"""
        errors = []
        
        # 检查基本配置
        if not config.name:
            errors.append("蜜罐名称不能为空")
        
        if not config.protocols:
            errors.append("至少需要启用一个协议")
        
        # 检查协议配置
        enabled_protocols = [p for p in config.protocols if p.enabled]
        if not enabled_protocols:
            errors.append("至少需要启用一个协议")
        
        # 检查端口冲突
        ports = [p.port for p in enabled_protocols]
        if len(ports) != len(set(ports)):
            errors.append("协议端口不能重复")
        
        # 检查端口范围
        for protocol in enabled_protocols:
            if protocol.port < 1 or protocol.port > 65535:
                errors.append(f"协议 {protocol.name} 端口 {protocol.port} 超出有效范围")
        
        # 检查LLM配置
        if config.llm.device not in ["cpu", "cuda"]:
            errors.append("LLM设备必须是 'cpu' 或 'cuda'")
        
        if errors:
            print("配置验证失败:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True
    
    def print_config_summary(self, config: HoneypotConfig):
        """打印配置摘要"""
        print("\n" + "="*60)
        print(f"蜜罐名称: {config.name}")
        print(f"描述: {config.description}")
        print(f"绑定地址: {config.bind_address}")
        print("="*60)
        
        print("\n协议配置:")
        for protocol in config.protocols:
            status = "启用" if protocol.enabled else "禁用"
            llm_status = "启用" if protocol.llm_enabled else "禁用"
            print(f"  {protocol.name:15} 端口: {protocol.port:5} 状态: {status:4} LLM: {llm_status}")
        
        print(f"\nLLM配置:")
        print(f"  模型类型: {config.llm.model_type}")
        print(f"  设备: {config.llm.device}")
        print(f"  最大令牌数: {config.llm.max_tokens}")
        
        print(f"\n安全配置:")
        print(f"  速率限制: {'启用' if config.security.enable_rate_limiting else '禁用'}")
        print(f"  阻止可疑IP: {'启用' if config.security.block_suspicious_ips else '禁用'}")
        
        print(f"\n数据库配置:")
        print(f"  MongoDB URL: {config.database.mongodb_url}")
        print(f"  数据库名: {config.database.database_name}")
        
        print("="*60)
    
    def setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(signum, frame):
            logging.info(f"收到信号 {signum}, 正在关闭蜜罐...")
            self.running = False
            if self.server:
                asyncio.create_task(self.server.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def deploy(self, config_path: str, daemon: bool = False):
        """部署蜜罐"""
        # 加载配置
        config = self.load_config(config_path)
        
        # 验证配置
        if not self.validate_config(config):
            return False
        
        # 打印配置摘要
        self.print_config_summary(config)
        
        # 设置日志
        self.setup_logging(
            config.monitoring.log_level,
            config.monitoring.log_file if config.monitoring.enable_logging else None
        )
        
        # 创建服务器
        self.server = HoneypotServer(config)
        
        # 初始化服务器
        await self.server.initialize()
        
        # 设置信号处理器
        self.setup_signal_handlers()
        
        # 启动服务器
        self.running = True
        logging.info("蜜罐部署启动中...")
        
        try:
            await self.server.start()
        except KeyboardInterrupt:
            logging.info("收到中断信号")
        except Exception as e:
            logging.error(f"蜜罐运行时错误: {e}")
        finally:
            await self.server.stop()
            self.running = False
        
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """获取蜜罐状态"""
        if not self.server:
            return {"status": "stopped", "message": "蜜罐未启动"}
        
        stats = self.server.get_statistics()
        stats["status"] = "running" if self.running else "stopped"
        stats["config_name"] = self.config.name if self.config else "未知"
        
        return stats


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="工控网络蜜罐部署工具 - Industrial Control Network Honeypot Deployment Tool"
    )
    
    parser.add_argument(
        "--config", "-c",
        default="./honeypot_config.yaml",
        help="配置文件路径 (默认: ./honeypot_config.yaml)"
    )
    
    parser.add_argument(
        "--create-config",
        metavar="FILE",
        help="创建示例配置文件"
    )
    
    parser.add_argument(
        "--validate",
        action="store_true",
        help="验证配置文件"
    )
    
    parser.add_argument(
        "--daemon", "-d",
        action="store_true",
        help="以守护进程模式运行"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="日志级别 (默认: INFO)"
    )
    
    parser.add_argument(
        "--status",
        action="store_true",
        help="显示蜜罐状态"
    )
    
    args = parser.parse_args()
    
    deployment = HoneypotDeployment()
    
    # 创建示例配置
    if args.create_config:
        deployment.create_sample_config(args.create_config)
        return
    
    # 验证配置
    if args.validate:
        config = deployment.load_config(args.config)
        if deployment.validate_config(config):
            print("配置验证通过 ✓")
        else:
            sys.exit(1)
        return
    
    # 显示状态
    if args.status:
        status = deployment.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
        return
    
    # 部署蜜罐
    try:
        success = asyncio.run(deployment.deploy(args.config, args.daemon))
        if not success:
            sys.exit(1)
    except Exception as e:
        print(f"部署失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()