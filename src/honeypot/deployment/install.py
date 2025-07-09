#!/usr/bin/env python3
"""
工控网络蜜罐自动化部署脚本
Industrial Control Network Honeypot Automated Deployment Script
"""
import os
import sys
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, Any, List
import argparse
import yaml


class HoneypotInstaller:
    """蜜罐安装器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.config_dir = Path("/etc/honeypot")
        self.log_dir = Path("/var/log/honeypot")
        self.data_dir = Path("/var/lib/honeypot")
        
    def check_requirements(self) -> bool:
        """检查系统要求"""
        print("检查系统要求...")
        
        # 检查Python版本
        if sys.version_info < (3, 8):
            print("错误: 需要Python 3.8或更高版本")
            return False
        
        # 检查权限
        if os.geteuid() != 0:
            print("警告: 建议使用root权限运行以便绑定特权端口")
        
        # 检查磁盘空间
        statvfs = os.statvfs('/')
        free_space = statvfs.f_frsize * statvfs.f_bavail
        if free_space < 1 * 1024 * 1024 * 1024:  # 1GB
            print("警告: 磁盘空间不足，建议至少1GB可用空间")
        
        print("✓ 系统要求检查完成")
        return True
    
    def install_dependencies(self) -> bool:
        """安装依赖包"""
        print("安装Python依赖包...")
        
        try:
            # 安装pip依赖
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", 
                str(self.project_root / "requirements.txt")
            ], check=True)
            
            print("✓ Python依赖包安装完成")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"错误: 依赖包安装失败: {e}")
            return False
    
    def create_directories(self):
        """创建必要的目录"""
        print("创建目录结构...")
        
        directories = [
            self.config_dir,
            self.log_dir,
            self.data_dir,
            self.data_dir / "models",
            self.data_dir / "datasets"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"✓ 创建目录: {directory}")
    
    def create_config(self) -> Dict[str, Any]:
        """创建配置文件"""
        print("创建配置文件...")
        
        config = {
            "name": "Industrial Control Network Honeypot",
            "description": "LLM-enhanced industrial control network honeypot system",
            "bind_address": "0.0.0.0",
            "protocols": [
                {
                    "name": "modbus_tcp",
                    "port": 502,
                    "enabled": True,
                    "llm_enabled": True,
                    "response_delay": 0.1,
                    "max_connections": 100,
                    "protocol_specific": {
                        "slave_id": 1,
                        "coils": 100,
                        "discrete_inputs": 100,
                        "holding_registers": 100,
                        "input_registers": 100,
                        "device_info": {
                            "vendor": "WAGO",
                            "product_code": "750-881",
                            "vendor_url": "https://www.wago.com",
                            "product_name": "ETHERNET Programmable Fieldbus Controller",
                            "model_name": "PFC200",
                            "revision": "03.01.02"
                        }
                    }
                },
                {
                    "name": "s7comm",
                    "port": 102,
                    "enabled": True,
                    "llm_enabled": True,
                    "response_delay": 0.1,
                    "max_connections": 100,
                    "protocol_specific": {
                        "rack": 0,
                        "slot": 2,
                        "cpu_type": "CPU 1214C",
                        "system_name": "SIMATIC",
                        "module_name": "CPU 1214C AC/DC/RLY",
                        "plant_identification": "PLC_1"
                    }
                },
                {
                    "name": "dnp3",
                    "port": 20000,
                    "enabled": False,
                    "llm_enabled": True,
                    "response_delay": 0.1,
                    "max_connections": 100,
                    "protocol_specific": {
                        "link_address": 10,
                        "master_address": 1,
                        "binary_inputs": 100,
                        "analog_inputs": 50,
                        "binary_outputs": 50,
                        "analog_outputs": 25
                    }
                }
            ],
            "llm": {
                "model_type": "byt5-small",
                "model_path": str(self.data_dir / "models"),
                "max_tokens": 512,
                "temperature": 0.7,
                "use_lora": True,
                "device": "cpu",
                "batch_size": 1
            },
            "security": {
                "enable_rate_limiting": True,
                "rate_limit_requests": 100,
                "rate_limit_window": 60,
                "block_suspicious_ips": True,
                "max_failed_attempts": 10,
                "blacklist_duration": 3600,
                "enable_geo_blocking": False,
                "allowed_countries": []
            },
            "monitoring": {
                "enable_logging": True,
                "log_level": "INFO",
                "log_file": str(self.log_dir / "honeypot.log"),
                "enable_metrics": True,
                "metrics_port": 9090,
                "enable_alerts": True,
                "alert_threshold": 50
            },
            "database": {
                "mongodb_url": "mongodb://root:root@127.0.0.1:27017/honeypot?authSource=admin",
                "database_name": "honeypot",
                "collection_prefix": "hp_"
            }
        }
        
        config_path = self.config_dir / "config.yaml"
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        print(f"✓ 配置文件创建: {config_path}")
        return config
    
    def install_mongodb(self) -> bool:
        """安装MongoDB"""
        print("检查MongoDB...")
        
        try:
            # 检查MongoDB是否已安装
            result = subprocess.run(["mongod", "--version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✓ MongoDB已安装")
                return True
        except FileNotFoundError:
            pass
        
        print("MongoDB未安装，请手动安装MongoDB或使用Docker容器:")
        print("Docker命令:")
        print("docker run -d --name honeypot-mongodb -p 27017:27017 \\")
        print("  -e MONGO_INITDB_ROOT_USERNAME=root \\")
        print("  -e MONGO_INITDB_ROOT_PASSWORD=root \\")
        print("  mongo:latest")
        
        return False
    
    def create_systemd_service(self):
        """创建systemd服务"""
        print("创建systemd服务...")
        
        service_content = f"""[Unit]
Description=Industrial Control Network Honeypot
After=network.target mongodb.service
Requires=mongodb.service

[Service]
Type=simple
User=root
WorkingDirectory={self.project_root}
Environment=PYTHONPATH={self.project_root}/src
ExecStart={sys.executable} {self.project_root}/src/honeypot/deployment/deploy.py --config {self.config_dir}/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        
        service_path = Path("/etc/systemd/system/honeypot.service")
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # 重新加载systemd配置
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            print(f"✓ 服务文件创建: {service_path}")
            print("使用以下命令管理服务:")
            print("  启动: sudo systemctl start honeypot")
            print("  停止: sudo systemctl stop honeypot")
            print("  开机自启: sudo systemctl enable honeypot")
            print("  查看状态: sudo systemctl status honeypot")
            print("  查看日志: sudo journalctl -u honeypot -f")
            
        except PermissionError:
            print("警告: 无权限创建systemd服务文件")
        except subprocess.CalledProcessError:
            print("警告: 无法重新加载systemd配置")
    
    def create_docker_compose(self):
        """创建Docker Compose文件"""
        print("创建Docker Compose文件...")
        
        docker_compose_content = f"""version: '3.8'

services:
  honeypot:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: honeypot
    restart: unless-stopped
    ports:
      - "502:502"    # Modbus TCP
      - "102:102"    # S7Comm
      - "20000:20000" # DNP3
      - "8080:8080"  # Dashboard
    volumes:
      - ./config:/etc/honeypot
      - ./logs:/var/log/honeypot
      - ./data:/var/lib/honeypot
    environment:
      - PYTHONPATH=/app/src
    depends_on:
      - mongodb
    networks:
      - honeypot-network

  mongodb:
    image: mongo:latest
    container_name: honeypot-mongodb
    restart: unless-stopped
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=root
      - MONGO_INITDB_ROOT_PASSWORD=root
    volumes:
      - mongodb_data:/data/db
    networks:
      - honeypot-network

  dashboard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: honeypot-dashboard
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PYTHONPATH=/app/src
    command: python /app/src/honeypot/deployment/dashboard.py
    depends_on:
      - mongodb
    networks:
      - honeypot-network

volumes:
  mongodb_data:

networks:
  honeypot-network:
    driver: bridge
"""
        
        compose_path = self.project_root / "docker-compose.yml"
        with open(compose_path, 'w') as f:
            f.write(docker_compose_content)
        
        print(f"✓ Docker Compose文件创建: {compose_path}")
        print("使用以下命令启动:")
        print("  docker-compose up -d")
    
    def create_dockerfile(self):
        """创建Dockerfile"""
        print("创建Dockerfile...")
        
        dockerfile_content = f"""FROM python:3.9-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY . .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 创建必要的目录
RUN mkdir -p /etc/honeypot /var/log/honeypot /var/lib/honeypot

# 设置环境变量
ENV PYTHONPATH=/app/src

# 暴露端口
EXPOSE 502 102 20000 8080

# 启动命令
CMD ["python", "/app/src/honeypot/deployment/deploy.py", "--config", "/etc/honeypot/config.yaml"]
"""
        
        dockerfile_path = self.project_root / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        print(f"✓ Dockerfile创建: {dockerfile_path}")
    
    def create_startup_script(self):
        """创建启动脚本"""
        print("创建启动脚本...")
        
        script_content = f"""#!/bin/bash
# 工控网络蜜罐启动脚本
# Industrial Control Network Honeypot Startup Script

set -e

PROJECT_ROOT="{self.project_root}"
CONFIG_FILE="{self.config_dir}/config.yaml"
LOG_FILE="{self.log_dir}/honeypot.log"

# 检查配置文件
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 检查日志目录
mkdir -p "{self.log_dir}"

# 设置环境变量
export PYTHONPATH="$PROJECT_ROOT/src"

# 启动蜜罐
echo "启动工控网络蜜罐..."
echo "配置文件: $CONFIG_FILE"
echo "日志文件: $LOG_FILE"
echo "项目根目录: $PROJECT_ROOT"

cd "$PROJECT_ROOT"
exec python3 "$PROJECT_ROOT/src/honeypot/deployment/deploy.py" --config "$CONFIG_FILE"
"""
        
        script_path = self.project_root / "start_honeypot.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # 添加执行权限
        script_path.chmod(0o755)
        
        print(f"✓ 启动脚本创建: {script_path}")
    
    def install(self, enable_docker: bool = False, enable_systemd: bool = True):
        """执行安装"""
        print("开始安装工控网络蜜罐...")
        print("=" * 50)
        
        # 检查系统要求
        if not self.check_requirements():
            return False
        
        # 创建目录
        self.create_directories()
        
        # 安装依赖
        if not self.install_dependencies():
            return False
        
        # 创建配置
        config = self.create_config()
        
        # 安装MongoDB
        self.install_mongodb()
        
        # 创建启动脚本
        self.create_startup_script()
        
        # 创建systemd服务
        if enable_systemd:
            self.create_systemd_service()
        
        # 创建Docker文件
        if enable_docker:
            self.create_dockerfile()
            self.create_docker_compose()
        
        print("=" * 50)
        print("✓ 工控网络蜜罐安装完成!")
        print()
        print("下一步:")
        print("1. 检查并修改配置文件:", self.config_dir / "config.yaml")
        print("2. 确保MongoDB正在运行")
        print("3. 启动蜜罐:")
        print(f"   ./start_honeypot.sh")
        print("   或者使用systemd: sudo systemctl start honeypot")
        print("4. 访问监控面板: http://localhost:8080")
        print()
        print("配置文件位置:", self.config_dir / "config.yaml")
        print("日志文件位置:", self.log_dir / "honeypot.log")
        print("数据目录位置:", self.data_dir)
        
        return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="工控网络蜜罐安装脚本")
    parser.add_argument("--docker", action="store_true", help="生成Docker相关文件")
    parser.add_argument("--no-systemd", action="store_true", help="不创建systemd服务")
    parser.add_argument("--config-only", action="store_true", help="仅创建配置文件")
    
    args = parser.parse_args()
    
    installer = HoneypotInstaller()
    
    if args.config_only:
        installer.create_directories()
        installer.create_config()
        print("配置文件创建完成!")
        return
    
    success = installer.install(
        enable_docker=args.docker,
        enable_systemd=not args.no_systemd
    )
    
    if success:
        print("安装成功!")
    else:
        print("安装失败!")
        sys.exit(1)


if __name__ == "__main__":
    main()