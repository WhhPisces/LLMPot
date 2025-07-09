#!/usr/bin/env python3
"""
工控网络蜜罐快速启动脚本
Industrial Control Network Honeypot Quick Start Script
"""
import os
import sys
import subprocess
import time
from pathlib import Path

def main():
    """主函数"""
    print("=" * 60)
    print("工控网络蜜罐快速启动 | Industrial Control Network Honeypot Quick Start")
    print("=" * 60)
    
    project_root = Path(__file__).parent
    config_file = project_root / "honeypot_config_example.yaml"
    
    # 检查配置文件
    if not config_file.exists():
        print(f"❌ 配置文件不存在: {config_file}")
        return
    
    # 设置环境变量
    os.environ['PYTHONPATH'] = str(project_root / 'src')
    
    print(f"📁 项目根目录: {project_root}")
    print(f"⚙️  配置文件: {config_file}")
    print(f"🐍 Python路径: {os.environ.get('PYTHONPATH')}")
    print()
    
    # 检查MongoDB
    print("🔍 检查MongoDB连接...")
    try:
        # 尝试连接MongoDB
        import pymongo
        client = pymongo.MongoClient("mongodb://root:root@127.0.0.1:27017/", serverSelectionTimeoutMS=5000)
        client.server_info()
        print("✅ MongoDB连接成功")
    except Exception as e:
        print(f"❌ MongoDB连接失败: {e}")
        print("请启动MongoDB或使用以下Docker命令:")
        print("docker run -d --name honeypot-mongodb -p 27017:27017 \\")
        print("  -e MONGO_INITDB_ROOT_USERNAME=root \\")
        print("  -e MONGO_INITDB_ROOT_PASSWORD=root \\")
        print("  mongo:latest")
        return
    
    # 检查Python依赖
    print("\n🔍 检查Python依赖...")
    try:
        import torch
        import transformers
        import beanie
        import motor
        print("✅ 主要依赖已安装")
    except ImportError as e:
        print(f"❌ 依赖缺失: {e}")
        print("请运行: pip install -r requirements.txt")
        return
    
    # 启动蜜罐
    print("\n🚀 启动工控网络蜜罐...")
    print("按 Ctrl+C 停止蜜罐")
    print("-" * 60)
    
    try:
        # 启动蜜罐服务器
        deploy_script = project_root / "src" / "honeypot" / "deployment" / "deploy.py"
        cmd = [sys.executable, str(deploy_script), "--config", str(config_file)]
        subprocess.run(cmd, check=True)
        
    except KeyboardInterrupt:
        print("\n\n🛑 收到中断信号，正在关闭蜜罐...")
        print("蜜罐已停止")
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ 蜜罐启动失败: {e}")
        
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")

if __name__ == "__main__":
    main()