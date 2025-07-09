#!/usr/bin/env python3
"""
工控网络蜜罐管理工具
Industrial Control Network Honeypot Management Tool
"""
import argparse
import json
import sys
import subprocess
from pathlib import Path
from typing import Dict, Any, List
import requests
import tabulate
from datetime import datetime, timedelta


class HoneypotManager:
    """蜜罐管理器"""
    
    def __init__(self, config_path: str = None, dashboard_url: str = None):
        self.config_path = config_path or "/etc/honeypot/config.yaml"
        self.dashboard_url = dashboard_url or "http://localhost:8080"
        
    def get_status(self) -> Dict[str, Any]:
        """获取蜜罐状态"""
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_config(self) -> Dict[str, Any]:
        """获取配置信息"""
        try:
            response = requests.get(f"{self.dashboard_url}/api/config", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_clients(self) -> Dict[str, Any]:
        """获取客户端信息"""
        try:
            response = requests.get(f"{self.dashboard_url}/api/clients", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_attacks(self) -> Dict[str, Any]:
        """获取攻击信息"""
        try:
            response = requests.get(f"{self.dashboard_url}/api/attacks", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_protocol_stats(self) -> Dict[str, Any]:
        """获取协议统计"""
        try:
            response = requests.get(f"{self.dashboard_url}/api/protocols", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def display_status(self):
        """显示蜜罐状态"""
        print("工控网络蜜罐状态")
        print("=" * 50)
        
        status = self.get_status()
        if "error" in status:
            print(f"❌ 无法获取状态: {status['error']}")
            return
        
        config = self.get_config()
        if "error" not in config:
            print(f"蜜罐名称: {config.get('name', 'Unknown')}")
            print(f"描述: {config.get('description', 'Unknown')}")
            print()
        
        print(f"总客户端数: {status.get('total_clients', 0)}")
        print(f"总请求数: {status.get('total_requests', 0)}")
        print(f"24小时请求: {status.get('recent_requests', 0)}")
        print(f"可疑请求: {status.get('suspicious_requests', 0)}")
        
        # 显示攻击类型统计
        attack_types = status.get('attack_types', [])
        if attack_types:
            print("\n攻击类型统计:")
            for attack_type in attack_types:
                print(f"  {attack_type['_id']}: {attack_type['count']}")
    
    def display_config(self):
        """显示配置信息"""
        print("蜜罐配置")
        print("=" * 50)
        
        config = self.get_config()
        if "error" in config:
            print(f"❌ 无法获取配置: {config['error']}")
            return
        
        print(f"名称: {config.get('name', 'Unknown')}")
        print(f"描述: {config.get('description', 'Unknown')}")
        print()
        
        print("协议配置:")
        protocols = config.get('protocols', [])
        if protocols:
            headers = ["协议", "端口", "状态", "LLM"]
            rows = []
            for protocol in protocols:
                status = "✓" if protocol['enabled'] else "✗"
                llm_status = "✓" if protocol['llm_enabled'] else "✗"
                rows.append([protocol['name'], protocol['port'], status, llm_status])
            
            print(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
        
        print(f"\nLLM配置:")
        llm = config.get('llm', {})
        print(f"  模型类型: {llm.get('model_type', 'Unknown')}")
        print(f"  设备: {llm.get('device', 'Unknown')}")
    
    def display_clients(self):
        """显示客户端信息"""
        print("客户端信息")
        print("=" * 50)
        
        clients_data = self.get_clients()
        if "error" in clients_data:
            print(f"❌ 无法获取客户端信息: {clients_data['error']}")
            return
        
        clients = clients_data.get('clients', [])
        if not clients:
            print("无客户端连接")
            return
        
        headers = ["IP地址", "首次连接", "请求数", "可疑请求", "风险等级"]
        rows = []
        
        for client in clients:
            first_contact = datetime.fromisoformat(client['first_contact'].replace('Z', '+00:00'))
            formatted_time = first_contact.strftime('%Y-%m-%d %H:%M:%S')
            
            risk_level = client['risk_level']
            if risk_level == 'high':
                risk_display = "🔴 高"
            elif risk_level == 'medium':
                risk_display = "🟡 中"
            else:
                risk_display = "🟢 低"
            
            rows.append([
                client['ip'],
                formatted_time,
                client['request_count'],
                client['suspicious_count'],
                risk_display
            ])
        
        print(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
    
    def display_attacks(self):
        """显示攻击信息"""
        print("最近攻击事件")
        print("=" * 50)
        
        attacks_data = self.get_attacks()
        if "error" in attacks_data:
            print(f"❌ 无法获取攻击信息: {attacks_data['error']}")
            return
        
        attacks = attacks_data.get('attacks', [])
        if not attacks:
            print("暂无攻击事件")
            return
        
        headers = ["时间", "客户端IP", "协议", "攻击类型", "严重程度"]
        rows = []
        
        for attack in attacks[:20]:  # 显示最近20个攻击
            timestamp = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00'))
            formatted_time = timestamp.strftime('%m-%d %H:%M:%S')
            
            severity = attack['severity']
            if severity == 'high':
                severity_display = "🔴 高"
            elif severity == 'medium':
                severity_display = "🟡 中"
            else:
                severity_display = "🟢 低"
            
            rows.append([
                formatted_time,
                attack['client_ip'],
                attack['protocol'],
                attack['attack_type'],
                severity_display
            ])
        
        print(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
    
    def display_protocols(self):
        """显示协议统计"""
        print("协议统计")
        print("=" * 50)
        
        protocol_data = self.get_protocol_stats()
        if "error" in protocol_data:
            print(f"❌ 无法获取协议统计: {protocol_data['error']}")
            return
        
        protocol_stats = protocol_data.get('protocol_stats', [])
        if not protocol_stats:
            print("暂无协议统计数据")
            return
        
        headers = ["协议", "总请求数", "可疑请求", "可疑比例"]
        rows = []
        
        for stats in protocol_stats:
            protocol = stats['_id']
            total_requests = stats['total_requests']
            suspicious_requests = stats['suspicious_requests']
            
            if total_requests > 0:
                suspicious_ratio = f"{suspicious_requests / total_requests * 100:.1f}%"
            else:
                suspicious_ratio = "0%"
            
            rows.append([
                protocol,
                total_requests,
                suspicious_requests,
                suspicious_ratio
            ])
        
        print(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
    
    def generate_report(self, output_file: str = None):
        """生成报告"""
        print("生成蜜罐报告")
        print("=" * 50)
        
        # 收集所有数据
        status = self.get_status()
        config = self.get_config()
        clients_data = self.get_clients()
        attacks_data = self.get_attacks()
        protocol_data = self.get_protocol_stats()
        
        # 生成报告
        report = {
            "generated_at": datetime.now().isoformat(),
            "status": status,
            "config": config,
            "clients": clients_data,
            "attacks": attacks_data,
            "protocols": protocol_data
        }
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"报告已保存到: {output_file}")
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
    
    def start_service(self):
        """启动服务"""
        print("启动蜜罐服务...")
        try:
            subprocess.run(["systemctl", "start", "honeypot"], check=True)
            print("✓ 服务启动成功")
        except subprocess.CalledProcessError:
            print("❌ 服务启动失败")
        except FileNotFoundError:
            print("❌ systemctl命令不可用")
    
    def stop_service(self):
        """停止服务"""
        print("停止蜜罐服务...")
        try:
            subprocess.run(["systemctl", "stop", "honeypot"], check=True)
            print("✓ 服务停止成功")
        except subprocess.CalledProcessError:
            print("❌ 服务停止失败")
        except FileNotFoundError:
            print("❌ systemctl命令不可用")
    
    def restart_service(self):
        """重启服务"""
        print("重启蜜罐服务...")
        try:
            subprocess.run(["systemctl", "restart", "honeypot"], check=True)
            print("✓ 服务重启成功")
        except subprocess.CalledProcessError:
            print("❌ 服务重启失败")
        except FileNotFoundError:
            print("❌ systemctl命令不可用")
    
    def service_status(self):
        """显示服务状态"""
        print("蜜罐服务状态")
        print("=" * 50)
        try:
            result = subprocess.run(["systemctl", "status", "honeypot"], 
                                  capture_output=True, text=True)
            print(result.stdout)
        except FileNotFoundError:
            print("❌ systemctl命令不可用")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="工控网络蜜罐管理工具")
    parser.add_argument("--config", "-c", help="配置文件路径")
    parser.add_argument("--dashboard", "-d", help="Dashboard URL")
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 状态命令
    subparsers.add_parser("status", help="显示蜜罐状态")
    subparsers.add_parser("config", help="显示配置信息")
    subparsers.add_parser("clients", help="显示客户端信息")
    subparsers.add_parser("attacks", help="显示攻击信息")
    subparsers.add_parser("protocols", help="显示协议统计")
    
    # 报告命令
    report_parser = subparsers.add_parser("report", help="生成报告")
    report_parser.add_argument("--output", "-o", help="输出文件路径")
    
    # 服务管理命令
    subparsers.add_parser("start", help="启动服务")
    subparsers.add_parser("stop", help="停止服务")
    subparsers.add_parser("restart", help="重启服务")
    subparsers.add_parser("service-status", help="显示服务状态")
    
    args = parser.parse_args()
    
    # 如果没有指定命令，显示状态
    if not args.command:
        args.command = "status"
    
    manager = HoneypotManager(args.config, args.dashboard)
    
    if args.command == "status":
        manager.display_status()
    elif args.command == "config":
        manager.display_config()
    elif args.command == "clients":
        manager.display_clients()
    elif args.command == "attacks":
        manager.display_attacks()
    elif args.command == "protocols":
        manager.display_protocols()
    elif args.command == "report":
        manager.generate_report(args.output)
    elif args.command == "start":
        manager.start_service()
    elif args.command == "stop":
        manager.stop_service()
    elif args.command == "restart":
        manager.restart_service()
    elif args.command == "service-status":
        manager.service_status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()