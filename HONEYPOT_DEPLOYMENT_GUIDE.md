# 工控网络蜜罐部署指南 | Industrial Control Network Honeypot Deployment Guide

## 概述 | Overview

本项目提供了一个基于LLM（大语言模型）增强的工控网络蜜罐系统，支持多种工控协议包括Modbus TCP、S7Comm、DNP3等。该系统可以智能地模拟真实的工控设备行为，用于网络安全研究和攻击检测。

This project provides an LLM-enhanced industrial control network honeypot system that supports multiple industrial protocols including Modbus TCP, S7Comm, DNP3, etc. The system can intelligently simulate real industrial device behavior for network security research and attack detection.

## 主要特性 | Key Features

- **多协议支持**: Modbus TCP, S7Comm, DNP3等工控协议
- **LLM智能响应**: 基于ByT5模型的智能响应生成
- **实时监控**: Web界面实时监控攻击活动
- **安全防护**: 速率限制、IP封锁、攻击检测
- **数据分析**: 完整的攻击数据收集和分析
- **易于部署**: 支持Docker、systemd等多种部署方式

## 系统架构 | System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    工控网络蜜罐系统                          │
│                Industrial Control Honeypot                 │
├─────────────────────────────────────────────────────────────┤
│  协议处理层 Protocol Handlers                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ Modbus TCP  │ │   S7Comm    │ │    DNP3     │            │
│  │   Handler   │ │   Handler   │ │   Handler   │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
├─────────────────────────────────────────────────────────────┤
│  智能响应层 Intelligent Response Layer                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           LLM Response Generator                        │ │
│  │         (ByT5 Model + LoRA Fine-tuning)                 │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  安全监控层 Security Monitoring Layer                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Security Monitor + Attack Detection + Rate Limiting   │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  数据存储层 Data Storage Layer                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              MongoDB Database                           │ │
│  │        (Clients, Requests, Attack Events)              │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  管理监控层 Management & Monitoring Layer                    │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │          Web Dashboard + REST API                       │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 快速部署 | Quick Deployment

### 1. 自动安装 | Automatic Installation

```bash
# 克隆仓库
git clone https://github.com/WhhPisces/LLMPot.git
cd LLMPot

# 运行自动安装脚本
sudo python3 src/honeypot/deployment/install.py

# 启动蜜罐
sudo systemctl start honeypot

# 查看状态
sudo systemctl status honeypot

# 访问监控面板
open http://localhost:8080
```

### 2. Docker部署 | Docker Deployment

```bash
# 生成Docker文件
python3 src/honeypot/deployment/install.py --docker

# 使用Docker Compose启动
docker-compose up -d

# 查看日志
docker-compose logs -f honeypot

# 停止服务
docker-compose down
```

### 3. 手动配置 | Manual Configuration

```bash
# 创建配置目录
sudo mkdir -p /etc/honeypot /var/log/honeypot /var/lib/honeypot

# 生成配置文件
python3 src/honeypot/deployment/install.py --config-only

# 编辑配置文件
sudo nano /etc/honeypot/config.yaml

# 启动MongoDB
docker run -d --name honeypot-mongodb -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=root \
  -e MONGO_INITDB_ROOT_PASSWORD=root \
  mongo:latest

# 启动蜜罐
python3 src/honeypot/deployment/deploy.py --config /etc/honeypot/config.yaml
```

## 配置说明 | Configuration Guide

### 基础配置 | Basic Configuration

```yaml
name: "Industrial Control Network Honeypot"
description: "LLM-enhanced industrial control network honeypot system"
bind_address: "0.0.0.0"
```

### 协议配置 | Protocol Configuration

```yaml
protocols:
  - name: "modbus_tcp"
    port: 502
    enabled: true
    llm_enabled: true
    response_delay: 0.1
    max_connections: 100
    protocol_specific:
      slave_id: 1
      coils: 100
      holding_registers: 100
      device_info:
        vendor: "WAGO"
        product_code: "750-881"
        product_name: "ETHERNET Programmable Fieldbus Controller"
        model_name: "PFC200"
        revision: "03.01.02"
```

### LLM配置 | LLM Configuration

```yaml
llm:
  model_type: "byt5-small"
  model_path: "/var/lib/honeypot/models"
  max_tokens: 512
  temperature: 0.7
  use_lora: true
  device: "cuda"  # 或 "cpu"
  batch_size: 1
```

### 安全配置 | Security Configuration

```yaml
security:
  enable_rate_limiting: true
  rate_limit_requests: 100
  rate_limit_window: 60
  block_suspicious_ips: true
  max_failed_attempts: 10
  blacklist_duration: 3600
```

## 使用指南 | Usage Guide

### 启动和停止 | Start and Stop

```bash
# 启动蜜罐
sudo systemctl start honeypot

# 停止蜜罐
sudo systemctl stop honeypot

# 重启蜜罐
sudo systemctl restart honeypot

# 开机自启
sudo systemctl enable honeypot
```

### 监控和管理 | Monitoring and Management

```bash
# 查看实时状态
python3 src/honeypot/deployment/manage.py status

# 查看客户端信息
python3 src/honeypot/deployment/manage.py clients

# 查看攻击信息
python3 src/honeypot/deployment/manage.py attacks

# 生成报告
python3 src/honeypot/deployment/manage.py report --output report.json
```

### Web管理界面 | Web Management Interface

访问 `http://localhost:8080` 查看实时监控界面，包括：

- 实时统计数据
- 攻击事件时间线
- 客户端连接信息
- 协议活动统计
- 攻击类型分析

## 协议支持 | Protocol Support

### Modbus TCP
- 支持所有标准Modbus功能码
- 模拟真实PLC寄存器和线圈
- 检测异常功能码和攻击模式
- 支持设备信息模拟

### S7Comm (Siemens)
- 支持S7-200/300/400/1200/1500系列
- TPKT/COTP协议栈支持
- 设备识别和通信参数配置
- 攻击检测和日志记录

### DNP3
- 支持DNP3 Level 2协议
- 二进制和模拟量点位模拟
- 主站和从站通信模拟
- 异常检测和安全分析

## 攻击检测 | Attack Detection

系统内置多种攻击检测机制：

1. **协议层检测**
   - 恶意功能码检测
   - 协议格式异常检测
   - 非法参数检测

2. **行为分析**
   - 频率异常检测
   - 连接模式分析
   - 请求序列分析

3. **安全防护**
   - 速率限制
   - IP黑名单
   - 地理位置过滤

## 数据分析 | Data Analysis

### 数据收集 | Data Collection

系统自动收集以下数据：
- 客户端连接信息
- 协议请求和响应
- 攻击事件和类型
- 网络流量统计

### 分析工具 | Analysis Tools

```bash
# 查看统计数据
python3 src/honeypot/deployment/manage.py protocols

# 生成详细报告
python3 src/honeypot/deployment/manage.py report --output detailed_report.json

# 导出数据库数据
mongodump --uri="mongodb://root:root@localhost:27017/honeypot?authSource=admin"
```

## 故障排除 | Troubleshooting

### 常见问题 | Common Issues

1. **端口被占用**
   ```bash
   # 查看端口使用情况
   sudo netstat -tulpn | grep :502
   
   # 修改配置文件中的端口号
   sudo nano /etc/honeypot/config.yaml
   ```

2. **MongoDB连接失败**
   ```bash
   # 检查MongoDB状态
   sudo systemctl status mongod
   
   # 或检查Docker容器
   docker ps | grep mongodb
   ```

3. **LLM模型加载失败**
   ```bash
   # 检查模型文件
   ls -la /var/lib/honeypot/models/
   
   # 检查CUDA可用性
   python3 -c "import torch; print(torch.cuda.is_available())"
   ```

### 日志查看 | Log Viewing

```bash
# 查看系统日志
sudo journalctl -u honeypot -f

# 查看应用日志
sudo tail -f /var/log/honeypot/honeypot.log

# 查看MongoDB日志
sudo journalctl -u mongod -f
```

## 性能优化 | Performance Optimization

### 硬件建议 | Hardware Recommendations

- **CPU**: 4核心以上，支持AVX指令集
- **内存**: 8GB以上（LLM模型需要较多内存）
- **存储**: SSD硬盘，至少50GB可用空间
- **网络**: 千兆网络接口

### 配置优化 | Configuration Optimization

```yaml
# 高性能配置示例
llm:
  batch_size: 4  # 增加批处理大小
  device: "cuda"  # 使用GPU加速

security:
  rate_limit_requests: 200  # 提高速率限制
  rate_limit_window: 30     # 减少时间窗口

monitoring:
  log_level: "WARNING"  # 减少日志输出
```

## 安全考虑 | Security Considerations

### 生产环境部署 | Production Deployment

1. **网络隔离**: 将蜜罐部署在隔离的网络段
2. **访问控制**: 限制管理界面访问
3. **数据加密**: 启用MongoDB认证和加密
4. **日志管理**: 定期轮转和备份日志文件

### 法律合规 | Legal Compliance

- 确保符合当地法律法规
- 设置适当的免责声明
- 定期审查和更新安全策略
- 保护收集的数据隐私

## 开发和扩展 | Development and Extension

### 添加新协议 | Adding New Protocols

1. 创建协议处理器类
2. 实现请求解析和响应生成
3. 添加到协议映射表
4. 更新配置文件

### 自定义攻击检测 | Custom Attack Detection

```python
def custom_attack_detector(request_data):
    # 实现自定义攻击检测逻辑
    if detect_malicious_pattern(request_data):
        return {
            'is_suspicious': True,
            'attack_type': 'custom_attack',
            'severity': 'high',
            'description': 'Custom attack detected'
        }
    return {'is_suspicious': False}
```

## 技术支持 | Technical Support

### 问题反馈 | Issue Reporting

- GitHub Issues: https://github.com/WhhPisces/LLMPot/issues
- Email: support@llmpot.com
- 文档: https://llmpot.readthedocs.io/

### 贡献指南 | Contributing

1. Fork 项目仓库
2. 创建功能分支
3. 提交代码更改
4. 创建Pull Request

---

## 许可证 | License

本项目采用 GPL v3 许可证，详见 [LICENSE](LICENSE) 文件。

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.

## 致谢 | Acknowledgments

- 感谢所有贡献者和测试者
- 基于开源项目构建
- 感谢工控安全研究社区的支持

---

*最后更新: 2024年*
*Last updated: 2024*