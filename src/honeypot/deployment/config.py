"""
工控网络蜜罐部署配置管理系统
Industrial Control Network Honeypot Deployment Configuration Management System
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import yaml
import json
from pathlib import Path


@dataclass
class ProtocolConfig:
    """工控协议配置"""
    name: str
    port: int
    enabled: bool = True
    llm_enabled: bool = True
    response_delay: float = 0.1
    max_connections: int = 100
    protocol_specific: Dict[str, Any] = None


@dataclass
class ModbusConfig:
    """Modbus协议特定配置"""
    slave_id: int = 1
    coils: int = 100
    discrete_inputs: int = 100
    holding_registers: int = 100
    input_registers: int = 100
    device_info: Dict[str, str] = None
    
    def __post_init__(self):
        if self.device_info is None:
            self.device_info = {
                'vendor': 'WAGO',
                'product_code': '750-881',
                'vendor_url': 'https://www.wago.com',
                'product_name': 'ETHERNET Programmable Fieldbus Controller',
                'model_name': 'PFC200',
                'revision': '03.01.02'
            }


@dataclass
class S7CommConfig:
    """S7Comm协议特定配置"""
    rack: int = 0
    slot: int = 2
    cpu_type: str = "CPU 1214C"
    system_name: str = "SIMATIC"
    module_name: str = "CPU 1214C AC/DC/RLY"
    plant_identification: str = "PLC_1"


@dataclass
class DNP3Config:
    """DNP3协议特定配置"""
    link_address: int = 10
    master_address: int = 1
    binary_inputs: int = 100
    analog_inputs: int = 50
    binary_outputs: int = 50
    analog_outputs: int = 25


@dataclass
class LLMConfig:
    """LLM配置"""
    model_type: str = "byt5-small"
    model_path: str = ""
    max_tokens: int = 512
    temperature: float = 0.7
    use_lora: bool = True
    device: str = "cuda"
    batch_size: int = 1


@dataclass
class SecurityConfig:
    """安全配置"""
    enable_rate_limiting: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    block_suspicious_ips: bool = True
    max_failed_attempts: int = 10
    blacklist_duration: int = 3600
    enable_geo_blocking: bool = False
    allowed_countries: List[str] = None


@dataclass
class MonitoringConfig:
    """监控配置"""
    enable_logging: bool = True
    log_level: str = "INFO"
    log_file: str = "honeypot.log"
    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_alerts: bool = True
    alert_threshold: int = 50


@dataclass
class DatabaseConfig:
    """数据库配置"""
    mongodb_url: str = "mongodb://root:root@127.0.0.1:27017/honeypot?authSource=admin"
    database_name: str = "honeypot"
    collection_prefix: str = "hp_"


@dataclass
class HoneypotConfig:
    """蜜罐主配置"""
    name: str
    description: str
    bind_address: str = "0.0.0.0"
    protocols: List[ProtocolConfig] = None
    llm: LLMConfig = None
    security: SecurityConfig = None
    monitoring: MonitoringConfig = None
    database: DatabaseConfig = None
    
    def __post_init__(self):
        if self.protocols is None:
            self.protocols = []
        if self.llm is None:
            self.llm = LLMConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.monitoring is None:
            self.monitoring = MonitoringConfig()
        if self.database is None:
            self.database = DatabaseConfig()


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "/etc/honeypot/config.yaml"
        self.config = None
    
    def load_config(self) -> HoneypotConfig:
        """加载配置文件"""
        if not Path(self.config_path).exists():
            self.config = self._create_default_config()
            self.save_config()
        else:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                self.config = self._parse_config(data)
        return self.config
    
    def save_config(self):
        """保存配置文件"""
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self._serialize_config(), f, default_flow_style=False)
    
    def _create_default_config(self) -> HoneypotConfig:
        """创建默认配置"""
        protocols = [
            ProtocolConfig(
                name="modbus_tcp",
                port=502,
                protocol_specific=ModbusConfig().__dict__
            ),
            ProtocolConfig(
                name="s7comm",
                port=102,
                protocol_specific=S7CommConfig().__dict__
            ),
            ProtocolConfig(
                name="dnp3",
                port=20000,
                protocol_specific=DNP3Config().__dict__
            )
        ]
        
        return HoneypotConfig(
            name="Industrial Control Network Honeypot",
            description="LLM-enhanced industrial control network honeypot system",
            protocols=protocols
        )
    
    def _parse_config(self, data: Dict) -> HoneypotConfig:
        """解析配置数据"""
        protocols = []
        for p in data.get('protocols', []):
            protocols.append(ProtocolConfig(**p))
        
        config = HoneypotConfig(
            name=data.get('name', 'Default Honeypot'),
            description=data.get('description', ''),
            bind_address=data.get('bind_address', '0.0.0.0'),
            protocols=protocols
        )
        
        if 'llm' in data:
            config.llm = LLMConfig(**data['llm'])
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])
        if 'monitoring' in data:
            config.monitoring = MonitoringConfig(**data['monitoring'])
        if 'database' in data:
            config.database = DatabaseConfig(**data['database'])
        
        return config
    
    def _serialize_config(self) -> Dict:
        """序列化配置为字典"""
        return {
            'name': self.config.name,
            'description': self.config.description,
            'bind_address': self.config.bind_address,
            'protocols': [p.__dict__ for p in self.config.protocols],
            'llm': self.config.llm.__dict__,
            'security': self.config.security.__dict__,
            'monitoring': self.config.monitoring.__dict__,
            'database': self.config.database.__dict__
        }
    
    def get_protocol_config(self, protocol_name: str) -> Optional[ProtocolConfig]:
        """获取指定协议配置"""
        for protocol in self.config.protocols:
            if protocol.name == protocol_name:
                return protocol
        return None
    
    def add_protocol(self, protocol: ProtocolConfig):
        """添加协议配置"""
        self.config.protocols.append(protocol)
    
    def remove_protocol(self, protocol_name: str):
        """移除协议配置"""
        self.config.protocols = [p for p in self.config.protocols if p.name != protocol_name]