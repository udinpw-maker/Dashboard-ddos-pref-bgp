import random
import time
from datetime import datetime, timedelta
from enum import Enum

class AttackType(Enum):
    VOLUMETRIC = "Volumetric Attack"
    PROTOCOL = "Protocol-based Attack"
    APPLICATION = "Application-layer Attack"
    NONE = "No Attack"

class AttackSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"

class AttackDetector:
    """Real-time DDoS Attack Detection"""
    
    def __init__(self):
        self.active_attacks = []
        self.attack_history = []
        self.simulation_mode = True  # Untuk demo/testing
        
    def get_severity_level(self, traffic_gbps):
        """Tentukan severity berdasarkan traffic volume"""
        if traffic_gbps > 100:
            return AttackSeverity.CRITICAL
        elif traffic_gbps > 50:
            return AttackSeverity.HIGH
        elif traffic_gbps > 20:
            return AttackSeverity.MEDIUM
        elif traffic_gbps > 5:
            return AttackSeverity.LOW
        return AttackSeverity.NONE
    
    def generate_mock_attack(self):
        """Generate mock attack untuk demo"""
        attack_types = [
            AttackType.VOLUMETRIC,
            AttackType.PROTOCOL,
            AttackType.APPLICATION
        ]
        
        source_regions = ["AS", "US", "EU", "CN", "BR"]
        prefixes = [
            "157.85.223.0/24",
            "157.85.224.0/24",
            "157.85.225.0/24"
        ]
        
        traffic_gbps = random.uniform(10, 150)
        attack_type = random.choice(attack_types)
        severity = self.get_severity_level(traffic_gbps)
        
        attack = {
            "id": f"ATK-{int(time.time())}-{random.randint(1000, 9999)}",
            "type": attack_type.value,
            "severity": severity.value,
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "source_region": random.choice(source_regions),
            "target_prefix": random.choice(prefixes),
            "traffic_gbps": round(traffic_gbps, 2),
            "packets_per_sec": random.randint(100000, 10000000),
            "start_time": datetime.now().isoformat(),
            "duration_seconds": random.randint(60, 3600),
            "status": "Active",
            "detection_confidence": round(random.uniform(80, 99.9), 2)
        }
        
        return attack
    
    def detect_attack(self):
        """Deteksi serangan (simulasi atau real)"""
        if self.simulation_mode:
            # Simulasi: 30% chance ada attack aktif
            if random.random() < 0.3:
                attack = self.generate_mock_attack()
                self.active_attacks.append(attack)
                self.attack_history.append(attack)
                return attack
        
        return None
    
    def get_active_attacks(self):
        """Dapatkan semua attack yang aktif"""
        # Cleanup attacks yang sudah expired
        current_time = datetime.now()
        self.active_attacks = [
            atk for atk in self.active_attacks
            if (datetime.fromisoformat(atk["start_time"]) + 
                timedelta(seconds=atk["duration_seconds"])) > current_time
        ]
        
        return self.active_attacks
    
    def get_attack_stats(self):
        """Statistik serangan"""
        active = self.get_active_attacks()
        
        if not active:
            return {
                "total_active": 0,
                "total_severity": "None",
                "avg_traffic_gbps": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0
            }
        
        stats = {
            "total_active": len(active),
            "total_severity": max([a["severity"] for a in active]),
            "avg_traffic_gbps": round(sum([a["traffic_gbps"] for a in active]) / len(active), 2),
            "critical_count": len([a for a in active if a["severity"] == "Critical"]),
            "high_count": len([a for a in active if a["severity"] == "High"]),
            "medium_count": len([a for a in active if a["severity"] == "Medium"]),
            "low_count": len([a for a in active if a["severity"] == "Low"])
        }
        
        return stats
    
    def get_attack_history(self, limit=50):
        """Dapatkan riwayat serangan"""
        return self.attack_history[-limit:]
    
    def get_threat_intelligence(self):
        """Threat Intelligence - Top attacking sources"""
        if not self.attack_history:
            return []
        
        # Group by source region
        threat_map = {}
        for attack in self.attack_history[-100:]:
            region = attack["source_region"]
            if region not in threat_map:
                threat_map[region] = {
                    "region": region,
                    "attack_count": 0,
                    "total_traffic_gbps": 0,
                    "severity": "None"
                }
            threat_map[region]["attack_count"] += 1
            threat_map[region]["total_traffic_gbps"] += attack["traffic_gbps"]
            threat_map[region]["severity"] = attack["severity"]
        
        return sorted(threat_map.values(), key=lambda x: x["attack_count"], reverse=True)