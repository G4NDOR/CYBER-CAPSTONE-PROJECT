import ipaddress
import os
import time
from datetime import datetime, timezone
import requests

class VirusTotalPlugin:
    API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    MAX_CACHE_AGE = 3600 #for the free limit
    TIMEOUT = 10
    
    def __init__(self):
        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._cache = {}   
        self._session = requests.Session()
    
    @staticmethod
    def _verdict(malicious: int, suspicious: int, total: int) -> str:
        if total and malicious >= total:
            return "Confirmed Malicious"
        elif malicious + suspicious >= 20:
            return "Suspicious"
        
        return "Clean and Low Risk"
    
    def run(self, alert: dict) -> dict:
        ip = (alert.get("source_ip") or "").strip()
        
        if not ip:
            return {
                "module": "VirusTotal", 
                "target": ip, 
                "error": "No source IP"
                }
        
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": "Invalid IP address"
                    }
        
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "score": "N/A",
                    "verdict": "Private Range",
                    "cached": False
                    }
        
        if not self.api_key:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": "VirusTotal API key not set"
                    }
        
        hit = self._cache.get(ip)
        if hit and time.time() - hit[0] < self.MAX_CACHE_AGE:
            return {**hit[1], "cached": True}
        
        
        try:
            resp = self._session.get(
                self.API_URL.format(ip=ip),
                headers={"x-apikey":self.api_key, 
                         "Accept": "Application/json",},
                timeout=self.TIMEOUT
            )
            if resp.status_code == 429:
                return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": "rate limit exceeded"
                    }
            if resp.status_code != 200:
                return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": f"HTTP {resp.status_code}"
                    }
            
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected 
            
            ts = attrs.get("last_analysis_date")
            last = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None
            
            result = {
                "module": "VirusTotal", 
                "target": ip, 
                "score": f"{malicious}/{total} Vendors Flagged",
                "verdict": self._verdict(malicious, suspicious, total),
                "country": attrs.get("country"),
                "total_reports": malicious + suspicious,
                "last_reported": last,
                "cached": False
            }
            self._cache[ip] = (time.time(),result)
            return result
            
        
        except requests.Timeout:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": "Request time out"
                    }
        
        except requests.RequestException as e:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": f"Request failed {e}"
                    }
        
        except Exception as e:
            return {"module": "VirusTotal", 
                    "target": ip, 
                    "error": f"Unexpected error: {e}"
                    }
        

plugin_instance = VirusTotalPlugin()