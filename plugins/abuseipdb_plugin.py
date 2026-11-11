# plugins/abuseipdb_plugin.py
import ipaddress
import os
import time
import requests

class AbuseIPDBPlugin:
    API_URL = "https://api.abuseipdb.com/api/v2/check"
    MAX_AGE_DAYS = 90
    MAX_CACHE_AGE = 3600 #for the free limit
    TIMEOUT = 10
    
    def __init__(self):
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY", " ")
        self._cache = {}   
        self._session = requests.Session()
    
    @staticmethod
    def _verdict(score: int) -> str:
        if score == 100:
            return "Confirmed Malicious"
        elif score >= 40:
            return "Suspicious"
        
        return "Clean and Low Risk"
    
    def run(self, alert: dict) -> dict:
        ip = (alert.get("source_ip")).strip()
        
        if not ip:
            return {
                "module": "AbuseIPDB", 
                "target": ip, 
                "error": "No source IP"
                }
        
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": "Invalid IP address"
                    }
        
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "score": "N/A",
                    "verdict": "Private Range",
                    "cached": False
                    }
        
        if not self.api_key:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": "AbuseIPDB API key not set"
                    }
        
        hit = self._cache.get(ip)
        if hit and time.time() - hit[0] < self.MAX_CACHE_AGE:
            return {**hit[1], "cached": True}
        
        
        try:
            resp = self._session.get(
                self.API_URL,
                headers={"KEY":self.api_key, 
                         "Accept": "Application/json",},
                params= {"ipAddress": ip,
                         "MaxAgeInDays":self.MAX_AGE_DAYS},
                timeout=self.TIMEOUT
            )
            if resp.status_code == 429:
                return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": "rate limit exceeded"
                    }
            if resp.status_code != 200:
                return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": f"HTTP {resp.status_code}"
                    }
            
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            
            result = {
                "module": "AbuseIPDB", 
                "target": ip, 
                "score": f"{score}% Confidence",
                "verdict": self._verdict(score),
                "country": data.get("countryCode"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "cached": False
            }
            self._cache[ip] = (time.time(),result)
            return result
            
        
        except requests.Timeout:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": "Request time out"
                    }
        
        except requests.RequestException as e:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": f"Request failed {e}"
                    }
        
        except Exception as e:
            return {"module": "AbuseIPDB", 
                    "target": ip, 
                    "error": f"Unexpected error: {e}"
                    }
        

plugin_instance = AbuseIPDBPlugin()
        
        
    