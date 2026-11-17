# plugins/alienvault_plugin.py
import ipaddress
import os
import time
import requests

class AlienVaultPlugin:
    API_URL = "https://otx.alienvault.com/api/v1/indicators/{ip_type}/{ip}/general"
    MALICIOUS_PULSES = 50
    SUSPICIOUS_PULSES = 25
    MAX_CACHE_AGE = 3600
    TIMEOUT = 10

    def __init__(self):
        self.api_key = os.environ.get("OTX_API_KEY", "").strip()
        self._cache = {}
        self._session = requests.Session()

    @classmethod
    def _verdict(cls, pulses: int) -> str:
        if pulses >= cls.MALICIOUS_PULSES:
            return "Confirmed Malicious"
        elif pulses >= cls.SUSPICIOUS_PULSES:
            return "Suspicious"

        return "Clean and Low Risk"

    def run(self, alert: dict) -> dict:
        ip = (alert.get("source_ip") or "").strip()

        if not ip:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": "No source IP"
                    }

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": "Invalid IP address"
                    }

        if not addr.is_global:
            return {"module": "AlienVault",
                    "target": ip,
                    "score": "N/A",
                    "verdict": "Private Range",
                    "cached": False
                    }

        if not self.api_key:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": "OTX API key not set"
                    }

        hit = self._cache.get(ip)
        if hit and time.time() - hit[0] < self.MAX_CACHE_AGE:
            return {**hit[1], "cached": True}

        ip_type = "IPv6" if addr.version == 6 else "IPv4"

        try:
            resp = self._session.get(
                self.API_URL.format(ip_type=ip_type, ip=ip),
                headers={"X-OTX-API-KEY": self.api_key,
                         "Accept": "application/json"},
                timeout=self.TIMEOUT
            )
            if resp.status_code == 429:
                return {"module": "AlienVault",
                        "target": ip,
                        "error": "rate limit exceeded"
                        }

            if resp.status_code == 404:
                result = {
                    "module": "AlienVault",
                    "target": ip,
                    "score": f"0/{self.MALICIOUS_PULSES} Pulses",
                    "verdict": "Clean and Low Risk",
                    "total_pulses": 0,
                    "cached": False
                }
                self._cache[ip] = (time.time(), result)
                return result

            if resp.status_code != 200:
                return {"module": "AlienVault",
                        "target": ip,
                        "error": f"HTTP {resp.status_code}"
                        }

            data = resp.json()
            pulse_info = data.get("pulse_info") or {}
            pulses = int(pulse_info.get("count", 0))

            result = {
                "module": "AlienVault",
                "target": ip,
                "score": f"{pulses}/{self.MALICIOUS_PULSES} Pulses",
                "verdict": self._verdict(pulses),
                "country": data.get("country_code"),
                "total_pulses": pulses,
                "reputation": data.get("reputation", 0),
                "cached": False
            }
            self._cache[ip] = (time.time(), result)
            return result

        except requests.Timeout:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": "Request time out"
                    }

        except requests.RequestException as e:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": f"Request failed {e}"
                    }

        except Exception as e:
            return {"module": "AlienVault",
                    "target": ip,
                    "error": f"Unexpected error: {e}"
                    }


plugin_instance = AlienVaultPlugin()