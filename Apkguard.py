from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
import os
import re
import base64
import zipfile
import logging
from pathlib import Path
from androguard.misc import AnalyzeAPK
from rich.console import Console
from rich.table import Table

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

@dataclass
class AnalysisResult:
    """Container for analysis results."""
    suspicious_ips: Set[str] = field(default_factory=set)
    suspicious_urls: Set[str] = field(default_factory=set)
    suspicious_payloads: List[str] = field(default_factory=list)
    suspicious_permissions: Set[str] = field(default_factory=set)
    suspicious_keywords: Dict[str, List[Path]] = field(default_factory=dict)
    suspicious_files: Set[Path] = field(default_factory=set)
    risk_factors: Dict[str, int] = field(default_factory=dict)

class APKMalwareAnalyzer:
    """APK Malware Analysis Tool with enhanced detection capabilities."""

    SUSPICIOUS_PERMISSIONS = {
        "android.permission.INTERNET": 1,
        "android.permission.ACCESS_NETWORK_STATE": 1,
        "android.permission.READ_SMS": 3,
        "android.permission.SEND_SMS": 3,
        "android.permission.READ_CONTACTS": 2,
        "android.permission.RECORD_AUDIO": 2,
        "android.permission.CAMERA": 2,
        "android.permission.READ_EXTERNAL_STORAGE": 1,
        "android.permission.WRITE_EXTERNAL_STORAGE": 1,
    }

    MALWARE_PATTERNS = {
        "malware_keywords": {
            "patterns": [
                r"rat\b", r"keylogger", r"backdoor", r"malware", r"payload",
                r"command.?and.?control", r"trojan", r"spyware", r"remote.?access",
                r"meterpreter"
            ],
            "risk_score": 5
        },
        "network_operations": {
            "patterns": [
                r"java/net/Socket", r"java/net/URLConnection",
                r"android/webkit/WebView", r"loadUrl"
            ],
            "risk_score": 2
        },
        "dynamic_code": {
            "patterns": [
                r"dalvik/system/DexClassLoader", r"java/lang/Runtime",
                r"loadClass", r"exec\b"
            ],
            "risk_score": 4
        },
        "crypto_ops": {
            "patterns": [
                r"javax/crypto/Cipher", r"java/security/MessageDigest",
                r"android/util/Base64"
            ],
            "risk_score": 1
        }
    }

    def __init__(self, apk_path: str):
        """Initialize the analyzer with APK path and setup analysis environment."""
        self.apk_path = Path(apk_path)
        self.output_dir = Path(str(self.apk_path.stem) + "_analysis")
        self.result = AnalysisResult()

    def display_header(self) -> None:
        """Display the tool header."""
        console.print("[bold green]========================================")
        console.print("[bold cyan]      APKGuard Malware Analyzer v1.0")
        console.print("[bold yellow]          Powered by ByteBreaker")
        console.print("[bold green]========================================")

    def extract_apk(self) -> bool:
        """Extract APK contents with enhanced error handling."""
        logger.info("Extracting APK contents...")
        try:
            self.output_dir.mkdir(exist_ok=True)
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                apk.extractall(self.output_dir)

            # Add analysis metadata
            (self.output_dir / "analysis_info.txt").write_text(
                "APK Malware Analyzer v2.0\nAnalysis Date: {}\n".format(
                    Path(self.apk_path).stat().st_mtime
                )
            )
            return True
        except zipfile.BadZipFile:
            logger.error("Invalid or corrupted APK file")
            return False
        except Exception as e:
            logger.error(f"Failed to extract APK: {e}")
            return False

    def analyze_manifest(self, apk) -> None:
        """Analyze AndroidManifest.xml for suspicious permissions and keywords."""
        logger.info("Analyzing manifest...")
        try:
            # Fetch and decode the AndroidManifest.xml file
            manifest_xml = apk.get_android_manifest_axml().get_xml()
            (self.output_dir / "AndroidManifest_decoded.xml").write_bytes(manifest_xml)

            # Check for suspicious keywords in the manifest (such as 'trojan')
            manifest_str = manifest_xml.decode('utf-8', errors='ignore').lower()

            # List of suspicious keywords to search in the manifest
            suspicious_keywords_in_manifest = ["trojan", "rat", "keylogger", "backdoor", "meterpreter"]

            for keyword in suspicious_keywords_in_manifest:
                if keyword in manifest_str:
                    self.result.suspicious_keywords[keyword] = [self.output_dir / "AndroidManifest_decoded.xml"]
                    logger.info(f"Found suspicious keyword '{keyword}' in AndroidManifest.xml")

            # Permissions analysis (already implemented)
            permissions = set(apk.get_permissions())
            risk_score = 0

            for perm in permissions:
                if perm in self.SUSPICIOUS_PERMISSIONS:
                    self.result.suspicious_permissions.add(perm)
                    risk_score += self.SUSPICIOUS_PERMISSIONS[perm]

            self.result.risk_factors["permissions"] = risk_score

        except Exception as e:
            logger.error(f"Failed to analyze manifest: {e}")

    def scan_patterns(self, dex_data: bytes) -> None:
        """Scan for suspicious patterns in DEX data and APK resources."""
        for category, config in self.MALWARE_PATTERNS.items():
            matches = set()
            for pattern in config["patterns"]:
                found = re.finditer(pattern.encode(), dex_data, re.IGNORECASE)
                matches.update(m.group(0).decode() for m in found)

            # Specifically add checks for suspicious keywords like "trojan"
            for keyword in ["trojan", "meterpreter", "rat", "keylogger"]:
                if keyword.lower() in dex_data.decode('utf-8', errors='ignore').lower():
                    self.result.suspicious_keywords[keyword] = [self.output_dir / "classes.dex"]
                    matches.add(keyword)

            if matches:
                # Store the found keywords with the file location
                for match in matches:
                    if match not in self.result.suspicious_keywords:
                        self.result.suspicious_keywords[match] = []
                    self.result.suspicious_keywords[match].append(self.output_dir / "classes.dex")

                # Update risk score for category
                self.result.risk_factors[category] = len(matches) * config["risk_score"]
                logger.info(f"Found {category}: {matches}")
                self.result.suspicious_files.add(self.output_dir / "classes.dex")

    def detect_encoded_strings(self, dex_data: bytes) -> None:
        """Detect and analyze potential encoded strings."""
        # Improved Base64 detection pattern
        b64_pattern = rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        potential_payloads = re.finditer(b64_pattern, dex_data)

        for match in potential_payloads:
            payload = match.group(0)
            if len(payload) >= 40:  # Minimum length to reduce false positives
                try:
                    decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                    # Check if decoded content looks suspicious
                    if any(keyword in decoded.lower() for keyword in ['http', 'exec', 'shell', 'cmd']):
                        self.result.suspicious_payloads.append(decoded)
                except Exception:
                    continue

    def calculate_risk_score(self) -> int:
        """Calculate overall risk score based on all factors."""
        return sum(self.result.risk_factors.values())

    def generate_risk_interpretation(self) -> str:
        """Provide an interpretation of the risk score."""
        total_risk = self.calculate_risk_score()

        if total_risk <= 5:
            return f"[green]Low Risk[/green] (Risk Score: {total_risk})"
        elif total_risk <= 15:
            return f"[yellow]Medium Risk[/yellow] (Risk Score: {total_risk})"
        else:
            return f"[red]High Risk[/red] (Risk Score: {total_risk})"

    def generate_report(self) -> None:
        """Generate comprehensive analysis report."""
        report_path = self.output_dir / "threat_report.md"
        risk_score = self.calculate_risk_score()

        report_content = [
            "# APK Malware Analysis Report",
            f"\nRisk Score: {risk_score} ({self.generate_risk_interpretation()})",
            "\n## Risk Factors Breakdown",
        ]

        for factor, score in self.result.risk_factors.items():
            report_content.append(f"- {factor}: {score}")

        if self.result.suspicious_permissions:
            report_content.extend([
                "\n## Suspicious Permissions",
                *[f"- {perm}" for perm in sorted(self.result.suspicious_permissions)]
            ])

        if self.result.suspicious_payloads:
            report_content.extend([
                "\n## Suspicious Encoded Content",
                *[f"- {payload[:100]}..." for payload in self.result.suspicious_payloads]
            ])

        if self.result.suspicious_keywords:
            report_content.extend([
                "\n## Suspicious Keywords Found",
                *[f"- {keyword} (Found in {', '.join(map(str, locations))})" for keyword, locations in self.result.suspicious_keywords.items()]
            ])

        report_path.write_text("\n".join(report_content))
        logger.info(f"Report generated: {report_path}")

    def run(self) -> Optional[AnalysisResult]:
        """Execute the complete analysis workflow."""
        self.display_header()

        if not self.apk_path.exists():
            logger.error(f"APK file not found: {self.apk_path}")
            return None

        if not self.extract_apk():
            return None

        try:
            apk, d, dx = AnalyzeAPK(str(self.apk_path))
            self.analyze_manifest(apk)

            dex_path = self.output_dir / "classes.dex"
            if dex_path.exists():
                dex_data = dex_path.read_bytes()
                self.scan_patterns(dex_data)
                self.detect_encoded_strings(dex_data)

            # Display all suspicious findings in well-formatted tables
            console.print("\n[bold yellow]Summary of Suspicious Findings:[/bold yellow]")

            # Display suspicious permissions in table
            if self.result.suspicious_permissions:
                table = Table(title="Suspicious Permissions")
                table.add_column("Permission", style="cyan")
                table.add_column("Risk Score", style="yellow")
                for perm in sorted(self.result.suspicious_permissions):
                    risk_score = self.SUSPICIOUS_PERMISSIONS.get(perm, 0)
                    table.add_row(perm, str(risk_score))
                console.print(table)

            # Display suspicious payloads in table
            if self.result.suspicious_payloads:
                table = Table(title="Suspicious Encoded Payloads")
                table.add_column("Payload", style="cyan")
                for payload in self.result.suspicious_payloads:
                    table.add_row(payload[:100] + "...")
                console.print(table)

            # Display suspicious keywords found in table
            if self.result.suspicious_keywords:
                table = Table(title="Suspicious Keywords Found")
                table.add_column("Keyword", style="cyan")
                table.add_column("Location", style="yellow")
                for keyword, locations in self.result.suspicious_keywords.items():
                    for location in locations:
                        table.add_row(keyword, str(location))
                console.print(table)

            # Display risk factors in table
            if self.result.risk_factors:
                table = Table(title="Risk Factors")
                table.add_column("Category", style="cyan")
                table.add_column("Risk Score", style="yellow")
                for category, score in self.result.risk_factors.items():
                    table.add_row(category, str(score))
                console.print(table)

            # Display overall risk interpretation
            console.print(f"\n[bold yellow]Overall Risk Status: {self.generate_risk_interpretation()}[/bold yellow]")

            self.generate_report()
            return self.result

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return None


def main():
    """Main entry point with command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced APK Malware Analyzer")
    parser.add_argument("apk", help="Path to the APK file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    analyzer = APKMalwareAnalyzer(args.apk)
    result = analyzer.run()

    if result:
        console.print(f"[green]Analysis completed successfully!")
        console.print(f"Overall Risk Score: {analyzer.calculate_risk_score()}")

if __name__ == "__main__":
    main()
