# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""OmniScan-AI scanner modules."""

from .ai_mutator import (
    discovered_param_slots,
    flatten_mutator_bundles,
    mutate_all_discovered_params,
    mutate_payload_waf,
)
from .api_doc_fuzzer import APISchemaFuzzer
from .broken_link_scanner import BrokenLinkScanner
from .cloud_scanner import CloudScanner
from .cve_lookup import extract_stack_components, lookup_cves_from_headers
from .evasion import EvasionProfile
from .exploit_gen import (
    auto_generate_exploits_after_scan,
    generate_pocs_from_report,
    load_report,
)
from .html_source_scanner import HtmlSourceScanner
from .idor_scanner import IDORScanner
from .nuclei_engine import run_nuclei_scan
from .param_probe import ParamProbeScanner
from .path_bruter import PathBruter
from .sensitive_file_hunter import SensitiveFileHunter
from .port_scanner import PortScanner
from .secret_finder import SecretFinder
from .smart_infiltration import SmartInfiltrationEngine
from .subdomain_scanner import SubdomainScanner
from .waf_evasion import WAFEvasionEngine
from .wayback_scanner import WaybackScanner
from .xss_scanner import XSSScanner
from .zero_day_hunter import ZeroDayHunter, compute_machine_hwid, zeroday_hwid_authorized

__all__ = [
    "AIAuditor",
    "discovered_param_slots",
    "flatten_mutator_bundles",
    "mutate_all_discovered_params",
    "mutate_payload_waf",
    "APISchemaFuzzer",
    "BrokenLinkScanner",
    "CloudScanner",
    "extract_stack_components",
    "EvasionProfile",
    "auto_generate_exploits_after_scan",
    "generate_pocs_from_report",
    "load_report",
    "lookup_cves_from_headers",
    "HtmlSourceScanner",
    "IDORScanner",
    "JSAnalyzer",
    "run_nuclei_scan",
    "PathBruter",
    "SensitiveFileHunter",
    "PortScanner",
    "SecretFinder",
    "SmartInfiltrationEngine",
    "SubdomainScanner",
    "WAFEvasionEngine",
    "WaybackScanner",
    "XSSScanner",
    "ZeroDayHunter",
    "compute_machine_hwid",
    "zeroday_hwid_authorized",
]
