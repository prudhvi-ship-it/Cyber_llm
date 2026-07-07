import nvdlib
import re
from llm_client import get_llm


class WebSearch:
    def __init__(self):
        self.llm = get_llm()

    def search_nvd(self, keyword, max_results=10):
        """Search NVD database directly for CVEs."""
        try:
            print(f"Searching NVD for: {keyword}")
            keyword = keyword.replace('"', "").replace("'", "")

            all_results = []

            try:
                results = nvdlib.searchCVE(
                    keywordSearch=keyword,
                    pubStartDate="2010-01-01 00:00",
                    pubEndDate="2026-12-31 00:00",
                    limit=max_results
                )
                if results:
                    all_results.extend(results)
                    print(f"Date-filtered search found: {len(results)}")
            except Exception:
                pass

            if not all_results:
                try:
                    results = nvdlib.searchCVE(
                        keywordSearch=keyword,
                        limit=max_results
                    )
                    if results:
                        all_results.extend(results)
                except Exception:
                    pass

            version_match = re.search(r"\d+\.\d+[\.\d]*", keyword)
            if version_match and not all_results:
                version = version_match.group()
                short_keyword = keyword.split()[0]

                try:
                    results = nvdlib.searchCVE(
                        keywordSearch=f"{short_keyword} {version}",
                        pubStartDate="2010-01-01 00:00",
                        pubEndDate="2026-12-31 00:00",
                        limit=max_results
                    )
                    if results:
                        all_results.extend(results)
                        print(f"Version-specific search found: {len(results)}")
                except Exception:
                    pass

            if all_results:
                seen = set()
                unique = []

                for result in all_results:
                    if result.id not in seen:
                        seen.add(result.id)
                        unique.append(result)

                unique.sort(
                    key=lambda x: x.published if hasattr(x, "published") else "",
                    reverse=True
                )
                return unique

            return []

        except Exception as e:
            print(f"NVD search error: {e}")
            return []

    def get_cve_details(self, cve_id):
        """Get full details of a specific CVE."""
        try:
            results = nvdlib.searchCVE(cveId=cve_id)
            if results:
                return results[0]
            return None
        except Exception as e:
            print(f"Error fetching CVE details: {e}")
            return None

    def format_cve(self, cve):
        """Format a CVE result into readable text."""
        try:
            cve_id = cve.id

            description = "No description available"
            if hasattr(cve, "descriptions"):
                for desc in cve.descriptions:
                    if desc.lang == "en":
                        description = desc.value
                        break

            severity = "Unknown"
            score = "Unknown"

            try:
                if hasattr(cve, "metrics"):
                    metrics = cve.metrics

                    if hasattr(metrics, "cvssMetricV31"):
                        cvss = metrics.cvssMetricV31[0]
                        score = cvss.cvssData.baseScore
                        severity = cvss.cvssData.baseSeverity

                    elif hasattr(metrics, "cvssMetricV30"):
                        cvss = metrics.cvssMetricV30[0]
                        score = cvss.cvssData.baseScore
                        severity = cvss.cvssData.baseSeverity

                    elif hasattr(metrics, "cvssMetricV2"):
                        cvss = metrics.cvssMetricV2[0]
                        score = cvss.cvssData.baseScore
                        severity = cvss.baseSeverity
            except Exception:
                pass

            published = "Unknown"
            if hasattr(cve, "published"):
                published = cve.published[:10]

            return (
                f"\nCVE ID: {cve_id}\n"
                f"Description: {description}\n"
                f"CVSS Score: {score}\n"
                f"Severity: {severity}\n"
                f"Published: {published}\n"
            )

        except Exception as e:
            return f"Error formatting CVE: {e}"

    def normalise_service_name(self, service):
        """Fix common capitalisation issues for NVD search."""
        mappings = {
            "phpmyadmin": "phpMyAdmin",
            "couchdb": "CouchDB",
            "mysql": "MySQL",
            "apache": "Apache",
            "openssh": "OpenSSH",
            "nginx": "nginx",
            "wordpress": "WordPress",
        }

        lower = service.lower()

        for key, value in mappings.items():
            if key in lower:
                return value

        return service

    def summarise_with_llm(self, query, cve_list):
        """Use LLM to identify most relevant CVE from list."""
        try:
            cve_text = "\n".join(cve_list)

            prompt = (
                f"You are a forensic analyst identifying CVEs.\n\n"
                f"The forensic analysis found this service and attack:\n"
                f"{query}\n\n"
                f"Here are the CVEs found in the NVD database:\n"
                f"{cve_text}\n\n"
                f"Rules:\n"
                f"1. Match on service name first, then specific exploit evidence.\n"
                f"2. Prefer CVEs that mention the same service and exploit behavior.\n"
                f"3. Only select from the list above.\n"
                f"4. Do not choose a CVE just because it is recent.\n"
                f"5. If none match, say: Most Likely CVE: CVE-NOT-FOUND\n\n"
                f"6. Strongly prefer CVEs whose description mentions preg_replace, /e modifier, find-and-replace, replace operation, or PHP code execution when the evidence includes command execution.\n"
                f"Respond in this format:\n"
                f"Most Likely CVE: CVE-XXXX-XXXXX\n"
                f"Reason: [explanation]\n"
                f"Confidence: [High/Medium/Low]\n"
            )

            response = self.llm.invoke(prompt)
            return response.content

        except Exception as e:
            return f"Error in LLM summarisation: {e}"

    def run(self, query):
        """Main function - search NVD and identify most relevant CVE."""
        print(f"\nSearching NVD for: {query}")

        stop_words = [
            "vulnerability",
            "attack",
            "version",
            "not",
            "specified",
            "unknown",
            "traffic",
            "analysis",
            "service",
            "application",
        ]

        words = query.split()

        clean_words = [
            word for word in words
            if word.lower() not in [s.lower() for s in stop_words]
            and len(word) > 2
        ]

        if clean_words:
            clean_words[0] = self.normalise_service_name(clean_words[0])

        has_version = any(
            re.search(r"\d+\.\d+", word)
            for word in clean_words
        )

        has_specific = any(
            word.lower() in [
                "preg_replace",
                "rce",
                "command",
                "execution",
                "system",
                "exec",
                "shell",
                "shell_exec",
                "passthru",
                "traversal",
                "injection",
                "upload",
                "deserialization",
                "replace",
            ]
            for word in clean_words
        )

        if has_version or has_specific:
            clean_query = " ".join(clean_words[:4])
        else:
            clean_query = clean_words[0] if clean_words else query

        print(f"Cleaned query: {clean_query}")

        #all_cves = self.search_nvd(clean_query, max_results=20)
        #print(f"Found {len(all_cves)} CVEs")
        search_queries = [clean_query]

        service_name = clean_words[0] if clean_words else query

        extra_terms = [
             "RCE",
             "remote code execution",
            "command execution",
            "preg_replace",
            "authentication bypass"
]

        for term in extra_terms:
          search_queries.append(f"{service_name} {term}")

        # Remove duplicate queries
        search_queries = list(dict.fromkeys(search_queries))

        all_cves = []

        for search_query in search_queries:
          results = self.search_nvd(search_query, max_results=20)
          all_cves.extend(results)

         # Deduplicate CVEs
        seen = set()
        unique_cves = []

        for cve in all_cves:
          if cve.id not in seen:
            seen.add(cve.id)
            unique_cves.append(cve)

        all_cves = unique_cves

        print(f"Found {len(all_cves)} CVEs across multiple searches")

        if not all_cves:
            print("No CVEs found in NVD")
            return "No CVEs found in NVD database for this query"

        all_cves.sort(key=lambda x: x.id, reverse=True)
        print(f"Using {len(all_cves)} CVEs for analysis")

        formatted_cves = []

        for cve in all_cves[:10]:
            formatted = self.format_cve(cve)
            formatted_cves.append(formatted)
            print(f"Found: {cve.id}")

        llm_analysis = self.summarise_with_llm(query, formatted_cves)

        return (
            f"\n=== NVD CVE Search Results ===\n"
            f"Query: {query}\n"
            f"Cleaned Query: {clean_query}\n"
            f"Total CVEs Found: {len(all_cves)}\n\n"
            f"=== CVE Details ===\n"
            f"{''.join(formatted_cves[:5])}\n\n"
            f"=== LLM Analysis ===\n"
            f"{llm_analysis}\n"
        )
