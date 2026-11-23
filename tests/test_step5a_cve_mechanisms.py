"""Step 5A mechanism-triage regression tests. No dataset filename is consulted."""
import unittest

from contracts import AnalystOutput, ServiceFinding, VerifierOutput
from cve_mechanism_matcher import rank_cve_mechanisms
from mcp_evidence_contracts import OnlineEvidenceResult
from mcp_evidence_policy import derive_online_cve_validation

WHEN = "2026-10-14T00:00:00Z"
FLOW = '''
[E-S0000-F000007-003] Client sends EPMD query to 172.18.0.2:4369.
[E-S0000-F000011-004] EPMD response lists couchdb node at TCP port 9100.
[E-S0001-F000023-003] Erlang node name couchdb@127.0.0.1.
[E-S0001-F000029-007] Erlang rex RPC request calling os:cmd('id') from client to server.
[E-S0001-F000031-008] Server rex response containing uid=0(root) gid=0(root).
'''


def evidence(candidates=None, sources=None):
    return OnlineEvidenceResult(
        status="Valid", query="CouchDB Erlang RPC", retrieved_at_utc=WHEN,
        candidate_cves=candidates if candidates is not None else ["CVE-2022-24706", "CVE-2018-8007"],
        sources=sources if sources is not None else [
            dict(source_name="CISA KEV", title="Apache CouchDB Insecure Default Initialization",
                 url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                 snippet="Apache CouchDB contains insecure default initialization.",
                 supports=["CISA KEV identifies CVE-2022-24706 as exploited in the wild."],
                 retrieved_at_utc=WHEN),
            dict(source_name="NIST NVD", title="CVE-2018-8007",
                 url="https://nvd.nist.gov/vuln/detail/CVE-2018-8007",
                 snippet="Apache CouchDB admin config via HTTP API permits RCE.",
                 retrieved_at_utc=WHEN),
        ],
    )


def analyst(service="Apache CouchDB", proposal="Not Found"):
    a = AnalystOutput(service=ServiceFinding(primary=service))
    a.cve.candidate = proposal
    return a


class MechanismTriageTests(unittest.TestCase):
    def test_couchdb_epmd_rex_ranks_as_lead_not_confirmed(self):
        triage = rank_cve_mechanisms(FLOW, analyst(), evidence())
        self.assertEqual([x.cve_id for x in triage.candidates], ["CVE-2022-24706"])
        top = triage.candidates[0]
        self.assertEqual(top.level, "Mechanism-consistent")
        self.assertIn("E-S0001-F000029-007", top.packet_ids)
        self.assertIn("E-S0000-F000007-003", top.packet_ids)
        self.assertTrue(any("cookie" in item.lower() for item in top.missing_conditions))
        self.assertIn("NOT CONFIRMED", triage.to_text())
        self.assertNotIn("CVE-2018-8007 —", triage.to_text())

    def test_rce_without_rpc_mechanism_not_enough(self):
        text = '''[E-S0001-F000029-007] A generic remote code execution attempt.
[E-S0001-F000031-008] Server output uid=0(root).'''
        self.assertFalse(rank_cve_mechanisms(text, analyst(), evidence()).candidates)

    def test_only_epmd_and_node_no_rpc_not_enough(self):
        text = '''[E-S0000-F000007-003] EPMD names query.
[E-S0000-F000011-004] couchdb@127.0.0.1.'''
        self.assertFalse(rank_cve_mechanisms(text, analyst(), evidence()).candidates)

    def test_request_only_uid_without_epmd_not_enough(self):
        text = '''[E-S0001-F000029-007] Client Erlang rex os:cmd('id') request uid=0(root).'''
        self.assertFalse(rank_cve_mechanisms(text, analyst(), evidence()).candidates)

    def test_wrong_product_excludes_candidate(self):
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst("Grafana"), evidence()).candidates)

    def test_untrusted_blog_cannot_create_authoritative_cve_candidate(self):
        fake = evidence(["CVE-2022-24706"], [dict(
            title="CVE-2022-24706", source_name="Blog", url="https://not-authoritative.example/post",
            snippet="Apache CouchDB EPMD cookie RCE", retrieved_at_utc=WHEN,
        )])
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(), fake).candidates)

    def test_cve_identifier_inside_unrelated_nvd_body_does_not_transfer(self):
        fake = evidence(["CVE-2022-24706"], [dict(
            title="CVE-2017-12635", source_name="NIST NVD",
            url="https://nvd.nist.gov/vuln/detail/CVE-2017-12635",
            snippet="References CVE-2022-24706 in passing, not this record.", retrieved_at_utc=WHEN,
        )])
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(), fake).candidates)

    def test_no_online_candidates_no_ranked_inference(self):
        self.assertFalse(rank_cve_mechanisms(FLOW, analyst(), evidence([], [])).candidates)

    def test_general_vulnerability_path_traversal_matching(self):
        pcap = '''[E-S0001-F000029-007] HTTP GET /public/plugins/../../../../etc/passwd path traversal.
[E-S0001-F000031-008] HTTP server responds with file content.'''
        web = evidence(["CVE-2021-43798"], [dict(
            title="CVE-2021-43798 Grafana path traversal", source_name="NIST NVD",
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
            snippet="Grafana contains a directory traversal vulnerability in its plugin paths.",
            retrieved_at_utc=WHEN,
        )])
        ranked = rank_cve_mechanisms(pcap, analyst("Grafana"), web)
        self.assertEqual(ranked.candidates[0].cve_id, "CVE-2021-43798")
        self.assertEqual(ranked.candidates[0].level, "Preliminary mechanism overlap")

    def test_general_vulnerability_no_generic_rce_overlap(self):
        pcap = '''[E-S0001-F000029-007] Remote code execution.
[E-S0001-F000031-008] Server error.'''
        web = evidence(["CVE-2021-43798"], [dict(
            title="CVE-2021-43798", source_name="NIST NVD",
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
            snippet="Grafana remote code execution vulnerability.", retrieved_at_utc=WHEN,
        )])
        self.assertFalse(rank_cve_mechanisms(pcap, analyst("Grafana"), web).candidates)

    def test_step5a_cannot_confirm_profile_with_unknown_prerequisites(self):
        a = analyst(proposal="CVE-2022-24706")
        verifier = VerifierOutput(cve_supported="Yes")
        online = evidence()
        triage = rank_cve_mechanisms(FLOW, a, online)
        decision = derive_online_cve_validation(a, verifier, online, cve_triage=triage)
        self.assertEqual(decision.validated_cve, "Not Found")
        self.assertIn("unconfirmed", " ".join(decision.reasons))

    def test_generic_cve_without_mechanism_triage_is_not_validated(self):
        a = analyst(proposal="CVE-2022-24706")
        decision = derive_online_cve_validation(a, VerifierOutput(cve_supported="Yes"), evidence())
        self.assertEqual(decision.validated_cve, "Not Found")
        self.assertIn("mechanism match", " ".join(decision.reasons))

    def test_generic_cve_with_mechanism_triage_can_be_validated(self):
        pcap = '''[E-S0001-F000029-007] HTTP GET /public/plugins/../../../../etc/passwd path traversal.
[E-S0001-F000031-008] HTTP server responds with file content.'''
        web = evidence(["CVE-2021-43798"], [dict(
            title="CVE-2021-43798 Grafana path traversal", source_name="NIST NVD",
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
            snippet="Grafana contains a directory traversal vulnerability in its plugin paths.",
            retrieved_at_utc=WHEN,
        )])
        a = analyst(service="Grafana", proposal="CVE-2021-43798")
        verifier = VerifierOutput(cve_supported="Yes")
        triage = rank_cve_mechanisms(pcap, a, web)
        decision = derive_online_cve_validation(a, verifier, web, cve_triage=triage)
        self.assertEqual(decision.validated_cve, "CVE-2021-43798")


if __name__ == "__main__":
    unittest.main()

class PipelineIntegrationTests(unittest.TestCase):
    def test_mechanism_lead_reaches_revision_and_report_without_overwriting_cve(self):
        import sys
        import types
        from unittest.mock import MagicMock, patch
        sys.modules.setdefault("llm_client", types.SimpleNamespace(get_llm=MagicMock()))
        from mafra_agent_mcp import MAFRAMCPAgent
        from contracts import CVEValidationOutput, ConsensusDecision
        patches = [patch("mafra_agent_mcp." + n) for n in (
            "AnalystAgent", "VerifierAgent", "ConsensusManager", "MCPOnlineEvidenceSearch",
            "EvidenceFormatter", "MCPReporterAgent", "MemoryManager",
        )]
        for p in patches:
            p.start()
        try:
            app = MAFRAMCPAgent(memory_mode="disabled")
            app.memory_manager.mode = "disabled"
            app.memory_manager.last_retrievals = []
            app.memory_manager.status.return_value = "disabled"
            a = analyst()
            app.analyst.analyze.return_value = a
            app.analyst.reconsider_with_online_evidence.return_value = a
            app.online_search.search.return_value = evidence()
            app.verifier.verify.return_value = VerifierOutput(cve_supported="Not Applicable")
            consensus = ConsensusDecision(service="Apache CouchDB", attack="RCE")
            app.consensus.calculate.return_value = consensus
            app.consensus.format.return_value = consensus.to_text()
            app.evidence_formatter.format.return_value = type("E", (), {"to_prompt_text": lambda self: "evidence"})()
            app.reporter.generate.return_value = type("R", (), {
                "status": "Valid", "validation_errors": [], "to_text": lambda self: "report"
            })()
            text = app.run(FLOW)
            hints = app.analyst.reconsider_with_online_evidence.call_args.kwargs["cve_mechanism_hints"]
            self.assertIn("CVE-2022-24706", hints)
            self.assertIn("does NOT require an HTTP API", hints)
            self.assertIn("CANDIDATE ONLY", text)
            self.assertEqual(app.last_cve_triage.candidates[0].cve_id, "CVE-2022-24706")
            self.assertEqual(consensus.cve, "Not Found")
            self.assertIn("cve_mechanism_hints", app.reporter.generate.call_args.kwargs)
        finally:
            for p in reversed(patches):
                p.stop()
