"""Aegis-style enforcement layer for autonomous DFIR findings.

Three layers that ENFORCE the forensic-discipline rules the base platform only
states as prompts:
  - staging:    rule-based confidence ceiling (unfakeable, no LLM)
  - quarantine: structural adversarial-evidence handling
  - grader:     independent evidence-only verifier (separate context)
"""
