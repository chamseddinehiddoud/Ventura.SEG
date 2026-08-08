/**
 * @name Potential hardcoded secret or credential
 * @description Finds string literals that look like API keys, tokens, or passwords.
 *              Complements secret scanning for patterns that may bypass standard detectors.
 * @kind problem
 * @problem.severity warning
 * @id ventura-seg/hardcoded-secret-pattern
 * @tags security
 *       external/cwe/cwe-798
 */

import python

from StringLiteral s
where
  // Common secret patterns (GitHub tokens, AWS, OpenAI-style, generic long secrets)
  s.getText().regexpMatch("(?i).*(ghp_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}).*")
  or
  (
    s.getText().length() >= 24 and
    s.getText().regexpMatch("(?i).*(api[_-]?key|secret|token|password|passwd|credential).*[:=].*[A-Za-z0-9+/=_-]{16,}.*")
  )
select s, "Potential hardcoded secret or credential pattern detected."
