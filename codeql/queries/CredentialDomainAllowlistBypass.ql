/**
 * @name Credential registration without domain allowlist
 * @description Detects CredentialProxy.register calls that omit allowed_domains,
 *              potentially allowing unrestricted outbound use of secrets.
 * @kind problem
 * @problem.severity warning
 * @id ventura-seg/credential-domain-allowlist-bypass
 * @tags security
 *       bypass
 *       external/cwe/cwe-862
 */

import python

from Call c
where
  c.getFunc().(Attribute).getName() = "register" and
  // Heuristic: method named register in credential/proxy context
  (
    c.getFunc().(Attribute).getObject().(Name).getId().regexpMatch("(?i).*proxy.*|.*credential.*") or
    c.getEnclosingModule().getName().regexpMatch(".*credential.*")
  ) and
  // No allowed_domains keyword argument present
  not exists(Keyword k | k = c.getANamedArg() and k.getArg() = "allowed_domains")
select c, "Credential registration without allowed_domains may bypass domain restrictions."
