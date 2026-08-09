/**
 * @name Sandbox isolation bypass
 * @description Detects use of IsolationLevel.NONE or disabling of critical
 *              sandbox protections (network + read-only root).
 * @kind problem
 * @problem.severity error
 * @id ventura-seg/sandbox-isolation-bypass
 * @tags security
 *       bypass
 *       external/cwe/cwe-250
 */

import python

from AstNode node
where
  exists(Attribute a |
    a.getName() = "NONE" and
    a.getObject().(Name).getId().regexpMatch("(?i).*isolation.*level.*|IsolationLevel") and
    node = a
  )
  or
  exists(Keyword k |
    (
      (k.getArg() = "network_disabled" and k.getValue().(Name).getId() = "False") or
      (k.getArg() = "read_only_root" and k.getValue().(Name).getId() = "False")
    ) and
    node = k
  )
select node, "Potential sandbox isolation bypass detected."
