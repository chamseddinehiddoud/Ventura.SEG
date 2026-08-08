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

from DataFlow::Node n
where
  // IsolationLevel.NONE
  exists(Attribute a |
    a = n.asExpr() and
    a.getName() = "NONE" and
    a.getObject().(Name).getId().regexpMatch("(?i).*isolation.*level.*|IsolationLevel")
  )
  or
  // network_disabled=False or read_only_root=False in constructor-like calls
  exists(Keyword k |
    k = n.asExpr().getParent() and
    (
      (k.getArg() = "network_disabled" and k.getValue().(Name).getId() = "False") or
      (k.getArg() = "read_only_root" and k.getValue().(Name).getId() = "False")
    )
  )
select n, "Potential sandbox isolation bypass detected."
