/**
 * @name Fail-secure default action bypass
 * @description Detects code that sets default_action to "allow" or overrides
 *              the fail-secure posture of the PermissionEngine.
 * @kind problem
 * @problem.severity error
 * @id ventura-seg/fail-secure-bypass
 * @tags security
 *       bypass
 *       external/cwe/cwe-276
 */

import python

from DataFlow::Node n
where
  // String literal "allow" assigned in contexts related to default_action
  exists(StringLiteral s |
    s = n.asExpr() and
    s.getText().regexpMatch("(?i)^allow$") and
    exists(Assign a |
      a.getAValue() = s and
      (
        a.getATarget().(Name).getId().regexpMatch("(?i).*default.*action.*") or
        a.getATarget().(Attribute).getName().regexpMatch("(?i).*default.*action.*")
      )
    )
  )
  or
  // Keyword argument default_action="allow"
  exists(Keyword k |
    k = n.asExpr().getParent() and
    k.getArg() = "default_action" and
    k.getValue().(StringLiteral).getText().regexpMatch("(?i)^allow$")
  )
select n, "Potential fail-secure bypass: default_action set to 'allow'."
