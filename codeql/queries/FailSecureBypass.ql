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

from AstNode node
where
  exists(Assign a, StringLiteral s |
    a.getValue() = s and
    s.getText().regexpMatch("(?i)^allow$") and
    (
      a.getATarget().(Name).getId().regexpMatch("(?i).*default.*action.*") or
      a.getATarget().(Attribute).getName().regexpMatch("(?i).*default.*action.*")
    ) and
    node = a
  )
  or
  exists(Keyword k, StringLiteral s |
    k.getArg() = "default_action" and
    k.getValue() = s and
    s.getText().regexpMatch("(?i)^allow$") and
    node = k
  )
select node, "Potential fail-secure bypass: default_action set to 'allow'."
