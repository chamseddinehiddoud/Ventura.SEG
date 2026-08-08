/**
 * @name subprocess with shell=True
 * @description Detects any use of shell=True, which weakens isolation and
 *              enables classic command injection vectors.
 * @kind problem
 * @problem.severity error
 * @id ventura-seg/shell-true-bypass
 * @tags security
 *       bypass
 *       external/cwe/cwe-078
 */

import python

from Keyword k
where
  k.getArg() = "shell" and
  (
    k.getValue().(Name).getId() = "True" or
    k.getValue().(BooleanLiteral).booleanValue() = true
  )
select k, "Use of shell=True bypasses safer argv-based execution and enables injection."
