/**
 * @name Unsafe subprocess with shell=True or unsanitized input
 * @description Detects use of subprocess with shell=True or potential command injection vectors.
 *              Critical for sandbox and agent execution paths in multi-agent systems.
 * @kind problem
 * @problem.severity error
 * @id ventura-seg/unsafe-subprocess
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command execution depends on a $@.", source.getNode(),
  "user-controlled value"
