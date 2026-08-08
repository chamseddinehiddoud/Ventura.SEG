/**
 * @name Direct subprocess execution outside sandbox/permission controls
 * @description Finds subprocess/os.system/os.popen calls that may bypass
 *              the PermissionEngine and SandboxExecutor controls.
 * @kind problem
 * @problem.severity warning
 * @id ventura-seg/direct-subprocess-bypass
 * @tags security
 *       bypass
 *       external/cwe/cwe-078
 */

import python

from Call c
where
  (
    // subprocess.run / subprocess.call / subprocess.Popen
    c.getFunc().(Attribute).getObject().(Name).getId() = "subprocess" and
    c.getFunc().(Attribute).getName().regexpMatch("run|call|Popen|check_output|check_call")
  )
  or
  (
    // os.system / os.popen
    c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
    c.getFunc().(Attribute).getName().regexpMatch("system|popen")
  )
  // Exclude the official sandbox module itself (expected location)
  and not c.getEnclosingModule().getName().regexpMatch(".*sandbox.*")
select c, "Direct process execution may bypass PermissionEngine / SandboxExecutor controls."
