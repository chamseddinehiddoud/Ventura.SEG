/**
 * @name Sensitive action without audit logging
 * @description Flags methods that perform credential, sandbox or permission operations
 *              without an obvious audit log call in the same scope (heuristic).
 * @kind problem
 * @problem.severity warning
 * @id ventura-seg/missing-audit-log
 * @tags security
 *       maintainability
 */

import python

from Function f
where
  f.getName().regexpMatch("(?i).*(execute|run|register|load_kv|evaluate|scan|sanitize).*") and
  f.getEnclosingModule().getName().regexpMatch(".*(sandbox|credential_proxy|permissions|gateway|dlp).*") and
  not exists(Call c |
    c.getScope() = f and
    (
      c.getFunc().(Attribute).getName() = "log_event" or
      c.getFunc().(Name).getId().regexpMatch("(?i).*audit.*")
    )
  )
select f, "Sensitive function may be missing audit logging."
