/**
 * @name Insecure YAML loading
 * @description Detects use of yaml.load() without SafeLoader, which can lead to arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id ventura-seg/insecure-yaml-load
 * @tags security
 *       external/cwe/cwe-502
 */

import python

from Call c, Attribute attr
where
  c.getFunc() = attr and
  attr.getName() = "load" and
  attr.getObject().(Name).getId() = "yaml" and
  // Exclude cases that explicitly pass Loader=SafeLoader or use safe_load
  not exists(Keyword k |
    k = c.getANamedArg() and
    k.getArg() = "Loader"
  )
select c, "Use of yaml.load() without explicit SafeLoader. Prefer yaml.safe_load()."
