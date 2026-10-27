/**
 * @name Project include edges
 * @description Exports resolved direct include edges for scope construction.
 * @kind table
 * @id trace2fuzz/project-include-edges
 */

import cpp

from Include include, File includingFile, File includedFile
where
  includingFile = include.getFile() and
  includedFile = include.getIncludedFile()
select
  includingFile.getAbsolutePath() as including_file,
  includedFile.getAbsolutePath() as included_file
