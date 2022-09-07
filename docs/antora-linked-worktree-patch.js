'use strict'

/* Copyright (c) 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const { promises: fsp } = require('fs')
const ospath = require('path')

/**
 * Rewrites local content sources to support the use of linked worktrees.
 *
 * @author Dan Allen <dan@opendevise.com>
 */
module.exports.register = function () {
  this.once('playbookBuilt', async ({ playbook }) => {
    const expandPath = this.require('@antora/expand-path-helper')
    for (const contentSource of playbook.content.sources) {
      const { url, branches } = contentSource
      if (url.charAt() !== '.') continue
      const absdir = expandPath(url, { dot: playbook.dir })
      const gitfile = ospath.join(absdir, '.git')
      if (await fsp.stat(gitfile).then((stat) => !stat.isDirectory(), () => false)) {
        const worktreeGitdir = await fsp.readFile(gitfile, 'utf8')
          .then((contents) => contents.trimRight().substr(8))
        const worktreeBranch = await fsp.readFile(ospath.join(worktreeGitdir, 'HEAD'), 'utf8')
          .then((contents) => contents.trimRight().replace(/^ref: (?:refs\/heads\/)?/, ''))
        const reldir = ospath.relative(
          playbook.dir,
          await fsp.readFile(ospath.join(worktreeGitdir, 'commondir'), 'utf8')
            .then((contents) => {
              const gitdir = ospath.join(worktreeGitdir, contents.trimRight())
              return ospath.basename(gitdir) === '.git' ? ospath.dirname(gitdir) : gitdir
            })
        )
        contentSource.url = reldir ? `.${ospath.sep}${reldir}` : '.'
        if (!branches) continue
        contentSource.branches = (branches.constructor === Array ? branches : [branches])
          .map((pattern) => pattern.replaceAll('HEAD', worktreeBranch))
      }
    }
  })
}
