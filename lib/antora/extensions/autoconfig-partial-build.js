'use strict'

const execFile = require('node:util').promisify(require('node:child_process').execFile)
const fsp = require('node:fs/promises')
const ospath = require('node:path')

module.exports.register = function () {
  if (!process.env.BUILD_REFNAME) return

  this.once('playbookBuilt', async ({ playbook }) => {
    const { concat: get } = this.require('simple-get')
    const asciidocAttrs = ((playbook.asciidoc ||= {}).attributes ||= {})
    const siteManifestUrl = asciidocAttrs['primary-site-manifest-url'] || `${playbook.site.url}/site-manifest.json`
    const siteManifestData = await (siteManifestUrl.startsWith('https://')
      ? download(get, siteManifestUrl)
      : fsp.readFile(siteManifestUrl)
    ).then(JSON.parse)
    let { BUILD_REFNAME: refname, BUILD_VERSION: version } = process.env
    const isBranch = /[a-z]$/.test(refname)
    if (!version) {
      const repoUrl = await execFile('git', ['remote', 'get-url', 'origin']).then(({ stdout: output }) => output.trim())
      const propertiesUrl = `${repoUrl.replace('github.com', 'raw.githubusercontent.com')}/${refname}/gradle.properties`
      version = await download(get, propertiesUrl)
        .then((contents) => contents.toString().split('\n').find((it) => it.startsWith('version='))?.slice(8))
    }
    if (isBranch && version.endsWith('-SNAPSHOT')) version = version.slice(0, -9)
    const versionsInManifest = siteManifestData.components.ROOT.versions
    if (!(version in versionsInManifest && isBranch === !!versionsInManifest[version].prerelease)) {
      const category = require('path').basename(module.id, '.js')
      await fsp.writeFile(ospath.join(playbook.dir, '.full-build'), '')
      console.log(`version ${version} not previously built; reverting to full build`)
      return
    }
    Object.assign(
      playbook.content.sources[0],
      isBranch ? { branches: [refname], tags: [] } : { branches: [], tags: [refname] }
    )
    Object.assign(
      asciidocAttrs,
      { 'primary-site-url': '.', 'primary-site-manifest-url': siteManifestUrl }
    )
    this.updateVariables({ playbook })
  })
}

function download (get, url) {
  return new Promise((resolve, reject) =>
    get({ url }, (err, response, contents) => {
      if (err) reject(err)
      if (response.statusCode !== 200) {
        const message = `Response code ${response.statusCode} (${response.statusMessage})`
        return reject(Object.assign(new Error(message), { name: 'HTTPError' }))
      }
      resolve(contents)
    })
  )
}
