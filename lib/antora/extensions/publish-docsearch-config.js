'use strict'

const fsp = require('node:fs/promises')
const ospath = require('node:path')

/**
 * An Antora extension that generates a config file that controls the behavior of the docsearch scraper.
 *
 * This extension generates a docsearch config file by evaluating a Handlebars template (e.g.,
 * .github/actions/docsearch-config.json.hbs). It then publishes the output file to the root of the site
 * (docsearch-config.json). The docsearch scraper will retrieve for the config file from the published site.
 *
 * This extension will only add entries for the latest version in each release line. Additionally, if the page-archived
 * or page-noindex attribute is defined in the document header of the page, that page will be excluded from the index.
 */
module.exports.register = function ({ config: { templatePath = './docsearch/config.json.hbs' } }) {
  const expandPath = this.require('@antora/expand-path-helper')
  const handlebars = this.require('handlebars').create()
  handlebars.registerHelper('eq', (a, b) => a === b)
  handlebars.registerHelper('and', (a, b) => a && b)

  this.on('beforePublish', async ({ playbook, contentCatalog, siteCatalog }) => {
    templatePath = expandPath(templatePath, { dot: playbook.dir })
    const templateSrc = await fsp.readFile(templatePath, 'utf8')
    const templateBasename = ospath.basename(templatePath)
    const template = handlebars.compile(templateSrc, { noEscape: true, preventIndent: true, srcName: templateBasename })
    const latestVersions = contentCatalog.getComponentsSortedBy('name').reduce((accum, component) => {
      component.versions.forEach((version) => version.versionSegment !== undefined && accum.push(version))
      return accum
    }, [])
    const stopPages = contentCatalog.getPages((page) => {
      return page.out && ('page-archived' in page.asciidoc.attributes || 'page-noindex' in page.asciidoc.attributes)
    })
    const compiled = template({ latestVersions, site: playbook.site, stopPages })
    siteCatalog.addFile({ contents: Buffer.from(compiled), out: { path: 'docsearch-config.json' } })
  })
}
