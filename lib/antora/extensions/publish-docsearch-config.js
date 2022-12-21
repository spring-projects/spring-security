'use strict'

const fsp = require('node:fs/promises')
const ospath = require('node:path')

/**
 * An Antora extension that generates the docsearch config file from a Handlebars template and publishes it with the
 * site, where the scraper job can retrieve it.
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
    const components = contentCatalog.getComponentsSortedBy('name').filter((component) => component.latest.version)
    const stopPages = contentCatalog.getPages((page) => {
      return page.out && ('page-archived' in page.asciidoc.attributes || 'page-noindex' in page.asciidoc.attributes)
    })
    const compiled = template({ components, site: playbook.site, stopPages })
    siteCatalog.addFile({ contents: Buffer.from(compiled), out: { path: 'docsearch-config.json' } })
  })
}
