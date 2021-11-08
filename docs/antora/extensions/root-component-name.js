// https://gitlab.com/antora/antora/-/issues/132#note_712132072
'use strict'

const { posix: path } = require('path')

module.exports.register = (pipeline, { config }) => {
    pipeline.on('contentClassified', ({ contentCatalog }) => {
        const rootComponentName = config.rootComponentName || 'ROOT'
        const rootComponentNameLength = rootComponentName.length
        contentCatalog.findBy({ component: rootComponentName }).forEach((file) => {
            if (file.out) {
                file.out.dirname = file.out.dirname.substr(rootComponentNameLength)
                file.out.path = file.out.path.substr(rootComponentNameLength + 1)
                file.out.rootPath = fixPath(file.out.rootPath)
            }
            if (file.pub) {
                file.pub.url = file.pub.url.substr(rootComponentNameLength + 1)
                if (file.pub.rootPath) {
                    file.pub.rootPath = fixPath(file.pub.rootPath)
                }
            }
            if (file.rel) {
                if (file.rel.pub) {
                    file.rel.pub.url = file.rel.pub.url.substr(rootComponentNameLength + 1)
                    file.rel.pub.rootPath = fixPath(file.rel.pub.rootPath);
                }
            }
        })
        const rootComponent = contentCatalog.getComponent(rootComponentName)
        rootComponent?.versions?.forEach((version) => {
            version.url = version.url.substr(rootComponentName.length + 1)
        })
        // const siteStartPage = contentCatalog.getById({ component: '', version: '', module: '', family: 'alias', relative: 'index.adoc' })
        // if (siteStartPage) delete siteStartPage.out
    })

    function fixPath(path) {
        return path.split('/').slice(1).join('/') || '.'
    }
}