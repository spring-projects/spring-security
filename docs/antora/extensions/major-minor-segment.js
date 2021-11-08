// https://gitlab.com/antora/antora/-/issues/132#note_712132072
'use strict'

const { posix: path } = require('path')

module.exports.register = (pipeline, { config }) => {
    pipeline.on('contentClassified', ({ contentCatalog }) => {
        contentCatalog.getComponents().forEach(component => {
            const componentName = component.name;
            const generationToVersion = new Map();
            component.versions.forEach(version => {
                const generation = getGeneration(version.version);
                const original = generationToVersion.get(generation);
                if (original === undefined || (original.prerelease && !version.prerelease)) {
                    generationToVersion.set(generation, version);
                }
            });

            const versionToGeneration = Array.from(generationToVersion.entries()).reduce((acc, entry) => {
                const [ generation, version ] = entry;
                acc.set(version.version, generation);
                return acc;
            }, new Map());

            contentCatalog.findBy({ component: componentName }).forEach((file) => {
                const candidateVersion = file.src.version;
                if (versionToGeneration.has(candidateVersion)) {
                    const generation = versionToGeneration.get(candidateVersion);
                    if (file.out) {
                        if (file.out) {
                            file.out.dirname = file.out.dirname.replace(candidateVersion, generation)
                            file.out.path = file.out.path.replace(candidateVersion, generation);
                        }
                    }
                    if (file.pub) {
                        file.pub.url = file.pub.url.replace(candidateVersion, generation)
                    }
                }
            });
            versionToGeneration.forEach((generation, mappedVersion) => {
                contentCatalog.getComponent(componentName).versions.filter(version => version.version === mappedVersion).forEach((version) => {
                    version.url = version.url.replace(mappedVersion, generation);
                })
                const symbolicVersionAlias = createSymbolicVersionAlias(
                    componentName,
                    mappedVersion,
                    generation,
                    'redirect:to'
                )
                symbolicVersionAlias.src.version = generation;
                contentCatalog.addFile(symbolicVersionAlias);
            });
        })
    })
}

function createSymbolicVersionAlias (component, version, symbolicVersionSegment, strategy) {
    if (symbolicVersionSegment == null || symbolicVersionSegment === version) return
    const family = 'alias'
    const baseVersionAliasSrc = { component, module: 'ROOT', family, relative: '', basename: '', stem: '', extname: '' }
    const symbolicVersionAliasSrc = Object.assign({}, baseVersionAliasSrc, { version: symbolicVersionSegment })
    const symbolicVersionAlias = {
        src: symbolicVersionAliasSrc,
        pub: computePub(
            symbolicVersionAliasSrc,
            computeOut(symbolicVersionAliasSrc, family, symbolicVersionSegment),
            family
        ),
    }
    const originalVersionAliasSrc = Object.assign({}, baseVersionAliasSrc, { version })
    const originalVersionSegment = computeVersionSegment(component, version, 'original')
    const originalVersionAlias = {
        src: originalVersionAliasSrc,
        pub: computePub(
            originalVersionAliasSrc,
            computeOut(originalVersionAliasSrc, family, originalVersionSegment),
            family
        ),
    }
    if (strategy === 'redirect:to') {
        originalVersionAlias.out = undefined
        originalVersionAlias.rel = symbolicVersionAlias
        return originalVersionAlias
    } else {
        symbolicVersionAlias.out = undefined
        symbolicVersionAlias.rel = originalVersionAlias
        return symbolicVersionAlias
    }
}


function computeOut (src, family, version, htmlUrlExtensionStyle) {
    let { component, module: module_, basename, extname, relative, stem } = src
    if (module_ === 'ROOT') module_ = ''
    let indexifyPathSegment = ''
    let familyPathSegment = ''

    if (family === 'page') {
        if (stem !== 'index' && htmlUrlExtensionStyle === 'indexify') {
            basename = 'index.html'
            indexifyPathSegment = stem
        } else if (extname === '.adoc') {
            basename = stem + '.html'
        }
    } else if (family === 'image') {
        familyPathSegment = '_images'
    } else if (family === 'attachment') {
        familyPathSegment = '_attachments'
    }
    const modulePath = path.join(component, version, module_)
    const dirname = path.join(modulePath, familyPathSegment, path.dirname(relative), indexifyPathSegment)
    const path_ = path.join(dirname, basename)
    const moduleRootPath = path.relative(dirname, modulePath) || '.'
    const rootPath = path.relative(dirname, '') || '.'

    return { dirname, basename, path: path_, moduleRootPath, rootPath }
}

function computePub (src, out, family, version, htmlUrlExtensionStyle) {
    const pub = {}
    let url
    if (family === 'nav') {
        const urlSegments = version ? [src.component, version] : [src.component]
        if (src.module && src.module !== 'ROOT') urlSegments.push(src.module)
        // an artificial URL used for resolving page references in navigation model
        url = '/' + urlSegments.join('/') + '/'
        pub.moduleRootPath = '.'
    } else if (family === 'page') {
        const urlSegments = out.path.split('/')
        const lastUrlSegmentIdx = urlSegments.length - 1
        if (htmlUrlExtensionStyle === 'drop') {
            // drop just the .html extension or, if the filename is index.html, the whole segment
            const lastUrlSegment = urlSegments[lastUrlSegmentIdx]
            urlSegments[lastUrlSegmentIdx] =
                lastUrlSegment === 'index.html' ? '' : lastUrlSegment.substr(0, lastUrlSegment.length - 5)
        } else if (htmlUrlExtensionStyle === 'indexify') {
            urlSegments[lastUrlSegmentIdx] = ''
        }
        url = '/' + urlSegments.join('/')
    } else {
        url = '/' + out.path
        if (family === 'alias' && !src.relative.length) pub.splat = true
    }

    pub.url = ~url.indexOf(' ') ? url.replace(SPACE_RX, '%20') : url

    if (out) {
        pub.moduleRootPath = out.moduleRootPath
        pub.rootPath = out.rootPath
    }

    return pub
}

function computeVersionSegment (name, version, mode) {
    if (mode === 'original') return !version || version === 'master' ? '' : version
    const strategy = this.latestVersionUrlSegmentStrategy
    // NOTE: special exception; revisit in Antora 3
    if (!version || version === 'master') {
        if (mode !== 'alias') return ''
        if (strategy === 'redirect:to') return
    }
    if (strategy === 'redirect:to' || strategy === (mode === 'alias' ? 'redirect:from' : 'replace')) {
        const component = this.getComponent(name)
        const componentVersion = component && this.getComponentVersion(component, version)
        if (componentVersion) {
            const segment =
                componentVersion === component.latest
                    ? this.latestVersionUrlSegment
                    : componentVersion === component.latestPrerelease
                        ? this.latestPrereleaseVersionUrlSegment
                        : undefined
            return segment == null ? version : segment
        }
    }
    return version
}

function getGeneration(version) {
    if (!version) return version;
    const firstIndex = version.indexOf('.')
    if (firstIndex < 0) {
        return version;
    }
    const secondIndex = version.indexOf('.', firstIndex + 1);
    const result = version.substr(0, secondIndex);
    return result;
}

function out(args) {
    console.log(JSON.stringify(args, no_data, 2));
}


function no_data(key, value) {
    if (key == "data" || key == "files") {
        return value ? "__data__" : value;
    }
    return value;
}