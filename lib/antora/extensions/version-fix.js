'use strict'

module.exports.register = function () {
  this.once('contentAggregated', ({ contentAggregate }) => {
    contentAggregate.forEach((componentVersionBucket) => {
      if (componentVersionBucket.prerelease === 'true') componentVersionBucket.prerelease = true
      if (!componentVersionBucket.name && componentVersionBucket.displayVersion === 5.6) {
        componentVersionBucket.name = 'ROOT'
        componentVersionBucket.version = '5.6.0-RC1'
        delete componentVersionBucket.displayVersion
        componentVersionBucket.prerelease = true
      }
      else if (componentVersionBucket.version === '5.6.1') {
        delete componentVersionBucket.prerelease
      }
      else if (typeof componentVersionBucket.prerelease === 'string' && componentVersionBucket.prerelease !== '-SNAPSHOT') {
        componentVersionBucket.version += componentVersionBucket.prerelease
        componentVersionBucket.prerelease = true
      }
    })
  })
}
