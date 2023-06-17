'use strict'

/**
 * The purpose of this extension is to fix invalid metadata saved to either antora.yml or gradle.properties in certain
 * tags. This invalid metadata prevents Antora from classifying the component versions properly.
 *
 * This extension addresses with the following cases:
 *
 * . the boolean value on the prerelease key is incorrectly quoted
 * . the prerelease tag is set to true for a GA version
 * . the value of the name key is empty
 * . the value of the displayVersion key doesn't match the actual version
 * . the -SNAPSHOT suffix is appended to the value of the version key instead of the value of the prerelease key
 *
 * This extension should be listed directly after @antora/collector-extension.
 */
module.exports.register = function () {
  this.once('contentAggregated', ({ contentAggregate }) => {
    contentAggregate.forEach((componentVersionBucket) => {
      Object.assign(componentVersionBucket, { name: 'security', display: 'Spring Security' })
    })
  })
}
