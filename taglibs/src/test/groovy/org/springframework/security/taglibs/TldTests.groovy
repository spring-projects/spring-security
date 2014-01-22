package org.springframework.security.taglibs

import groovy.util.slurpersupport.GPathResult
import spock.lang.Specification


class TldTests extends Specification {

  def "SEC-2324: tld version is correct"() {
      when:
          File securityTld = new File('src/main/resources/META-INF/security.tld')
          GPathResult tldRoot = new XmlSlurper().parse(securityTld)
      then:
          String version = System.getProperty('springSecurityVersion');
          version.startsWith(tldRoot.'tlib-version'.text())
  }
}
