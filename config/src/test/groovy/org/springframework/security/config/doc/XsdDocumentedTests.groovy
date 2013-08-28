/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.doc

import groovy.util.slurpersupport.GPathResult;
import groovy.util.slurpersupport.NodeChild

import org.springframework.security.config.http.SecurityFilters

import spock.lang.*

/**
 * Tests to ensure that the xsd is properly documented.
 *
 * @author Rob Winch
 */
class XsdDocumentedTests extends Specification {

    def ignoredIds = ['nsa-any-user-service','nsa-any-user-service-parents','nsa-authentication','nsa-ldap','nsa-method-security','nsa-web']
    @Shared def appendix = new File('../docs/manual/src/docbook/appendix-namespace.xml')
    @Shared def appendixRoot = new XmlSlurper().parse(appendix)

    @Shared File schema31xDocument = new File('src/main/resources/org/springframework/security/config/spring-security-3.1.xsd')
    @Shared File schemaDocument = new File('src/main/resources/org/springframework/security/config/spring-security-3.2.xsd')
    @Shared Map<String,Element> elementNameToElement
    @Shared GPathResult schemaRootElement

    def setupSpec() {
        schemaRootElement = new XmlSlurper().parse(schemaDocument)
        elementNameToElement = new SpringSecurityXsdParser(rootElement: schemaRootElement).parse()
        appendixRoot.getMetaClass().sections = {
            delegate.breadthFirst().inject([]) {result, c->
                if(c.name() == 'section' && c.@id) {
                    result.add(c)
                }
                result
            }
        }
        NodeChild.metaClass.hrefs = { result ->
            def id = delegate.@id.text().replace('-parents', '').replace('-children', '')
            result.put(id,[])
            delegate.children().breadthFirst().each { sectionChild ->
                def href = sectionChild.@linkend.text()
                if(href) {
                    result.get(id).add(href)
                }
            }
        }
    }

    def 'SEC-2139: named-security-filter are all defined and ordered properly'() {
        setup:
            def expectedFilters = (EnumSet.allOf(SecurityFilters) as List).sort { it.order }
        when:
            def nsf = schemaRootElement.simpleType.find { it.@name == 'named-security-filter' }
            def nsfValues = nsf.children().children().collect { c ->
                Enum.valueOf(SecurityFilters, c.@value.toString())
            }
        then:
            expectedFilters == nsfValues
    }

    def 'SEC-2139: 3.1.x named-security-filter are all defined and ordered properly'() {
        setup:
            def expectedFilters = ["FIRST", "CHANNEL_FILTER", "SECURITY_CONTEXT_FILTER", "CONCURRENT_SESSION_FILTER", "LOGOUT_FILTER", "X509_FILTER",
                "PRE_AUTH_FILTER", "CAS_FILTER", "FORM_LOGIN_FILTER", "OPENID_FILTER", "LOGIN_PAGE_FILTER", "DIGEST_AUTH_FILTER","BASIC_AUTH_FILTER",
                "REQUEST_CACHE_FILTER", "SERVLET_API_SUPPORT_FILTER", "JAAS_API_SUPPORT_FILTER", "REMEMBER_ME_FILTER", "ANONYMOUS_FILTER",
                "SESSION_MANAGEMENT_FILTER", "EXCEPTION_TRANSLATION_FILTER", "FILTER_SECURITY_INTERCEPTOR", "SWITCH_USER_FILTER", "LAST"].collect {
                Enum.valueOf(SecurityFilters, it)
            }
            def schema31xRootElement = new XmlSlurper().parse(schema31xDocument)
        when:
            def nsf = schema31xRootElement.simpleType.find { it.@name == 'named-security-filter' }
            def nsfValues = nsf.children().children().collect { c ->
                Enum.valueOf(SecurityFilters, c.@value.toString())
            }
        then:
            expectedFilters == nsfValues
    }

    /**
     * This will check to ensure that the expected number of xsd documents are found to ensure that we are validating
     * against the current xsd document. If this test fails, all that is needed is to update the schemaDocument
     * and the expected size for this test.
     * @return
     */
    def 'the latest schema is being validated'() {
        when: 'all the schemas are found'
        def schemas = schemaDocument.getParentFile().list().findAll { it.endsWith('.xsd') }
        then: 'the count is equal to 8, if not then schemaDocument needs updated'
        schemas.size() == 8
    }

    /**
     * This uses a naming convention for the ids of the appendix to ensure that the entire appendix is documented.
     * The naming convention for the ids is documented in {@link Element#getIds()}.
     * @return
     */
    def 'the entire schema is included in the appendix documentation'() {
        setup: 'get all the documented ids and the expected ids'
        def documentedIds = appendixRoot.sections().collect { it.@id.text() }
        when: 'the schema is compared to the appendix documentation'
        def expectedIds = [] as Set
        elementNameToElement*.value*.ids*.each { expectedIds.addAll it }
        documentedIds.removeAll ignoredIds
        expectedIds.removeAll ignoredIds
        def undocumentedIds = (expectedIds - documentedIds)
        def shouldNotBeDocumented = (documentedIds - expectedIds)
        then: 'all the elements and attributes are documented'
        shouldNotBeDocumented.empty
        undocumentedIds.empty
    }

    /**
     * This test ensures that any element that has children or parents contains a section that has links pointing to that
     * documentation.
     * @return
     */
    def 'validate parents and children are linked in the appendix documentation'() {
        when: "get all the links for each element's children and parents"
        def docAttrNameToChildren = [:]
        def docAttrNameToParents = [:]
        appendixRoot.sections().each { c->
            def id = c.@id.text()
            if(id.endsWith('-parents')) {
                c.hrefs(docAttrNameToParents)
            }
            if(id.endsWith('-children')) {
                c.hrefs(docAttrNameToChildren)
            }
        }
        def schemaAttrNameToParents = [:]
        def schemaAttrNameToChildren = [:]
        elementNameToElement.each { entry ->
            def key = 'nsa-'+entry.key
            if(ignoredIds.contains(key)) {
                return
            }
            def parentIds = entry.value.allParentElmts.values()*.id.findAll { !ignoredIds.contains(it) }.sort()
            if(parentIds) {
                schemaAttrNameToParents.put(key,parentIds)
            }
            def childIds = entry.value.allChildElmts.values()*.id.findAll { !ignoredIds.contains(it) }.sort()
            if(childIds) {
                schemaAttrNameToChildren.put(key,childIds)
            }
        }
        then: "the expected parents and children are all documented"
        schemaAttrNameToChildren.sort() == docAttrNameToChildren.sort()
        schemaAttrNameToParents.sort() == docAttrNameToParents.sort()
    }

    /**
     * This test checks each xsd element and ensures there is documentation for it.
     * @return
     */
    def 'entire xsd is documented'() {
        when: "validate that the entire xsd contains documentation"
        def notDocElmtIds = elementNameToElement.values().findAll {
            !it.desc.text() && !ignoredIds.contains(it.id)
        }*.id.sort().join("\n")
        def notDocAttrIds = elementNameToElement.values()*.attrs.flatten().findAll {
            !it.desc.text() && !ignoredIds.contains(it.id)
        }*.id.sort().join("\n")
        then: "all the elements and attributes have some documentation"
        !notDocElmtIds
        !notDocAttrIds
    }
}
