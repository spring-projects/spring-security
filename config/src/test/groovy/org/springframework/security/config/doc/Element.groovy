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

/**
* Represents a Spring Security XSD Element. It is created when parsing the current xsd to compare to the documented appendix.
*
* @author Rob Winch
* @see SpringSecurityXsdParser
* @see XsdDocumentedSpec
*/
class Element {
    def name
    def desc
    def attrs
    /**
     * Contains the elements that extend this element (i.e. any-user-service contains ldap-user-service)
     */
    def subGrps = []
    def childElmts = [:]
    def parentElmts = [:]

    def getId() {
        return "nsa-${name}".toString()
    }

    /**
     * Gets all the ids related to this Element including attributes, parent elements, and child elements.
     *
     * <p>
     * The expected ids to be found are documented below.
     * <ul>
     * <li>Elements - any xml element will have the nsa-&lt;element&gt;. For example the http element will have the id
     * nsa-http</li>
     * <li>Parent Section - Any element with a parent other than beans will have a section named
     * nsa-&lt;element&gt;-parents. For example, authentication-provider would have a section id of
     * nsa-authentication-provider-parents. The section would then contain a list of links pointing to the
     * documentation for each parent element.</li>
     * <li>Attributes Section - Any element with attributes will have a section with the id
     * nsa-&lt;element&gt;-attributes. For example the http element would require a section with the id
     * http-attributes.</li>
     * <li>Attribute - Each attribute of an element would have an id of nsa-&lt;element&gt;-&lt;attributeName&gt;. For
     * example the attribute create-session for the http attribute would have the id http-create-session.</li>
     * <li>Child Section - Any element with a child element will have a section named nsa-&lt;element&gt;-children.
     * For example, authentication-provider would have a section id of nsa-authentication-provider-children. The
     * section would then contain a list of links pointing to the documentation for each child element.</li>
     * </ul>
     * @return
     */
    def getIds() {
        def ids = [id]
        childElmts.values()*.ids.each { ids.addAll it }
        attrs*.id.each { ids.add it }
        if(childElmts) {
            ids.add id+'-children'
        }
        if(attrs) {
            ids.add id+'-attributes'
        }
        if(parentElmts) {
            ids.add id+'-parents'
        }
        ids
    }

    def getAllChildElmts() {
        def result = [:]
        childElmts.values()*.subGrps*.each { elmt -> result.put(elmt.name,elmt) }
        result + childElmts
    }

    def getAllParentElmts() {
        def result = [:]
        parentElmts.values()*.subGrps*.each { elmt -> result.put(elmt.name,elmt) }
        result + parentElmts
    }
}
