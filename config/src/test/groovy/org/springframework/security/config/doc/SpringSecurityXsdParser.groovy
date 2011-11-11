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

import groovy.xml.Namespace

/**
 * Parses the Spring Security Xsd Document
 *
 * @author Rob Winch
 */
class SpringSecurityXsdParser {
    private def rootElement

    private def xs = new Namespace("http://www.w3.org/2001/XMLSchema", 'xs')
    private def attrElmts = [] as Set
    private def elementNameToElement = [:] as Map

    /**
     * Returns a map of the element name to the {@link Element}.
     * @return
     */
    Map<String,Element> parse() {
        elements(rootElement)
        elementNameToElement
    }

    /**
     * Creates a Map of the name to an Element object of all the children of element.
     *
     * @param element
     * @return
     */
    private def elements(element) {
        def elementNameToElement = [:] as Map
        element.children().each { c->
            if(c.name() == 'element') {
              def e = elmt(c)
              elementNameToElement.put(e.name,e)
            } else {
              elementNameToElement.putAll(elements(c))
            }
        }
        elementNameToElement
    }

    /**
     * Any children that are attribute will be returned as an Attribute object.
     * @param element
     * @return a collection of Attribute objects that are children of element.
     */
    private def attrs(element) {
        def r = []
        element.children().each { c->
            if(c.name() == 'attribute') {
                r.add(attr(c))
            }else if(c.name() == 'element') {
            }else {
                r.addAll(attrs(c))
            }
        }
        r
    }

    /**
     * Any children will be searched for an attributeGroup, each of it's children will be returned as an Attribute
     * @param element
     * @return
     */
    private def attrgrps(element) {
        def r = []
        element.children().each { c->
            if(c.name() == 'element') {
            }else if (c.name() == 'attributeGroup') {
               if(c.attributes().get('name')) {
                   r.addAll(attrgrp(c))
               } else {
                   private def n = c.attributes().get('ref').split(':')[1]
                   private def attrGrp = findNode(element,n)
                   r.addAll(attrgrp(attrGrp))
               }
            } else {
               r.addAll(attrgrps(c))
            }
        }
        r
    }

    private def findNode(c,name) {
        def root = c
        while(root.name() != 'schema') {
            root = root.parent()
        }
        def result = root.breadthFirst().find { child-> name == child.@name?.text() }
        assert result?.@name?.text() == name
        result
    }

    /**
     * Processes an individual attributeGroup by obtaining all the attributes and then looking for more attributeGroup elements and prcessing them.
     * @param e
     * @return all the attributes for a specific attributeGroup and any child attributeGroups
     */
    private def attrgrp(e) {
        def attrs = attrs(e)
        attrs.addAll(attrgrps(e))
        attrs
    }

    /**
     * Obtains the description for a specific element
     * @param element
     * @return
     */
    private def desc(element) {
        return element['annotation']['documentation']
    }

    /**
     * Given an element creates an attribute from it.
     * @param n
     * @return
     */
    private def attr(n) {
        new Attribute(desc: desc(n), name: n.@name.text())
    }

    /**
     * Given an element creates an Element out of it by collecting all its attributes and child elements.
     *
     * @param n
     * @return
     */
    private def elmt(n) {
        def name = n.@ref.text()
        if(name) {
            name = name.split(':')[1]
            n = findNode(n,name)
        } else {
           name = n.@name.text()
        }
        if(elementNameToElement.containsKey(name)) {
            return elementNameToElement.get(name)
        }
        attrElmts.add(name)
        def e = new Element()
        e.name = n.@name.text()
        e.desc = desc(n)
        e.childElmts = elements(n)
        e.attrs = attrs(n)
        e.attrs.addAll(attrgrps(n))
        e.childElmts.values()*.indent()
        e.attrs*.indent()
        e.attrs*.elmt = e
        e.childElmts.values()*.each { it.parentElmts.put(e.name,e) }

        def subGrpName = n.@substitutionGroup.text()
        if(subGrpName) {
            def subGrp = elmt(findNode(n,subGrpName.split(":")[1]))
            subGrp.subGrps.add(e)
        }

        elementNameToElement.put(name,e)
        e
    }
}
