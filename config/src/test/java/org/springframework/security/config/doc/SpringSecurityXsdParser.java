/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.doc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.util.StringUtils;

/**
 * Parses the Spring Security Xsd Document
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class SpringSecurityXsdParser {

	private XmlNode rootElement;

	private Set<String> attrElmts = new LinkedHashSet<>();

	private Map<String, Element> elementNameToElement = new HashMap<>();

	public SpringSecurityXsdParser(XmlNode rootElement) {
		this.rootElement = rootElement;
	}

	/**
	 * Returns a map of the element name to the {@link Element}.
	 * @return
	 */
	public Map<String, Element> parse() {
		elements(this.rootElement);
		return this.elementNameToElement;
	}

	/**
	 * Creates a Map of the name to an Element object of all the children of element.
	 * @param node
	 * @return
	 */
	private Map<String, Element> elements(XmlNode node) {
		Map<String, Element> elementNameToElement = new HashMap<>();

		node.children().forEach(child -> {
			if ("element".equals(child.simpleName())) {
				Element e = elmt(child);
				elementNameToElement.put(e.getName(), e);
			}
			else {
				elementNameToElement.putAll(elements(child));
			}
		});

		return elementNameToElement;
	}

	/**
	 * Any children that are attribute will be returned as an Attribute object.
	 * @param element
	 * @return a collection of Attribute objects that are children of element.
	 */
	private Collection<Attribute> attrs(XmlNode element) {
		Collection<Attribute> attrs = new ArrayList<>();
		element.children().forEach(c -> {
			String name = c.simpleName();
			if ("attribute".equals(name)) {
				attrs.add(attr(c));
			}
			else if ("element".equals(name)) {
			}
			else {
				attrs.addAll(attrs(c));
			}
		});

		return attrs;
	}

	/**
	 * Any children will be searched for an attributeGroup, each of its children will be
	 * returned as an Attribute
	 * @param element
	 * @return
	 */
	private Collection<Attribute> attrgrps(XmlNode element) {
		Collection<Attribute> attrgrp = new ArrayList<>();

		element.children().forEach(c -> {
			if ("element".equals(c.simpleName())) {

			}
			else if ("attributeGroup".equals(c.simpleName())) {
				if (c.attribute("name") != null) {
					attrgrp.addAll(attrgrp(c));
				}
				else {
					String name = c.attribute("ref").split(":")[1];
					XmlNode attrGrp = findNode(element, name);
					attrgrp.addAll(attrgrp(attrGrp));
				}
			}
			else {
				attrgrp.addAll(attrgrps(c));
			}
		});

		return attrgrp;
	}

	private XmlNode findNode(XmlNode c, String name) {
		XmlNode root = c;
		while (!"schema".equals(root.simpleName())) {
			root = root.parent().get();
		}

		return expand(root).filter(node -> name.equals(node.attribute("name"))).findFirst()
				.orElseThrow(IllegalArgumentException::new);
	}

	private Stream<XmlNode> expand(XmlNode root) {
		return Stream.concat(Stream.of(root), root.children().flatMap(this::expand));
	}

	/**
	 * Processes an individual attributeGroup by obtaining all the attributes and then
	 * looking for more attributeGroup elements and prcessing them.
	 * @param e
	 * @return all the attributes for a specific attributeGroup and any child
	 * attributeGroups
	 */
	private Collection<Attribute> attrgrp(XmlNode e) {
		Collection<Attribute> attrs = attrs(e);
		attrs.addAll(attrgrps(e));
		return attrs;
	}

	/**
	 * Obtains the description for a specific element
	 * @param element
	 * @return
	 */
	private String desc(XmlNode element) {
		return element.child("annotation").flatMap(annotation -> annotation.child("documentation"))
				.map(documentation -> documentation.text()).orElse(null);
	}

	/**
	 * Given an element creates an attribute from it.
	 * @param n
	 * @return
	 */
	private Attribute attr(XmlNode n) {
		return new Attribute(desc(n), n.attribute("name"));
	}

	/**
	 * Given an element creates an Element out of it by collecting all its attributes and
	 * child elements.
	 * @param n
	 * @return
	 */
	private Element elmt(XmlNode n) {
		String name = n.attribute("ref");
		if (StringUtils.isEmpty(name)) {
			name = n.attribute("name");
		}
		else {
			name = name.split(":")[1];
			n = findNode(n, name);
		}

		if (this.elementNameToElement.containsKey(name)) {
			return this.elementNameToElement.get(name);
		}
		this.attrElmts.add(name);

		Element e = new Element();
		e.setName(n.attribute("name"));
		e.setDesc(desc(n));
		e.setChildElmts(elements(n));
		e.setAttrs(attrs(n));
		e.getAttrs().addAll(attrgrps(n));
		e.getAttrs().forEach(attr -> attr.setElmt(e));
		e.getChildElmts().values().forEach(element -> element.getParentElmts().put(e.getName(), e));

		String subGrpName = n.attribute("substitutionGroup");
		if (!StringUtils.isEmpty(subGrpName)) {
			Element subGrp = elmt(findNode(n, subGrpName.split(":")[1]));
			subGrp.getSubGrps().add(e);
		}

		this.elementNameToElement.put(name, e);

		return e;
	}

}
