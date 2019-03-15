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
import java.util.Map;

/**
 * Represents a Spring Security XSD Element. It is created when parsing
 * the current xsd to compare to the documented appendix.
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 * @see SpringSecurityXsdParser
 * @see XsdDocumentedTests
*/
public class Element {
	private String name;
	private String desc;
	private Collection<Attribute> attrs = new ArrayList<>();

	/**
	 * Contains the elements that extend this element (i.e. any-user-service contains ldap-user-service)
	 */
	private Collection<Element> subGrps = new ArrayList<>();
	private Map<String, Element> childElmts = new HashMap<>();
	private Map<String, Element> parentElmts = new HashMap<>();

	public String getId() {
		return String.format("nsa-%s", this.name);
	}

	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDesc() {
		return this.desc;
	}

	public void setDesc(String desc) {
		this.desc = desc;
	}

	public Collection<Attribute> getAttrs() {
		return this.attrs;
	}

	public void setAttrs(Collection<Attribute> attrs) {
		this.attrs = attrs;
	}

	public Collection<Element> getSubGrps() {
		return this.subGrps;
	}

	public void setSubGrps(Collection<Element> subGrps) {
		this.subGrps = subGrps;
	}

	public Map<String, Element> getChildElmts() {
		return this.childElmts;
	}

	public void setChildElmts(Map<String, Element> childElmts) {
		this.childElmts = childElmts;
	}

	public Map<String, Element> getParentElmts() {
		return this.parentElmts;
	}

	public void setParentElmts(Map<String, Element> parentElmts) {
		this.parentElmts = parentElmts;
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
	public Collection<String> getIds() {
		Collection<String> ids = new ArrayList<>();
		ids.add(getId());

		this.childElmts.values()
			.forEach(elmt -> ids.add(elmt.getId()));

		this.attrs.forEach(attr -> ids.add(attr.getId()));

		if ( !this.childElmts.isEmpty() ) {
			ids.add(getId() + "-children");
		}

		if ( !this.attrs.isEmpty() ) {
			ids.add(getId() + "-attributes");
		}

		if ( !this.parentElmts.isEmpty() ) {
			ids.add(getId() + "-parents");
		}

		return ids;
	}

	public Map<String, Element> getAllChildElmts() {
		Map<String, Element> result = new HashMap<>();

		this.childElmts.values()
			.forEach(elmt ->
				elmt.subGrps.forEach(
					subElmt -> result.put(subElmt.name, subElmt)));

		result.putAll(this.childElmts);

		return result;
	}

	public Map<String, Element> getAllParentElmts() {
		Map<String, Element> result = new HashMap<>();

		this.parentElmts.values()
			.forEach(elmt ->
				elmt.subGrps.forEach(
					subElmt -> result.put(subElmt.name, subElmt)));

		result.putAll(this.parentElmts);

		return result;
	}
}
