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

/**
 * Represents a Spring Security XSD Attribute. It is created when parsing the current xsd to compare to the documented appendix.
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 * @see SpringSecurityXsdParser
 * @see XsdDocumentedTests
 */
public class Attribute {
	private String name;

	private String desc;

	private Element elmt;

	public Attribute(String desc, String name) {
		this.desc = desc;
		this.name = name;
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

	public Element getElmt() {
		return this.elmt;
	}

	public void setElmt(Element elmt) {
		this.elmt = elmt;
	}

	public String getId() {
		return String.format("%s-%s", this.elmt.getId(), this.name);
	}
}
