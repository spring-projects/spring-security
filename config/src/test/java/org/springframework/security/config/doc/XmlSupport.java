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

import java.io.IOException;
import java.util.Map;

import org.springframework.core.io.ClassPathResource;

/**
 * Support for ensuring preparing the givens in {@link XsdDocumentedTests}
 *
 * @author Josh Cummings
 */
public class XmlSupport {

	private XmlParser parser;

	public XmlNode parse(String location) throws IOException {
		ClassPathResource resource = new ClassPathResource(location);
		this.parser = new XmlParser(resource.getInputStream());
		return this.parser.parse();
	}

	public Map<String, Element> elementsByElementName(String location) throws IOException {
		XmlNode node = parse(location);
		return new SpringSecurityXsdParser(node).parse();
	}

	public void close() throws IOException {
		if (this.parser != null) {
			this.parser.close();
		}
	}

}
