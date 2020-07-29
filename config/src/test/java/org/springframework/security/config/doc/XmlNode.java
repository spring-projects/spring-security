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

import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author Josh Cummings
 */
public class XmlNode {

	private final Node node;

	public XmlNode(Node node) {
		this.node = node;
	}

	public String simpleName() {
		String[] parts = this.node.getNodeName().split(":");
		return parts[parts.length - 1];
	}

	public String text() {
		return this.node.getTextContent();
	}

	public Stream<XmlNode> children() {
		NodeList children = this.node.getChildNodes();

		return IntStream.range(0, children.getLength()).mapToObj(children::item).map(XmlNode::new);
	}

	public Optional<XmlNode> child(String name) {
		return this.children().filter(child -> name.equals(child.simpleName())).findFirst();
	}

	public Optional<XmlNode> parent() {
		return Optional.ofNullable(this.node.getParentNode()).map(parent -> new XmlNode(parent));
	}

	public String attribute(String name) {
		return Optional.ofNullable(this.node.getAttributes()).map(attrs -> attrs.getNamedItem(name))
				.map(attr -> attr.getTextContent()).orElse(null);
	}

	public Node node() {
		return this.node;
	}

}
