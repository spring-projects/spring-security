/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.http.SecurityFiltersAssertions;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests to ensure that the xsd is properly documented.
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class XsdDocumentedTests {

	// @formatter:off
	Collection<String> ignoredIds = Arrays.asList("nsa-any-user-service",
			"nsa-any-user-service-parents",
			"nsa-authentication",
			"nsa-websocket-security",
			"nsa-ldap",
			"nsa-web",
			// deprecated and for removal
			"nsa-frame-options-strategy",
			"nsa-frame-options-ref",
			"nsa-frame-options-value",
			"nsa-frame-options-from-parameter");
	// @formatter:on

	String referenceLocation = "../docs/modules/ROOT/pages/servlet/appendix/namespace";

	String schema31xDocumentLocation = "org/springframework/security/config/spring-security-3.1.xsd";

	String schemaDocumentLocation = "org/springframework/security/config/spring-security-6.5.xsd";

	XmlSupport xml = new XmlSupport();

	@AfterEach
	public void close() throws IOException {
		this.xml.close();
	}

	@Test
	public void parseWhenLatestXsdThenAllNamedSecurityFiltersAreDefinedAndOrderedProperly() throws IOException {
		XmlNode root = this.xml.parse(this.schemaDocumentLocation);
		// @formatter:off
		List<String> nodes = root.child("schema")
				.map(XmlNode::children)
				.orElse(Stream.empty())
				.filter((node) -> "simpleType".equals(node.simpleName())
						&& "named-security-filter".equals(node.attribute("name")))
				.flatMap(XmlNode::children)
				.flatMap(XmlNode::children)
				.map((node) -> node.attribute("value"))
				.filter(StringUtils::isNotEmpty)
				.collect(Collectors.toList());
		// @formatter:on
		SecurityFiltersAssertions.assertEquals(nodes);
	}

	@Test
	public void parseWhen31XsdThenAllNamedSecurityFiltersAreDefinedAndOrderedProperly() throws IOException {
		// @formatter:off
		List<String> expected = Arrays.asList("FIRST",
				"CHANNEL_FILTER",
				"SECURITY_CONTEXT_FILTER",
				"CONCURRENT_SESSION_FILTER",
				"LOGOUT_FILTER",
				"X509_FILTER",
				"PRE_AUTH_FILTER",
				"CAS_FILTER",
				"FORM_LOGIN_FILTER",
				"OPENID_FILTER",
				"LOGIN_PAGE_FILTER",
				"DIGEST_AUTH_FILTER",
				"BASIC_AUTH_FILTER",
				"REQUEST_CACHE_FILTER",
				"SERVLET_API_SUPPORT_FILTER",
				"JAAS_API_SUPPORT_FILTER",
				"REMEMBER_ME_FILTER",
				"ANONYMOUS_FILTER",
				"SESSION_MANAGEMENT_FILTER",
				"EXCEPTION_TRANSLATION_FILTER",
				"FILTER_SECURITY_INTERCEPTOR",
				"SWITCH_USER_FILTER",
				"LAST");
		// @formatter:on
		XmlNode root = this.xml.parse(this.schema31xDocumentLocation);
		// @formatter:off
		List<String> nodes = root.child("schema")
				.map(XmlNode::children)
				.orElse(Stream.empty())
				.filter((node) -> "simpleType".equals(node.simpleName())
						&& "named-security-filter".equals(node.attribute("name")))
				.flatMap(XmlNode::children)
				.flatMap(XmlNode::children)
				.map((node) -> node.attribute("value"))
				.filter(StringUtils::isNotEmpty)
				.collect(Collectors.toList());
		// @formatter:on
		assertThat(nodes).isEqualTo(expected);
	}

	/**
	 * This will check to ensure that the expected number of xsd documents are found to
	 * ensure that we are validating against the current xsd document. If this test fails,
	 * all that is needed is to update the schemaDocument and the expected size for this
	 * test.
	 * @return
	 */
	@Test
	public void sizeWhenReadingFilesystemThenIsCorrectNumberOfSchemaFiles() throws IOException {
		ClassPathResource resource = new ClassPathResource(this.schemaDocumentLocation);
		// @formatter:off
		String[] schemas = resource.getFile()
				.getParentFile()
				.list((dir, name) -> name.endsWith(".xsd"));
		// @formatter:on
		assertThat(schemas.length)
			.withFailMessage("the count is equal to 27, if not then schemaDocument needs updating")
			.isEqualTo(27);
	}

	/**
	 * This uses a naming convention for the ids of the appendix to ensure that the entire
	 * appendix is documented. The naming convention for the ids is documented in
	 * {@link Element#getIds()}.
	 * @return
	 */
	@Test
	public void countReferencesWhenReviewingDocumentationThenEntireSchemaIsIncluded() throws IOException {
		Map<String, Element> elementsByElementName = this.xml.elementsByElementName(this.schemaDocumentLocation);
		// @formatter:off
		List<String> documentIds = namespaceLines()
				.filter((line) -> line.matches("\\[\\[(nsa-.*)\\]\\]"))
				.map((line) -> line.substring(2, line.length() - 2))
				.collect(Collectors.toList());
		Set<String> expectedIds = elementsByElementName.values()
				.stream()
				.flatMap((element) -> element.getIds().stream())
				.collect(Collectors.toSet());
		// @formatter:on
		documentIds.removeAll(this.ignoredIds);
		expectedIds.removeAll(this.ignoredIds);
		assertThat(documentIds).containsAll(expectedIds);
		assertThat(expectedIds).containsAll(documentIds);
	}

	/**
	 * This test ensures that any element that has children or parents contains a section
	 * that has links pointing to that documentation.
	 * @return
	 */
	@Test
	public void countLinksWhenReviewingDocumentationThenParentsAndChildrenAreCorrectlyLinked() throws IOException {
		Map<String, List<String>> docAttrNameToChildren = new TreeMap<>();
		Map<String, List<String>> docAttrNameToParents = new TreeMap<>();
		String docAttrName = null;
		Map<String, List<String>> currentDocAttrNameToElmt = null;
		List<String> lines = namespaceLines().collect(Collectors.toList());
		for (String line : lines) {
			if (line.matches("^\\[\\[.*\\]\\]$")) {
				String id = line.substring(2, line.length() - 2);
				if (id.endsWith("-children")) {
					docAttrName = id.substring(0, id.length() - 9);
					currentDocAttrNameToElmt = docAttrNameToChildren;
				}
				else if (id.endsWith("-parents")) {
					docAttrName = id.substring(0, id.length() - 8);
					currentDocAttrNameToElmt = docAttrNameToParents;
				}
				else if (id.endsWith("-attributes") || docAttrName != null && !id.startsWith(docAttrName)) {
					currentDocAttrNameToElmt = null;
					docAttrName = null;
				}
			}
			if (docAttrName != null && currentDocAttrNameToElmt != null) {
				String expression = ".*<<(nsa-.*),.*>>.*";
				if (line.matches(expression)) {
					String elmtId = line.replaceAll(expression, "$1");
					currentDocAttrNameToElmt.computeIfAbsent(docAttrName, (key) -> new ArrayList<>()).add(elmtId);
				}
				else {
					expression = ".*xref:.*#(nsa-.*)\\[.*\\]";
					if (line.matches(expression)) {
						String elmtId = line.replaceAll(expression, "$1");
						currentDocAttrNameToElmt.computeIfAbsent(docAttrName, (key) -> new ArrayList<>()).add(elmtId);
					}
				}
			}
		}
		Map<String, Element> elementNameToElement = this.xml.elementsByElementName(this.schemaDocumentLocation);
		Map<String, List<String>> schemaAttrNameToChildren = new TreeMap<>();
		Map<String, List<String>> schemaAttrNameToParents = new TreeMap<>();
		elementNameToElement.entrySet().stream().forEach((entry) -> {
			String key = "nsa-" + entry.getKey();
			if (this.ignoredIds.contains(key)) {
				return;
			}
			// @formatter:off
			List<String> parentIds = entry.getValue()
					.getAllParentElmts()
					.values()
					.stream()
					.filter((element) -> !this.ignoredIds.contains(element.getId()))
					.map((element) -> element.getId())
					.sorted()
					.collect(Collectors.toList());
			// @formatter:on
			if (!parentIds.isEmpty()) {
				schemaAttrNameToParents.put(key, parentIds);
			}
			// @formatter:off
			List<String> childIds = entry.getValue()
					.getAllChildElmts()
					.values()
					.stream()
					.filter((element) -> !this.ignoredIds.contains(element.getId())).map((element) -> element.getId())
					.sorted()
					.collect(Collectors.toList());
			// @formatter:on
			if (!childIds.isEmpty()) {
				schemaAttrNameToChildren.put(key, childIds);
			}
		});
		assertThat(docAttrNameToChildren)
			.describedAs(toString(docAttrNameToChildren) + "\n!=\n\n" + toString(schemaAttrNameToChildren))
			.containsExactlyInAnyOrderEntriesOf(schemaAttrNameToChildren);
		assertThat(docAttrNameToParents)
			.describedAs(toString(docAttrNameToParents) + "\n!=\n\n" + toString(schemaAttrNameToParents))
			.containsExactlyInAnyOrderEntriesOf(schemaAttrNameToParents);
	}

	private String toString(Map<?, ?> map) {
		StringBuffer buffer = new StringBuffer();
		map.forEach((k, v) -> {
			buffer.append(k);
			buffer.append("=");
			buffer.append(v);
			buffer.append("\n");
		});
		return buffer.toString();
	}

	/**
	 * This test checks each xsd element and ensures there is documentation for it.
	 * @return
	 */
	@Test
	public void countWhenReviewingDocumentationThenAllElementsDocumented() throws IOException {
		Map<String, Element> elementNameToElement = this.xml.elementsByElementName(this.schemaDocumentLocation);
		// @formatter:off
		String notDocElmtIds = elementNameToElement.values()
				.stream()
				.filter((element) -> StringUtils.isEmpty(element.getDesc())
						&& !this.ignoredIds.contains(element.getId()))
				.map((element) -> element.getId())
				.sorted()
				.collect(Collectors.joining("\n"));
		String notDocAttrIds = elementNameToElement.values()
				.stream()
				.flatMap((element) -> element.getAttrs().stream())
				.filter((element) -> StringUtils.isEmpty(element.getDesc())
						&& !this.ignoredIds.contains(element.getId()))
				.map((element) -> element.getId())
				.sorted()
				.collect(Collectors.joining("\n"));
		// @formatter:on
		assertThat(notDocElmtIds).isEmpty();
		assertThat(notDocAttrIds).isEmpty();
	}

	private Stream<String> namespaceLines() {
		return Stream.of(new File(this.referenceLocation).listFiles()).map(File::toPath).flatMap(this::fileLines);
	}

	private Stream<String> fileLines(Path path) {
		try {
			return Files.lines(path);
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

}
