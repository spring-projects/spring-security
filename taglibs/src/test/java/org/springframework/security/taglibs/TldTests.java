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

package org.springframework.security.taglibs;

import org.junit.Test;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

public class TldTests {

	//SEC-2324
	@Test
	public void testTldVersionIsCorrect() throws Exception{
		String SPRING_SECURITY_VERSION = "springSecurityVersion";

		String version = System.getProperty(SPRING_SECURITY_VERSION);

		File securityTld = new File("src/main/resources/META-INF/security.tld");

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = documentBuilder.parse(securityTld);

		String tlibVersion = document.getElementsByTagName("tlib-version").item(0).getTextContent();

		assertThat(version).startsWith(tlibVersion);
	}


}
