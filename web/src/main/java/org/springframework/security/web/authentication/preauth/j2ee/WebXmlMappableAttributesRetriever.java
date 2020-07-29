/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.preauth.j2ee;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.authority.mapping.MappableAttributesRetriever;

/**
 * This <tt>MappableAttributesRetriever</tt> implementation reads the list of defined J2EE
 * roles from a <tt>web.xml</tt> file and returns these from {
 * {@link #getMappableAttributes()}.
 *
 * @author Ruud Senden
 * @author Luke Taylor
 * @since 2.0
 */
public class WebXmlMappableAttributesRetriever
		implements ResourceLoaderAware, MappableAttributesRetriever, InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private ResourceLoader resourceLoader;

	private Set<String> mappableAttributes;

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	@Override
	public Set<String> getMappableAttributes() {
		return this.mappableAttributes;
	}

	/**
	 * Loads the web.xml file using the configured <tt>ResourceLoader</tt> and parses the
	 * role-name elements from it, using these as the set of <tt>mappableAttributes</tt>.
	 */

	@Override
	public void afterPropertiesSet() throws Exception {
		Resource webXml = this.resourceLoader.getResource("/WEB-INF/web.xml");
		Document doc = getDocument(webXml.getInputStream());
		NodeList webApp = doc.getElementsByTagName("web-app");
		if (webApp.getLength() != 1) {
			throw new IllegalArgumentException("Failed to find 'web-app' element in resource" + webXml);
		}
		NodeList securityRoles = ((Element) webApp.item(0)).getElementsByTagName("security-role");

		ArrayList<String> roleNames = new ArrayList<>();

		for (int i = 0; i < securityRoles.getLength(); i++) {
			Element secRoleElt = (Element) securityRoles.item(i);
			NodeList roles = secRoleElt.getElementsByTagName("role-name");

			if (roles.getLength() > 0) {
				String roleName = roles.item(0).getTextContent().trim();
				roleNames.add(roleName);
				this.logger.info("Retrieved role-name '" + roleName + "' from web.xml");
			}
			else {
				this.logger.info("No security-role elements found in " + webXml);
			}
		}

		this.mappableAttributes = Collections.unmodifiableSet(new HashSet<>(roleNames));
	}

	/**
	 * @return Document for the specified InputStream
	 */
	private Document getDocument(InputStream aStream) {
		Document doc;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			DocumentBuilder db = factory.newDocumentBuilder();
			db.setEntityResolver(new MyEntityResolver());
			doc = db.parse(aStream);
			return doc;
		}
		catch (FactoryConfigurationError | IOException | SAXException | ParserConfigurationException ex) {
			throw new RuntimeException("Unable to parse document object", ex);
		}
		finally {
			try {
				aStream.close();
			}
			catch (IOException ex) {
				this.logger.warn("Failed to close input stream for web.xml", ex);
			}
		}
	}

	/**
	 * We do not need to resolve external entities, so just return an empty String.
	 */
	private static final class MyEntityResolver implements EntityResolver {

		@Override
		public InputSource resolveEntity(String publicId, String systemId) {
			return new InputSource(new StringReader(""));
		}

	}

}
