/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.config.util;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;

import static org.springframework.security.config.util.InMemoryXmlApplicationContext.BEANS_CLOSE;
import static org.springframework.security.config.util.InMemoryXmlApplicationContext.BEANS_OPENING;
import static org.springframework.security.config.util.InMemoryXmlApplicationContext.SPRING_SECURITY_VERSION;

/**
 * @author Joe Grandja
 */
public class InMemoryXmlWebApplicationContext extends AbstractRefreshableWebApplicationContext {

	private Resource inMemoryXml;

	public InMemoryXmlWebApplicationContext(String xml) {
		this(xml, SPRING_SECURITY_VERSION, null);
	}

	public InMemoryXmlWebApplicationContext(String xml, ApplicationContext parent) {
		this(xml, SPRING_SECURITY_VERSION, parent);
	}

	public InMemoryXmlWebApplicationContext(String xml, String secVersion, ApplicationContext parent) {
		String fullXml = BEANS_OPENING + secVersion + ".xsd'>\n" + xml + BEANS_CLOSE;
		this.inMemoryXml = new InMemoryResource(fullXml);
		setAllowBeanDefinitionOverriding(true);
		setParent(parent);
	}

	@Override
	protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException {
		XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(beanFactory);
		reader.loadBeanDefinitions(new Resource[] { this.inMemoryXml });
	}

}
