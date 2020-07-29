/*
 * Copyright 2009-2020 the original author or authors.
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

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
public class InMemoryXmlApplicationContext extends AbstractXmlApplicationContext {

	static final String BEANS_OPENING = "<b:beans xmlns='http://www.springframework.org/schema/security'\n"
			+ "    xmlns:context='http://www.springframework.org/schema/context'\n"
			+ "    xmlns:b='http://www.springframework.org/schema/beans'\n"
			+ "    xmlns:aop='http://www.springframework.org/schema/aop'\n"
			+ "    xmlns:mvc='http://www.springframework.org/schema/mvc'\n"
			+ "    xmlns:websocket='http://www.springframework.org/schema/websocket'\n"
			+ "    xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\n"
			+ "    xsi:schemaLocation='http://www.springframework.org/schema/beans https://www.springframework.org/schema/beans/spring-beans-2.5.xsd\n"
			+ "http://www.springframework.org/schema/aop https://www.springframework.org/schema/aop/spring-aop-2.5.xsd\n"
			+ "http://www.springframework.org/schema/mvc https://www.springframework.org/schema/mvc/spring-mvc.xsd\n"
			+ "http://www.springframework.org/schema/websocket https://www.springframework.org/schema/websocket/spring-websocket.xsd\n"
			+ "http://www.springframework.org/schema/context https://www.springframework.org/schema/context/spring-context-2.5.xsd\n"
			+ "http://www.springframework.org/schema/security https://www.springframework.org/schema/security/spring-security-";
	static final String BEANS_CLOSE = "</b:beans>\n";

	static final String SPRING_SECURITY_VERSION = "5.4";

	Resource inMemoryXml;

	public InMemoryXmlApplicationContext(String xml) {
		this(xml, SPRING_SECURITY_VERSION, null);
	}

	public InMemoryXmlApplicationContext(String xml, ApplicationContext parent) {
		this(xml, SPRING_SECURITY_VERSION, parent);
	}

	public InMemoryXmlApplicationContext(String xml, String secVersion, ApplicationContext parent) {
		String fullXml = BEANS_OPENING + secVersion + ".xsd'>\n" + xml + BEANS_CLOSE;
		this.inMemoryXml = new InMemoryResource(fullXml);
		setAllowBeanDefinitionOverriding(true);
		setParent(parent);
		refresh();
	}

	@Override
	protected DefaultListableBeanFactory createBeanFactory() {
		return new DefaultListableBeanFactory(getInternalParentBeanFactory()) {
			@Override
			protected boolean allowAliasOverriding() {
				return true;
			}
		};
	}

	@Override
	protected Resource[] getConfigResources() {
		return new Resource[] { this.inMemoryXml };
	}

}
