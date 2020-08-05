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
package org.springframework.security.config;

import org.junit.After;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests which make sure invalid configurations are rejected by the namespace. In
 * particular invalid top-level elements. These are likely to fail after the namespace has
 * been updated using trang, but the spring-security.xsl transform has not been applied.
 *
 * @author Luke Taylor
 */
public class InvalidConfigurationTests {

	private InMemoryXmlApplicationContext appContext;

	@After
	public void closeAppContext() {
		if (appContext != null) {
			appContext.close();
		}
	}

	// Parser should throw a SAXParseException
	@Test(expected = XmlBeanDefinitionStoreException.class)
	public void passwordEncoderCannotAppearAtTopLevel() {
		setContext("<password-encoder hash='md5'/>");
	}

	@Test(expected = XmlBeanDefinitionStoreException.class)
	public void authenticationProviderCannotAppearAtTopLevel() {
		setContext("<authentication-provider ref='blah'/>");
	}

	@Test
	public void missingAuthenticationManagerGivesSensibleErrorMessage() {
		try {
			setContext("<http auto-config='true' />");
			fail();
		}
		catch (BeanCreationException e) {
			Throwable cause = ultimateCause(e);
			assertThat(cause instanceof NoSuchBeanDefinitionException).isTrue();
			NoSuchBeanDefinitionException nsbe = (NoSuchBeanDefinitionException) cause;
			assertThat(nsbe.getBeanName()).isEqualTo(BeanIds.AUTHENTICATION_MANAGER);
			assertThat(nsbe.getMessage()).endsWith(AuthenticationManagerFactoryBean.MISSING_BEAN_ERROR_MESSAGE);
		}
	}

	private Throwable ultimateCause(Throwable e) {
		if (e.getCause() == null) {
			return e;
		}
		return ultimateCause(e.getCause());
	}

	private void setContext(String context) {
		appContext = new InMemoryXmlApplicationContext(context);
	}

}
