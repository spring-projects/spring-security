/*
 * Copyright 2002-2022 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.config.util.SpringSecurityVersions;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
@ExtendWith(MockitoExtension.class)
public class SecurityNamespaceHandlerTests {

	// @formatter:off
	private static final String XML_AUTHENTICATION_MANAGER = "<authentication-manager>"
			+ "  <authentication-provider>"
			+ "    <user-service id='us'>"
			+ "      <user name='bob' password='bobspassword' authorities='ROLE_A' />"
			+ "    </user-service>"
			+ "  </authentication-provider>"
			+ "</authentication-manager>";
	// @formatter:on

	private static final String XML_HTTP_BLOCK = "<http auto-config='true'/>";

	private static final String FILTER_CHAIN_PROXY_CLASSNAME = "org.springframework.security.web.FilterChainProxy";

	@Mock(answer = Answers.CALLS_REAL_METHODS)
	private MockedStatic<ClassUtils> classUtils;

	@Test
	public void constructionSucceeds() {
		new SecurityNamespaceHandler();
		// Shameless class coverage stats boosting
		new BeanIds() {
		};
		new Elements() {
		};
	}

	@Test
	public void pre32SchemaAreNotSupported() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> new InMemoryXmlApplicationContext(
						"<user-service id='us'><user name='bob' password='bobspassword' authorities='ROLE_A' /></user-service>",
						"3.0.3", null))
				.withMessageContaining("You cannot use a spring-security-2.0.xsd");
	}

	// SEC-1868
	@Test
	public void initDoesNotLogErrorWhenFilterChainProxyFailsToLoad() throws Exception {
		String className = "jakarta.servlet.Filter";
		Log logger = mock(Log.class);
		SecurityNamespaceHandler handler = new SecurityNamespaceHandler();
		ReflectionTestUtils.setField(handler, "logger", logger);
		expectClassUtilsForNameThrowsNoClassDefFoundError(className);
		handler.init();
		verifyNoMoreInteractions(logger);
	}

	@Test
	public void filterNoClassDefFoundError() throws Exception {
		String className = "jakarta.servlet.Filter";
		expectClassUtilsForNameThrowsNoClassDefFoundError(className);
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER + XML_HTTP_BLOCK))
				.havingRootCause().isInstanceOf(NoClassDefFoundError.class).withMessage(className);
	}

	@Test
	public void filterNoClassDefFoundErrorNoHttpBlock() throws Exception {
		String className = "jakarta.servlet.Filter";
		expectClassUtilsForNameThrowsNoClassDefFoundError(className);
		new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER);
		// should load just fine since no http block
	}

	@Test
	public void filterChainProxyClassNotFoundException() throws Exception {
		String className = FILTER_CHAIN_PROXY_CLASSNAME;
		expectClassUtilsForNameThrowsClassNotFoundException(className);
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER + XML_HTTP_BLOCK))
				.havingRootCause().isInstanceOf(ClassNotFoundException.class).withMessage(className);
	}

	@Test
	public void filterChainProxyClassNotFoundExceptionNoHttpBlock() throws Exception {
		String className = FILTER_CHAIN_PROXY_CLASSNAME;
		expectClassUtilsForNameThrowsClassNotFoundException(className);
		new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER);
		// should load just fine since no http block
	}

	@Test
	public void websocketNotFoundExceptionNoMessageBlock() throws Exception {
		String className = FILTER_CHAIN_PROXY_CLASSNAME;
		expectClassUtilsForNameThrowsClassNotFoundException(className);
		new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER);
		// should load just fine since no websocket block
	}

	@Test
	public void configureWhenOldVersionThenErrorMessageContainsCorrectVersion() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(() -> new InMemoryXmlApplicationContext(XML_AUTHENTICATION_MANAGER, "3.0", null))
				.withMessageContaining(SpringSecurityVersions.getCurrentXsdVersionFromSpringSchemas());
	}

	private void expectClassUtilsForNameThrowsNoClassDefFoundError(String className) {
		this.classUtils.when(() -> ClassUtils.forName(eq(FILTER_CHAIN_PROXY_CLASSNAME), any()))
				.thenThrow(new NoClassDefFoundError(className));
	}

	private void expectClassUtilsForNameThrowsClassNotFoundException(String className) {
		this.classUtils.when(() -> ClassUtils.forName(eq(FILTER_CHAIN_PROXY_CLASSNAME), any()))
				.thenThrow(new ClassNotFoundException(className));
	}

}
