/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.ldap;

import java.io.IOException;
import java.net.ServerSocket;

import org.junit.After;
import org.junit.Test;

import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class LdapServerBeanDefinitionParserTests {

	InMemoryXmlApplicationContext appCtx;

	@After
	public void closeAppContext() {
		if (appCtx != null) {
			appCtx.close();
			appCtx = null;
		}
	}

	@Test
	public void embeddedServerCreationContainsExpectedContextSourceAndData() {
		appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>");

		DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx
				.getBean(BeanIds.CONTEXT_SOURCE);

		// Check data is loaded
		LdapTemplate template = new LdapTemplate(contextSource);
		template.lookup("uid=ben,ou=people");
	}

	@Test
	public void useOfUrlAttributeCreatesCorrectContextSource() throws Exception {
		int port = getDefaultPort();
		// Create second "server" with a url pointing at embedded one
		appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='" + port
				+ "'/>" + "<ldap-server ldif='classpath:test-server.ldif' id='blah' url='ldap://127.0.0.1:" + port
				+ "/dc=springframework,dc=org' />");

		// Check the default context source is still there.
		appCtx.getBean(BeanIds.CONTEXT_SOURCE);

		DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx.getBean("blah");

		// Check data is loaded as before
		LdapTemplate template = new LdapTemplate(contextSource);
		template.lookup("uid=ben,ou=people");
	}

	@Test
	public void loadingSpecificLdifFileIsSuccessful() {
		appCtx = new InMemoryXmlApplicationContext(
				"<ldap-server ldif='classpath*:test-server2.xldif' root='dc=monkeymachine,dc=co,dc=uk' port='0'/>");
		DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx
				.getBean(BeanIds.CONTEXT_SOURCE);

		LdapTemplate template = new LdapTemplate(contextSource);
		template.lookup("uid=pg,ou=gorillas");
	}

	@Test
	public void defaultLdifFileIsSuccessful() {
		appCtx = new InMemoryXmlApplicationContext("<ldap-server/>");
		ApacheDSContainer dsContainer = appCtx.getBean(ApacheDSContainer.class);

		assertThat(ReflectionTestUtils.getField(dsContainer, "ldifResources")).isEqualTo("classpath*:*.ldif");
	}

	private int getDefaultPort() throws IOException {
		try (ServerSocket server = new ServerSocket(0)) {
			return server.getLocalPort();
		}
	}

}
