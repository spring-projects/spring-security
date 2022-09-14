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

package org.springframework.security.config.ldap;

import java.text.MessageFormat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationContextException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class LdapProviderBeanDefinitionParserTests {

	InMemoryXmlApplicationContext appCtx;

	@AfterEach
	public void closeAppContext() {
		if (this.appCtx != null) {
			this.appCtx.close();
			this.appCtx = null;
		}
	}

	@Test
	public void simpleProviderAuthenticatesCorrectly() {
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>"
				+ "<authentication-manager>" + "  <ldap-authentication-provider group-search-filter='member={0}' />"
				+ "</authentication-manager>");

		AuthenticationManager authenticationManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER,
				AuthenticationManager.class);
		Authentication auth = authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ben", "benspassword"));
		UserDetails ben = (UserDetails) auth.getPrincipal();
		assertThat(ben.getAuthorities()).hasSize(3);
	}

	@Test
	public void multipleProvidersAreSupported() {
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>"
				+ "<authentication-manager>" + "  <ldap-authentication-provider group-search-filter='member={0}' />"
				+ "  <ldap-authentication-provider group-search-filter='uniqueMember={0}' />"
				+ "</authentication-manager>");

		ProviderManager providerManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER, ProviderManager.class);
		assertThat(providerManager.getProviders()).hasSize(2);
		assertThat(providerManager.getProviders()).extracting("authoritiesPopulator.groupSearchFilter")
				.containsExactly("member={0}", "uniqueMember={0}");
	}

	@Test
	public void missingServerEltCausesConfigException() {
		assertThatExceptionOfType(ApplicationContextException.class).isThrownBy(() -> new InMemoryXmlApplicationContext(
				"<authentication-manager>" + "  <ldap-authentication-provider />" + "</authentication-manager>"));
	}

	@Test
	public void supportsPasswordComparisonAuthentication() {
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>"
				+ "<authentication-manager>" + "  <ldap-authentication-provider user-dn-pattern='uid={0},ou=people'>"
				+ "    <password-compare />" + "  </ldap-authentication-provider>" + "</authentication-manager>");

		AuthenticationManager authenticationManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER,
				AuthenticationManager.class);
		Authentication auth = authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ben", "benspassword"));

		assertThat(auth).isNotNull();
	}

	@Test
	public void supportsPasswordComparisonAuthenticationWithPasswordEncoder() {
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>"
				+ "<authentication-manager>" + "  <ldap-authentication-provider user-dn-pattern='uid={0},ou=people'>"
				+ "    <password-compare password-attribute='uid'>" + "      <password-encoder ref='passwordEncoder' />"
				+ "    </password-compare>" + "  </ldap-authentication-provider>" + "</authentication-manager>"
				+ "<b:bean id='passwordEncoder' class='org.springframework.security.crypto.password.NoOpPasswordEncoder' factory-method='getInstance' />");

		AuthenticationManager authenticationManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER,
				AuthenticationManager.class);
		Authentication auth = authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ben", "ben"));

		assertThat(auth).isNotNull();
	}

	// SEC-2472
	@Test
	public void supportsCryptoPasswordEncoder() {
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server ldif='classpath:test-server.ldif' port='0'/>"
				+ "<authentication-manager>" + "  <ldap-authentication-provider user-dn-pattern='uid={0},ou=people'>"
				+ "    <password-compare>" + "      <password-encoder ref='pe' />" + "    </password-compare>"
				+ "  </ldap-authentication-provider>" + "</authentication-manager>"
				+ "<b:bean id='pe' class='org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder' />");

		AuthenticationManager authenticationManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER,
				AuthenticationManager.class);
		Authentication auth = authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("bcrypt", "password"));

		assertThat(auth).isNotNull();
	}

	@Test
	public void inetOrgContextMapperIsSupported() {
		this.appCtx = new InMemoryXmlApplicationContext(
				"<ldap-server url='ldap://127.0.0.1:343/dc=springframework,dc=org' port='0'/>"
						+ "<authentication-manager>"
						+ "  <ldap-authentication-provider user-details-class='inetOrgPerson' />"
						+ "</authentication-manager>");

		ProviderManager providerManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER, ProviderManager.class);
		assertThat(providerManager.getProviders()).hasSize(1);
		assertThat(providerManager.getProviders()).extracting("userDetailsContextMapper").allSatisfy(
				(contextMapper) -> assertThat(contextMapper).isInstanceOf(InetOrgPersonContextMapper.class));
	}

	@Test
	public void ldapAuthenticationProviderWorksWithPlaceholders() {
		System.setProperty("udp", "people");
		System.setProperty("gsf", "member");
		this.appCtx = new InMemoryXmlApplicationContext("<ldap-server />" + "<authentication-manager>"
				+ "  <ldap-authentication-provider user-dn-pattern='uid={0},ou=${udp}' group-search-filter='${gsf}={0}' />"
				+ "</authentication-manager>"
				+ "<b:bean id='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer' class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer' />");

		ProviderManager providerManager = this.appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER, ProviderManager.class);
		assertThat(providerManager.getProviders()).hasSize(1);

		AuthenticationProvider authenticationProvider = providerManager.getProviders().get(0);
		assertThat(authenticationProvider).extracting("authenticator.userDnFormat")
				.satisfies((messageFormats) -> assertThat(messageFormats)
						.isEqualTo(new MessageFormat[] { new MessageFormat("uid={0},ou=people") }));
		assertThat(authenticationProvider).extracting("authoritiesPopulator.groupSearchFilter")
				.satisfies((searchFilter) -> assertThat(searchFilter).isEqualTo("member={0}"));
	}

}
