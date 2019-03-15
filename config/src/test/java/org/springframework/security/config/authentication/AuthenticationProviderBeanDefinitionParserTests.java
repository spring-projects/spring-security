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
package org.springframework.security.config.authentication;

import static org.assertj.core.api.Assertions.*;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.util.FieldUtils;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.support.AbstractXmlApplicationContext;

import org.junit.Test;
import org.junit.After;

import java.util.List;

/**
 * Tests for {@link AuthenticationProviderBeanDefinitionParser}.
 *
 * @author Luke Taylor
 */
public class AuthenticationProviderBeanDefinitionParserTests {
	private AbstractXmlApplicationContext appContext;
	private UsernamePasswordAuthenticationToken bob = new UsernamePasswordAuthenticationToken(
			"bob", "bobspassword");

	@After
	public void closeAppContext() {
		if (appContext != null) {
			appContext.close();
		}
	}

	@Test
	public void worksWithEmbeddedUserService() {
		setContext(" <authentication-provider>"
				+ "        <user-service>"
				+ "            <user name='bob' password='bobspassword' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");
		getProvider().authenticate(bob);
	}

	@Test
	public void externalUserServiceRefWorks() throws Exception {
		appContext = new InMemoryXmlApplicationContext(
				"    <authentication-manager>"
						+ "        <authentication-provider user-service-ref='myUserService' />"
						+ "    </authentication-manager>"
						+ "    <user-service id='myUserService'>"
						+ "       <user name='bob' password='bobspassword' authorities='ROLE_A' />"
						+ "    </user-service>");
		getProvider().authenticate(bob);
	}

	@Test
	public void providerWithBCryptPasswordEncoderWorks() throws Exception {
		setContext(" <authentication-provider>"
				+ "        <password-encoder hash='bcrypt'/>"
				+ "        <user-service>"
				+ "            <user name='bob' password='$2a$05$dRmjl1T05J7rvCPD2NgsHesCEJHww3pdmesUhjM3PD4m/gaEYyx/G' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");

		getProvider().authenticate(bob);
	}

	@Test(expected = BeanDefinitionParsingException.class)
	public void bCryptAndSaltSourceRaisesException() throws Exception {
		appContext = new InMemoryXmlApplicationContext(
				""
						+ " <authentication-manager>"
						+ "    <authentication-provider>"
						+ "        <password-encoder hash='bcrypt'>"
						+ "            <salt-source ref='saltSource'/>"
						+ "        </password-encoder>"
						+ "        <user-service>"
						+ "            <user name='bob' password='$2a$05$dRmjl1T05J7rvCPD2NgsHesCEJHww3pdmesUhjM3PD4m/gaEYyx/G' authorities='ROLE_A' />"
						+ "        </user-service>" + "    </authentication-provider>"
						+ " </authentication-manager>"
						+ " <b:bean id='saltSource'  class='"
						+ ReflectionSaltSource.class.getName() + "'>"
						+ "     <b:property name='userPropertyToUse' value='username'/>"
						+ " </b:bean>");
	}

	@Test
	public void providerWithMd5PasswordEncoderWorks() throws Exception {
		setContext(" <authentication-provider>"
				+ "        <password-encoder hash='md5'/>"
				+ "        <user-service>"
				+ "            <user name='bob' password='12b141f35d58b8b3a46eea65e6ac179e' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");

		getProvider().authenticate(bob);
	}

	@Test
	public void providerWithShaPasswordEncoderWorks() throws Exception {
		setContext(" <authentication-provider>"
				+ "        <password-encoder hash='{sha}'/>"
				+ "        <user-service>"
				+ "            <user name='bob' password='{SSHA}PpuEwfdj7M1rs0C2W4ssSM2XEN/Y6S5U' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");

		getProvider().authenticate(bob);
	}

	@Test
	public void providerWithSha256PasswordEncoderIsSupported() throws Exception {
		setContext(" <authentication-provider>"
				+ "        <password-encoder hash='sha-256'/>"
				+ "        <user-service>"
				+ "            <user name='bob' password='notused' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");

		ShaPasswordEncoder encoder = (ShaPasswordEncoder) FieldUtils.getFieldValue(
				getProvider(), "passwordEncoder");
		assertThat(encoder.getAlgorithm()).isEqualTo("SHA-256");
	}

	@Test
	public void passwordIsBase64EncodedWhenBase64IsEnabled() throws Exception {
		setContext(" <authentication-provider>"
				+ "        <password-encoder hash='md5' base64='true'/>"
				+ "        <user-service>"
				+ "            <user name='bob' password='ErFB811YuLOkbupl5qwXng==' authorities='ROLE_A' />"
				+ "        </user-service>" + "    </authentication-provider>");

		getProvider().authenticate(bob);
	}

	@Test
	public void externalUserServicePasswordEncoderAndSaltSourceWork() throws Exception {
		appContext = new InMemoryXmlApplicationContext(
				"    <authentication-manager>"
						+ "      <authentication-provider user-service-ref='customUserService'>"
						+ "        <password-encoder ref='customPasswordEncoder'>"
						+ "            <salt-source ref='saltSource'/>"
						+ "        </password-encoder>"
						+ "      </authentication-provider>"
						+ "    </authentication-manager>"
						+

						"    <b:bean id='customPasswordEncoder' "
						+ "class='org.springframework.security.authentication.encoding.Md5PasswordEncoder'/>"
						+ "    <b:bean id='saltSource' "
						+ "           class='"
						+ ReflectionSaltSource.class.getName()
						+ "'>"
						+ "         <b:property name='userPropertyToUse' value='username'/>"
						+ "    </b:bean>"
						+ "    <b:bean id='customUserService' "
						+ "           class='org.springframework.security.provisioning.InMemoryUserDetailsManager'>"
						+ "        <b:constructor-arg>"
						+ "            <b:props>"
						+ "                <b:prop key='bob'>f117f0862384e9497ff4f470e3522606,ROLE_A</b:prop>"
						+ "            </b:props>" + "        </b:constructor-arg>"
						+ "    </b:bean>");
		getProvider().authenticate(bob);
	}

	// SEC-1466
	@Test(expected = BeanDefinitionParsingException.class)
	public void exernalProviderDoesNotSupportChildElements() throws Exception {
		appContext = new InMemoryXmlApplicationContext(
				"    <authentication-manager>"
						+ "      <authentication-provider ref='aProvider'> "
						+ "        <password-encoder ref='customPasswordEncoder'/>"
						+ "      </authentication-provider>"
						+ "    </authentication-manager>"
						+ "    <b:bean id='aProvider' class='org.springframework.security.authentication.TestingAuthenticationProvider'/>"
						+ "    <b:bean id='customPasswordEncoder' "
						+ "        class='org.springframework.security.authentication.encoding.Md5PasswordEncoder'/>");
	}

	private AuthenticationProvider getProvider() {
		List<AuthenticationProvider> providers = ((ProviderManager) appContext
				.getBean(BeanIds.AUTHENTICATION_MANAGER)).getProviders();

		return providers.get(0);
	}

	private void setContext(String context) {
		appContext = new InMemoryXmlApplicationContext("<authentication-manager>"
				+ context + "</authentication-manager>");
	}
}
