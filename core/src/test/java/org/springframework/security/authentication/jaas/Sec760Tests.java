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

package org.springframework.security.authentication.jaas;

import org.junit.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests bug reported in SEC-760.
 *
 * @author Ben Alex
 *
 */
public class Sec760Tests {

	public String resolveConfigFile(String filename) {
		String resName = "/" + getClass().getPackage().getName().replace('.', '/') + filename;
		return resName;
	}

	private void testConfigureJaasCase(JaasAuthenticationProvider p1, JaasAuthenticationProvider p2) throws Exception {
		p1.setLoginConfig(new ClassPathResource(resolveConfigFile("/test1.conf")));
		p1.setLoginContextName("test1");
		p1.setCallbackHandlers(new JaasAuthenticationCallbackHandler[] { new TestCallbackHandler(),
				new JaasNameCallbackHandler(), new JaasPasswordCallbackHandler() });
		p1.setAuthorityGranters(new AuthorityGranter[] { new TestAuthorityGranter() });
		p1.afterPropertiesSet();
		testAuthenticate(p1);

		p2.setLoginConfig(new ClassPathResource(resolveConfigFile("/test2.conf")));
		p2.setLoginContextName("test2");
		p2.setCallbackHandlers(new JaasAuthenticationCallbackHandler[] { new TestCallbackHandler(),
				new JaasNameCallbackHandler(), new JaasPasswordCallbackHandler() });
		p2.setAuthorityGranters(new AuthorityGranter[] { new TestAuthorityGranter() });
		p2.afterPropertiesSet();
		testAuthenticate(p2);
	}

	private void testAuthenticate(JaasAuthenticationProvider p1) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

		Authentication auth = p1.authenticate(token);
		assertThat(auth).isNotNull();
	}

	@Test
	public void testConfigureJaas() throws Exception {
		testConfigureJaasCase(new JaasAuthenticationProvider(), new JaasAuthenticationProvider());
	}

}
