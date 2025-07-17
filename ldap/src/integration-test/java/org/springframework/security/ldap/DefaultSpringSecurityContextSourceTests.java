/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.ldap;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.support.AbstractContextSource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = UnboundIdContainerConfig.class)
public class DefaultSpringSecurityContextSourceTests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	@Test
	public void instantiationSucceedsWithExpectedProperties() {
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	@Test
	public void supportsSpacesInUrl() {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				"ldap://myhost:10389/dc=spring%20framework,dc=org");
		assertThat(contextSource.getBaseLdapPathAsString()).isEqualTo("dc=spring framework,dc=org");
	}

	// gh-9742
	@Test
	public void constructorWhenUrlEncodedSpacesWithPlusCharacterThenBaseDnIsProperlyDecoded() {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				"ldap://blah:123/dc=spring+framework,dc=org ldap://blah:456/dc=spring+framework,dc=org");
		assertThat(contextSource.getBaseLdapPathAsString()).isEqualTo("dc=spring framework,dc=org");
	}

	@Test
	public void poolingFlagIsSetWhenAuthenticationDnMatchesManagerUserDn() {
		EnvExposingDefaultSpringSecurityContextSource ctxSrc = new EnvExposingDefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		ctxSrc.setUserDn("manager");
		ctxSrc.setPassword("password");
		ctxSrc.afterPropertiesSet();
		assertThat(ctxSrc.getAuthenticatedEnvForTest("manager", "password"))
			.containsKey(AbstractContextSource.SUN_LDAP_POOLING_FLAG);
	}

	@Test
	public void poolingFlagIsNotSetWhenAuthenticationDnIsNotManagerUserDn() {
		EnvExposingDefaultSpringSecurityContextSource ctxSrc = new EnvExposingDefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		ctxSrc.setUserDn("manager");
		ctxSrc.setPassword("password");
		ctxSrc.afterPropertiesSet();
		assertThat(ctxSrc.getAuthenticatedEnvForTest("user", "password"))
			.doesNotContainKey(AbstractContextSource.SUN_LDAP_POOLING_FLAG);
	}

	// SEC-1145. Confirms that there is no issue here with pooling.
	@Test
	public void cantBindWithWrongPasswordImmediatelyAfterSuccessfulBind() throws Exception {
		this.contextSource.getContext("uid=Bob,ou=people,dc=springframework,dc=org", "bobspassword").close();
		// com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
		// com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
		// Now get it gain, with wrong password. Should fail.
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(
				() -> this.contextSource.getContext("uid=Bob,ou=people,dc=springframework,dc=org", "wrongpassword")
					.close());
	}

	@Test
	public void serverUrlWithSpacesIsSupported() {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				this.contextSource.getUrls()[0] + "ou=space%20cadets,dc=springframework,dc=org");
		assertThat(contextSource.getBaseLdapPathAsString()).isEqualTo("ou=space cadets,dc=springframework,dc=org");
		contextSource.afterPropertiesSet();
		contextSource.getContext("uid=space cadet,ou=space cadets,dc=springframework,dc=org", "spacecadetspassword");
	}

	@Test
	public void instantiationFailsWithEmptyServerList() {
		List<String> serverUrls = new ArrayList<>();
		assertThatIllegalArgumentException().isThrownBy(() -> {
			DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(serverUrls,
					"dc=springframework,dc=org");
			ctxSrc.afterPropertiesSet();
		});
	}

	@Test
	public void instantiationSucceedsWithProperServerList() {
		List<String> serverUrls = new ArrayList<>();
		serverUrls.add("ldap://foo:789");
		serverUrls.add("ldap://bar:389");
		serverUrls.add("ldaps://blah:636");
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(serverUrls,
				"dc=springframework,dc=org");

		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	// SEC-2308
	@Test
	public void instantiationSucceedsWithEmptyBaseDn() {
		String baseDn = "";
		List<String> serverUrls = new ArrayList<>();
		serverUrls.add("ldap://foo:789");
		serverUrls.add("ldap://bar:389");
		serverUrls.add("ldaps://blah:636");
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(serverUrls, baseDn);

		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	// gh-9742
	@Test
	public void constructorWhenServerListWithSpacesInBaseDnThenSuccess() {
		List<String> serverUrls = new ArrayList<>();
		serverUrls.add("ldap://ad1.example.org:789");
		serverUrls.add("ldap://ad2.example.org:389");
		serverUrls.add("ldaps://ad3.example.org:636");
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(serverUrls,
				"dc=spring framework,dc=org");
		assertThat(contextSource.getBaseLdapPathAsString()).isEqualTo("dc=spring framework,dc=org");
	}

	@Test
	public void instantiationFailsWithIncorrectServerUrl() {
		List<String> serverUrls = new ArrayList<>();
		// a simple trailing slash should be ok
		serverUrls.add("ldaps://blah:636/");
		// this url should be rejected because the root DN goes into a separate parameter
		serverUrls.add("ldap://bar:389/dc=foobar,dc=org");
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DefaultSpringSecurityContextSource(serverUrls, "dc=springframework,dc=org"));
	}

	static class EnvExposingDefaultSpringSecurityContextSource extends DefaultSpringSecurityContextSource {

		EnvExposingDefaultSpringSecurityContextSource(String providerUrl) {
			super(providerUrl);
		}

		@SuppressWarnings("unchecked")
		Hashtable getAuthenticatedEnvForTest(String userDn, String password) {
			return getAuthenticatedEnv(userDn, password);
		}

	}

}
