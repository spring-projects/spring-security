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
package org.springframework.security.ldap;

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.directory.DirContext;

import org.junit.Test;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.support.AbstractContextSource;

/**
 * @author Luke Taylor
 */
public class DefaultSpringSecurityContextSourceTests extends AbstractLdapIntegrationTests {

	@Test
	public void instantiationSucceedsWithExpectedProperties() {
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	@Test
	public void supportsSpacesInUrl() {
		new DefaultSpringSecurityContextSource(
				"ldap://myhost:10389/dc=spring%20framework,dc=org");
	}

	@Test
	public void poolingFlagIsSetWhenAuthenticationDnMatchesManagerUserDn()
			throws Exception {
		EnvExposingDefaultSpringSecurityContextSource ctxSrc = new EnvExposingDefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		ctxSrc.setUserDn("manager");
		ctxSrc.setPassword("password");
		ctxSrc.afterPropertiesSet();
		assertThat(ctxSrc.getAuthenticatedEnvForTest("manager", "password")).containsKey(
				AbstractContextSource.SUN_LDAP_POOLING_FLAG);
	}

	@Test
	public void poolingFlagIsNotSetWhenAuthenticationDnIsNotManagerUserDn()
			throws Exception {
		EnvExposingDefaultSpringSecurityContextSource ctxSrc = new EnvExposingDefaultSpringSecurityContextSource(
				"ldap://blah:789/dc=springframework,dc=org");
		ctxSrc.setUserDn("manager");
		ctxSrc.setPassword("password");
		ctxSrc.afterPropertiesSet();
		assertThat(ctxSrc.getAuthenticatedEnvForTest("user", "password")).doesNotContainKey(
				AbstractContextSource.SUN_LDAP_POOLING_FLAG);
	}

	// SEC-1145. Confirms that there is no issue here with pooling.
	@Test(expected = AuthenticationException.class)
	public void cantBindWithWrongPasswordImmediatelyAfterSuccessfulBind()
			throws Exception {
		DirContext ctx = null;
		try {
			ctx = getContextSource().getContext(
					"uid=Bob,ou=people,dc=springframework,dc=org", "bobspassword");
		}
		catch (Exception e) {
		}
		assertThat(ctx).isNotNull();
		// com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
		ctx.close();
		// com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
		// Now get it gain, with wrong password. Should fail.
		ctx = getContextSource().getContext(
				"uid=Bob,ou=people,dc=springframework,dc=org", "wrongpassword");
		ctx.close();
	}

	@Test
	public void serverUrlWithSpacesIsSupported() throws Exception {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
				"ldap://127.0.0.1:" + ApacheDSServerIntegrationTests.getServerPort()
						+ "/ou=space%20cadets,dc=springframework,dc=org");
		contextSource.afterPropertiesSet();
		contextSource.getContext(
				"uid=space cadet,ou=space cadets,dc=springframework,dc=org",
				"spacecadetspassword");
	}

	@Test(expected = IllegalArgumentException.class)
	public void instantiationFailsWithEmptyServerList() throws Exception {
		List<String> serverUrls = new ArrayList<>();
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				serverUrls, "dc=springframework,dc=org");
		ctxSrc.afterPropertiesSet();
	}

	@Test
	public void instantiationSuceedsWithProperServerList() throws Exception {
		List<String> serverUrls = new ArrayList<>();
		serverUrls.add("ldap://foo:789");
		serverUrls.add("ldap://bar:389");
		serverUrls.add("ldaps://blah:636");
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				serverUrls, "dc=springframework,dc=org");

		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	// SEC-2308
	@Test
	public void instantiationSuceedsWithEmtpyBaseDn() throws Exception {
		String baseDn = "";
		List<String> serverUrls = new ArrayList<>();
		serverUrls.add("ldap://foo:789");
		serverUrls.add("ldap://bar:389");
		serverUrls.add("ldaps://blah:636");
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				serverUrls, baseDn);

		assertThat(ctxSrc.isAnonymousReadOnly()).isFalse();
		assertThat(ctxSrc.isPooled()).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void instantiationFailsWithIncorrectServerUrl() throws Exception {
		List<String> serverUrls = new ArrayList<>();
		// a simple trailing slash should be ok
		serverUrls.add("ldaps://blah:636/");
		// this url should be rejected because the root DN goes into a separate parameter
		serverUrls.add("ldap://bar:389/dc=foobar,dc=org");
		DefaultSpringSecurityContextSource ctxSrc = new DefaultSpringSecurityContextSource(
				serverUrls, "dc=springframework,dc=org");
	}

	static class EnvExposingDefaultSpringSecurityContextSource extends
			DefaultSpringSecurityContextSource {
		EnvExposingDefaultSpringSecurityContextSource(String providerUrl) {
			super(providerUrl);
		}

		@SuppressWarnings("unchecked")
		Hashtable getAuthenticatedEnvForTest(String userDn, String password) {
			return getAuthenticatedEnv(userDn, password);
		}
	}
}
