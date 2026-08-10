/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.client.ldap;

import java.security.PrivilegedAction;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.util.Assert;

/**
 * Implementation of an {@link LdapContextSource} that authenticates with the ldap server
 * using Kerberos.
 *
 * Example usage:
 *
 * <pre>
 *  &lt;bean id=&quot;authorizationContextSource&quot; class=&quot;org.springframework.security.kerberos.ldap.KerberosLdapContextSource&quot;&gt;
 *      &lt;constructor-arg value=&quot;${authentication.ldap.ldapUrl}&quot; /&gt;
 *      &lt;property name=&quot;referral&quot; value=&quot;ignore&quot; /&gt;
 *
 *       &lt;property name=&quot;loginConfig&quot;&gt;
 *           &lt;bean class=&quot;org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig&quot;&gt;
 *               &lt;property name=&quot;servicePrincipal&quot; value=&quot;${authentication.ldap.servicePrincipal}&quot; /&gt;
 *               &lt;property name=&quot;useTicketCache&quot; value=&quot;true&quot; /&gt;
 *               &lt;property name=&quot;isInitiator&quot; value=&quot;true&quot; /&gt;
 *               &lt;property name=&quot;debug&quot; value=&quot;false&quot; /&gt;
 *           &lt;/bean&gt;
 *       &lt;/property&gt;
 *   &lt;/bean&gt;
 *
 *   &lt;sec:ldap-user-service id=&quot;ldapUserService&quot; server-ref=&quot;authorizationContextSource&quot; user-search-filter=&quot;(| (userPrincipalName={0}) (sAMAccountName={0}))&quot;
 *       group-search-filter=&quot;(member={0})&quot; group-role-attribute=&quot;cn&quot; role-prefix=&quot;none&quot; /&gt;
 * </pre>
 *
 * @author Nelson Rodrigues
 * @see SunJaasKrb5LoginConfig
 */
public class KerberosLdapContextSource extends DefaultSpringSecurityContextSource implements InitializingBean {

	private @Nullable Configuration loginConfig;

	/**
	 * Instantiates a new kerberos ldap context source.
	 * @param url the url
	 */
	public KerberosLdapContextSource(String url) {
		super(url);
	}

	/**
	 * Instantiates a new kerberos ldap context source.
	 * @param urls the urls
	 * @param baseDn the base dn
	 */
	public KerberosLdapContextSource(List<String> urls, String baseDn) {
		super(urls, baseDn);
	}

	@Override
	public void afterPropertiesSet() /* throws Exception */ {
		// org.springframework.ldap.core.support.AbstractContextSource in 4.x
		// doesn't throw Exception for its InitializingBean method, so
		// we had to remove it from here also. Addition to that
		// we need to catch super call and re-throw.
		try {
			super.afterPropertiesSet();
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
		Assert.notNull(this.loginConfig, "loginConfig must be specified");
	}

	@SuppressWarnings("unchecked")
	@Override
	protected DirContext getDirContextInstance(final @SuppressWarnings("rawtypes") Hashtable environment)
			throws NamingException {
		environment.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

		Subject serviceSubject = login();

		final NamingException[] suppressedException = new NamingException[] { null };
		DirContext dirContext = Subject.doAs(serviceSubject, new PrivilegedAction<@Nullable DirContext>() {

			@Override
			public @Nullable DirContext run() {
				try {
					return KerberosLdapContextSource.super.getDirContextInstance(environment);
				}
				catch (NamingException ex) {
					suppressedException[0] = ex;
					return null;
				}
			}
		});

		if (suppressedException[0] != null) {
			throw suppressedException[0];
		}
		if (dirContext == null) {
			throw new NamingException("Failed to obtain DirContext");
		}

		return dirContext;
	}

	/**
	 * The login configuration to get the serviceSubject from LoginContext
	 * @param loginConfig the login config
	 */
	public void setLoginConfig(Configuration loginConfig) {
		this.loginConfig = loginConfig;
	}

	private Subject login() throws AuthenticationException {
		try {
			LoginContext lc = new LoginContext(KerberosLdapContextSource.class.getSimpleName(), null, null,
					this.loginConfig);

			lc.login();

			return lc.getSubject();
		}
		catch (LoginException ex) {
			AuthenticationException ae = new AuthenticationException(ex.getMessage());
			ae.initCause(ex);
			throw ae;
		}
	}

}
