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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * ContextSource implementation which uses Spring LDAP's <tt>LdapContextSource</tt> as a
 * base class. Used internally by the Spring Security LDAP namespace configuration.
 * <p>
 * From Spring Security 3.0, Spring LDAP 1.3 is used and the <tt>ContextSource</tt>
 * interface provides support for binding with a username and password. As a result,
 * Spring LDAP <tt>ContextSource</tt> implementations such as <tt>LdapContextSource</tt>
 * may be used directly with Spring Security.
 * <p>
 * Spring LDAP 1.3 doesn't have JVM-level LDAP connection pooling enabled by default. This
 * class sets the <tt>pooled</tt> property to true, but customizes the
 * {@link DirContextAuthenticationStrategy} used to disable pooling when the <tt>DN</tt>
 * doesn't match the <tt>userDn</tt> property. This prevents pooling for calls to
 * {@link #getContext(String, String)} to authenticate as specific users.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class DefaultSpringSecurityContextSource extends LdapContextSource {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * Create and initialize an instance which will connect to the supplied LDAP URL. If
	 * you want to use more than one server for fail-over, rather use the
	 * {@link #DefaultSpringSecurityContextSource(List, String)} constructor.
	 * @param providerUrl an LDAP URL of the form
	 * <code>ldap://localhost:389/base_dn</code>
	 */
	public DefaultSpringSecurityContextSource(String providerUrl) {
		Assert.hasLength(providerUrl, "An LDAP connection URL must be supplied.");
		StringTokenizer tokenizer = new StringTokenizer(providerUrl);
		ArrayList<String> urls = new ArrayList<>();
		// Work out rootDn from the first URL and check that the other URLs (if any) match
		String rootDn = null;
		while (tokenizer.hasMoreTokens()) {
			String url = tokenizer.nextToken();
			String urlRootDn = LdapUtils.parseRootDnFromUrl(url);
			urls.add(url.substring(0, url.lastIndexOf(urlRootDn)));
			this.logger.info(" URL '" + url + "', root DN is '" + urlRootDn + "'");
			Assert.isTrue(rootDn == null || rootDn.equals(urlRootDn),
					"Root DNs must be the same when using multiple URLs");
			rootDn = (rootDn != null) ? rootDn : urlRootDn;
		}
		setUrls(urls.toArray(new String[0]));
		setBase((rootDn != null) ? decodeUrl(rootDn) : null);
		setPooled(true);
		setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy() {

			@Override
			@SuppressWarnings("rawtypes")
			public void setupEnvironment(Hashtable env, String dn, String password) {
				super.setupEnvironment(env, dn, password);
				// Remove the pooling flag unless authenticating as the 'manager' user.
				if (!DefaultSpringSecurityContextSource.this.userDn.equals(dn)
						&& env.containsKey(SUN_LDAP_POOLING_FLAG)) {
					DefaultSpringSecurityContextSource.this.logger.debug("Removing pooling flag for user " + dn);
					env.remove(SUN_LDAP_POOLING_FLAG);
				}
			}

		});
	}

	/**
	 * Create and initialize an instance which will connect of the LDAP Spring Security
	 * Context Source. It will connect to any of the provided LDAP server URLs.
	 * @param urls A list of string values which are LDAP server URLs. An example would be
	 * <code>ldap://ldap.company.com:389</code>. LDAPS URLs (SSL-secured) may be used as
	 * well, given that Spring Security is able to connect to the server. Note that these
	 * <b>URLs must not include the base DN</b>!
	 * @param baseDn The common Base DN for all provided servers, e.g.
	 *
	 * <pre>
	 * dc=company,dc=com
	 * </pre>
	 *
	 * .
	 */
	public DefaultSpringSecurityContextSource(List<String> urls, String baseDn) {
		this(buildProviderUrl(urls, baseDn));
	}

	/**
	 * Builds a Spring LDAP-compliant Provider URL string, i.e. a space-separated list of
	 * LDAP servers with their base DNs. As the base DN must be identical for all servers,
	 * it needs to be supplied only once.
	 * @param urls A list of string values which are LDAP server URLs. An example would be
	 *
	 * <pre>
	 * ldap://ldap.company.com:389
	 * </pre>
	 *
	 * . LDAPS URLs may be used as well, given that Spring Security is able to connect to
	 * the server.
	 * @param baseDn The common Base DN for all provided servers, e.g.
	 *
	 * <pre>
	 * dc=company,dc=com
	 * </pre>
	 *
	 * .
	 * @return A Spring Security/Spring LDAP-compliant Provider URL string.
	 */
	private static String buildProviderUrl(List<String> urls, String baseDn) {
		Assert.notNull(baseDn, "The Base DN for the LDAP server must not be null.");
		Assert.notEmpty(urls, "At least one LDAP server URL must be provided.");
		String encodedBaseDn = encodeUrl(baseDn.trim());
		StringBuilder providerUrl = new StringBuilder();
		for (String serverUrl : urls) {
			String trimmedUrl = serverUrl.trim();
			if ("".equals(trimmedUrl)) {
				continue;
			}
			providerUrl.append(trimmedUrl);
			if (!trimmedUrl.endsWith("/")) {
				providerUrl.append("/");
			}
			providerUrl.append(encodedBaseDn);
			providerUrl.append(" ");
		}
		return providerUrl.toString();

	}

	private static String encodeUrl(String url) {
		try {
			return URLEncoder.encode(url, StandardCharsets.UTF_8.toString());
		}
		catch (UnsupportedEncodingException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private String decodeUrl(String url) {
		try {
			return URLDecoder.decode(url, StandardCharsets.UTF_8.toString());
		}
		catch (UnsupportedEncodingException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
