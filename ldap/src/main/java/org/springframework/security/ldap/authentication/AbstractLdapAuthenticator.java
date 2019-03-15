/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.ldap.authentication;

import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.ldap.core.ContextSource;
import org.springframework.util.Assert;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Base class for the authenticator implementations.
 *
 * @author Luke Taylor
 */
public abstract class AbstractLdapAuthenticator implements LdapAuthenticator,
		InitializingBean, MessageSourceAware {
	// ~ Instance fields
	// ================================================================================================

	private final ContextSource contextSource;

	/**
	 * Optional search object which can be used to locate a user when a simple DN match
	 * isn't sufficient
	 */
	private LdapUserSearch userSearch;
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * The attributes which will be retrieved from the directory. Null means all
	 * attributes
	 */
	private String[] userAttributes = null;

	// private String[] userDnPattern = null;
	/** Stores the patterns which are used as potential DN matches */
	private MessageFormat[] userDnFormat = null;

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Create an initialized instance with the {@link ContextSource} provided.
	 *
	 * @param contextSource
	 */
	public AbstractLdapAuthenticator(ContextSource contextSource) {
		Assert.notNull(contextSource, "contextSource must not be null.");
		this.contextSource = contextSource;
	}

	// ~ Methods
	// ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.isTrue((userDnFormat != null) || (userSearch != null),
				"Either an LdapUserSearch or DN pattern (or both) must be supplied.");
	}

	protected ContextSource getContextSource() {
		return contextSource;
	}

	public String[] getUserAttributes() {
		return userAttributes;
	}

	/**
	 * Builds list of possible DNs for the user, worked out from the
	 * <tt>userDnPatterns</tt> property.
	 *
	 * @param username the user's login name
	 *
	 * @return the list of possible DN matches, empty if <tt>userDnPatterns</tt> wasn't
	 * set.
	 */
	protected List<String> getUserDns(String username) {
		if (userDnFormat == null) {
			return Collections.emptyList();
		}

		List<String> userDns = new ArrayList<String>(userDnFormat.length);
		String[] args = new String[] { LdapEncoder.nameEncode(username) };

		synchronized (userDnFormat) {
			for (MessageFormat formatter : userDnFormat) {
				userDns.add(formatter.format(args));
			}
		}

		return userDns;
	}

	protected LdapUserSearch getUserSearch() {
		return userSearch;
	}

	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "Message source must not be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Sets the user attributes which will be retrieved from the directory.
	 *
	 * @param userAttributes
	 */
	public void setUserAttributes(String[] userAttributes) {
		Assert.notNull(userAttributes,
				"The userAttributes property cannot be set to null");
		this.userAttributes = userAttributes;
	}

	/**
	 * Sets the pattern which will be used to supply a DN for the user. The pattern should
	 * be the name relative to the root DN. The pattern argument {0} will contain the
	 * username. An example would be "cn={0},ou=people".
	 *
	 * @param dnPattern the array of patterns which will be tried when converting a
	 * username to a DN.
	 */
	public void setUserDnPatterns(String[] dnPattern) {
		Assert.notNull(dnPattern, "The array of DN patterns cannot be set to null");
		// this.userDnPattern = dnPattern;
		userDnFormat = new MessageFormat[dnPattern.length];

		for (int i = 0; i < dnPattern.length; i++) {
			userDnFormat[i] = new MessageFormat(dnPattern[i]);
		}
	}

	public void setUserSearch(LdapUserSearch userSearch) {
		Assert.notNull(userSearch, "The userSearch cannot be set to null");
		this.userSearch = userSearch;
	}
}
