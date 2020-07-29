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
package org.springframework.security.ldap.ppolicy;

import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Obtains the <tt>PasswordPolicyControl</tt> from a context for use by other classes.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PasswordPolicyControlExtractor {

	private static final Log logger = LogFactory.getLog(PasswordPolicyControlExtractor.class);

	public static PasswordPolicyResponseControl extractControl(DirContext dirCtx) {
		LdapContext ctx = (LdapContext) dirCtx;
		Control[] ctrls = null;
		try {
			ctrls = ctx.getResponseControls();
		}
		catch (javax.naming.NamingException ex) {
			logger.error("Failed to obtain response controls", ex);
		}

		for (int i = 0; ctrls != null && i < ctrls.length; i++) {
			if (ctrls[i] instanceof PasswordPolicyResponseControl) {
				return (PasswordPolicyResponseControl) ctrls[i];
			}
		}

		return null;
	}

}
