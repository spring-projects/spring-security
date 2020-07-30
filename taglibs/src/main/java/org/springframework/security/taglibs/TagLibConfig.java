/*
 * Copyright 2002-2014 the original author or authors.
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

package org.springframework.security.taglibs;

import javax.servlet.jsp.tagext.Tag;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * internal configuration class for taglibs.
 *
 * Not for public use.
 *
 * @author Luke Taylor
 */
public final class TagLibConfig {

	static Log logger = LogFactory.getLog("spring-security-taglibs");

	static final boolean DISABLE_UI_SECURITY;
	static final String SECURED_UI_PREFIX;
	static final String SECURED_UI_SUFFIX;

	static {
		String db = System.getProperty("spring.security.disableUISecurity");
		String prefix = System.getProperty("spring.security.securedUIPrefix");
		String suffix = System.getProperty("spring.security.securedUISuffix");

		SECURED_UI_PREFIX = (prefix != null) ? prefix : "<span class=\"securityHiddenUI\">";
		SECURED_UI_SUFFIX = (suffix != null) ? suffix : "</span>";

		DISABLE_UI_SECURITY = "true".equals(db);

		if (DISABLE_UI_SECURITY) {
			logger.warn("***** UI security is disabled. All unauthorized content will be displayed *****");
		}
	}

	private TagLibConfig() {
	}

	/**
	 * Returns EVAL_BODY_INCLUDE if the authorized flag is true or UI security has been
	 * disabled. Otherwise returns SKIP_BODY.
	 * @param authorized whether the user is authorized to see the content or not
	 */
	public static int evalOrSkip(boolean authorized) {
		if (authorized || DISABLE_UI_SECURITY) {
			return Tag.EVAL_BODY_INCLUDE;
		}

		return Tag.SKIP_BODY;
	}

	public static boolean isUiSecurityDisabled() {
		return DISABLE_UI_SECURITY;
	}

	public static String getSecuredUiPrefix() {
		return SECURED_UI_PREFIX;
	}

	public static String getSecuredUiSuffix() {
		return SECURED_UI_SUFFIX;
	}

}
