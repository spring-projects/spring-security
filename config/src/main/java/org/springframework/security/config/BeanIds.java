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
package org.springframework.security.config;

/**
 * Contains globally used default Bean IDs for beans created by the namespace support in
 * Spring Security 2.
 * <p>
 * These are intended for internal use.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public abstract class BeanIds {
	private static final String PREFIX = "org.springframework.security.";

	/**
	 * The "global" AuthenticationManager instance, registered by the
	 * &lt;authentication-manager&gt; element
	 */
	public static final String AUTHENTICATION_MANAGER = PREFIX + "authenticationManager";

	/** External alias for FilterChainProxy bean, for use in web.xml files */
	public static final String SPRING_SECURITY_FILTER_CHAIN = "springSecurityFilterChain";

	public static final String CONTEXT_SOURCE_SETTING_POST_PROCESSOR = PREFIX
			+ "contextSettingPostProcessor";

	public static final String USER_DETAILS_SERVICE = PREFIX + "userDetailsService";
	public static final String USER_DETAILS_SERVICE_FACTORY = PREFIX
			+ "userDetailsServiceFactory";

	public static final String METHOD_ACCESS_MANAGER = PREFIX
			+ "defaultMethodAccessManager";

	public static final String FILTER_CHAIN_PROXY = PREFIX + "filterChainProxy";
	public static final String FILTER_CHAINS = PREFIX + "filterChains";

	public static final String METHOD_SECURITY_METADATA_SOURCE_ADVISOR = PREFIX
			+ "methodSecurityMetadataSourceAdvisor";
	public static final String EMBEDDED_APACHE_DS = PREFIX
			+ "apacheDirectoryServerContainer";
	public static final String EMBEDDED_UNBOUNDID = PREFIX
			+ "unboundidServerContainer";
	public static final String CONTEXT_SOURCE = PREFIX + "securityContextSource";

	public static final String DEBUG_FILTER = PREFIX + "debugFilter";
}
