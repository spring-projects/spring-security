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

package org.springframework.security.config.annotation.authorization;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;

/**
 * Exposes a {@link DefaultAuthorizationManagerFactory} as a Bean with the
 * {@link #authorities()} specified as additional required authorities. The configuration
 * will be picked up by both
 * {@link org.springframework.security.config.annotation.web.configuration.EnableWebSecurity}
 * and
 * {@link org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity}.
 *
 * <pre>

 * &#64;Configuration
 * &#64;EnableGlobalMultiFactorAuthentication(authorities = { GrantedAuthorities.FACTOR_OTT, GrantedAuthorities.FACTOR_PASSWORD })
 * public class MyConfiguration {
 *     // ...
 * }
 * </pre>
 *
 * NOTE: At this time reactive applications do not support MFA and thus are not impacted.
 * This will likely be enhanced in the future.
 *
 * @author Rob Winch
 * @since 7.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(GlobalMultiFactorAuthenticationSelector.class)
public @interface EnableGlobalMultiFactorAuthentication {

	/**
	 * The additional authorities that are required.
	 * @return the additional authorities that are required (e.g. {
	 * FactorGrantedAuthority.FACTOR_OTT, FactorGrantedAuthority.FACTOR_PASSWORD }). Can
	 * be null or an empty array if no additional authorities are required (if
	 * authorization rules are not globally requiring MFA).
	 * @see org.springframework.security.core.authority.FactorGrantedAuthority
	 */
	String[] authorities();

}
