/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;

/**
 * Evaluates <code>Authentication</code> tokens
 *
 * @author Yoshikazu Nojima
 */
public interface MFATokenEvaluator {

	/**
	 * Indicates whether the passed <code>Authentication</code> token represents a
	 * user in the middle of multi factor authentication process.
     *
	 * @param authentication to test (may be <code>null</code> in which case the method
	 * will always return <code>false</code>)
	 *
	 * @return <code>true</code> the passed authentication token represented a principal
	 * in the middle of multi factor authentication process, <code>false</code> otherwise
	 */
	boolean isMultiFactorAuthentication(Authentication authentication);

	/**
	 * Indicates whether the principal associated with the <code>Authentication</code>
	 * token is allowed to login with only single factor.
	 *
	 * @param authentication to test (may be <code>null</code> in which case the method
	 * will always return <code>false</code>)
	 *
	 * @return <code>true</code> the principal associated with thepassed authentication
	 * token is allowed to login with only single factor, <code>false</code> otherwise
	 */
	boolean isSingleFactorAuthenticationAllowed(Authentication authentication);
}
