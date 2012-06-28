/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.cas.rememberme;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * This class evaluates if the CAS authentication token is in remember me mode.
 * 
 * @author Jerome Leleu
 * @since 3.1.1
 */
public class CasAuthenticationTokenEvaluator {
	
	private static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
	
	private String rememberMeAttributeName = DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
	
	public boolean isRememberMe(Authentication authentication) {
		// if CAS token
		if (authentication instanceof CasAuthenticationToken) {
			CasAuthenticationToken casToken = (CasAuthenticationToken) authentication;
			Assertion assertion = casToken.getAssertion();
			// if "remember me"
			return ("true".equals(assertion.getPrincipal().getAttributes().get(rememberMeAttributeName)));
		}
		
		return false;
	}
	
	public String getRememberMeAttributeName() {
		return rememberMeAttributeName;
	}
	
	public void setRememberMeAttributeName(String rememberMeAttributeName) {
		this.rememberMeAttributeName = rememberMeAttributeName;
	}
}
