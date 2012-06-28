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

import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * This class is an authentication trust resolver taking into account the CAS remember me feature.
 * 
 * @author Jerome Leleu
 * @since 3.1.1
 */
public class CasRememberMeAuthenticationTrustResolverImpl extends AuthenticationTrustResolverImpl {
	
	private CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator = new CasAuthenticationTokenEvaluator();
	
	public boolean isRememberMe(Authentication authentication) {
		// if it's a Spring Security remember me
		if (super.isRememberMe(authentication)) {
			return true;
		}
		
		// else if it's a CAS remember me
		return casAuthenticationTokenEvaluator.isRememberMe(authentication);
	}
	
	public CasAuthenticationTokenEvaluator getCasAuthenticationTokenEvaluator() {
		return casAuthenticationTokenEvaluator;
	}
	
	public void setCasAuthenticationTokenEvaluator(	CasAuthenticationTokenEvaluator casAuthenticationTokenEvaluator) {
		this.casAuthenticationTokenEvaluator = casAuthenticationTokenEvaluator;
	}
}
