/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;

/**
 * Basic implementation of {@link MFATokenEvaluator}.
 * <p>
 * Makes trust decisions based on whether the passed <code>Authentication</code> is an
 * instance of a defined class.
 * <p>
 * If {@link #multiFactorClass} is <code>null</code>, the
 * corresponding method will always return <code>false</code>.
 *
 * @author Yoshikazu Nojima
 */
public class MFATokenEvaluatorImpl implements MFATokenEvaluator {

	private Class<? extends Authentication> multiFactorClass = MultiFactorAuthenticationToken.class;

	Class<? extends Authentication> getMultiFactorClass() { return multiFactorClass; }

	@Override
	public boolean isMultiFactorAuthentication(Authentication authentication) {
		if ((multiFactorClass == null) || (authentication == null)) {
			return false;
		}

		return multiFactorClass.isAssignableFrom(authentication.getClass());
	}

	public void setMultiFactorClass(Class<? extends Authentication> multiFactorClass) {this.multiFactorClass = multiFactorClass; }

}
