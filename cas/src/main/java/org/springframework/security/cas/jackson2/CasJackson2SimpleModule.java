/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.cas.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.security.cas.authentication.CasAuthenticationToken;

/**
 * Jackson module for spring-security-cas. This module register {@link AssertionImplMixin},
 * {@link AttributePrincipalImplMixin} and {@link CasAuthenticationTokenMixin}. In order to use this module just
 * add this module into your ObjectMapper configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CasJackson2SimpleModule());
 * </pre>
 *
 * @author Jitendra Singh.
 */
public class CasJackson2SimpleModule extends SimpleModule {

	public CasJackson2SimpleModule() {
		super(CasJackson2SimpleModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(AssertionImpl.class, AssertionImplMixin.class);
		context.setMixInAnnotations(AttributePrincipalImpl.class, AttributePrincipalImplMixin.class);
		context.setMixInAnnotations(CasAuthenticationToken.class, CasAuthenticationTokenMixin.class);
	}
}
