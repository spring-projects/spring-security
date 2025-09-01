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

package org.springframework.security.web.jackson;

import jakarta.servlet.http.Cookie;
import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedCookie;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;

/**
 * Jackson module for spring-security-web related to servlet. This module registers
 * {@link CookieMixin}, {@link SavedCookieMixin}, {@link DefaultSavedRequestMixin},
 * {@link WebAuthenticationDetailsMixin}, and {@link SwitchUserGrantedAuthorityMixIn}.
 *
 * <p>
 * The recommended way to configure it is to use {@link SecurityJacksonModules} in order
 * to enable properly automatic inclusion of type information with related validation.
 *
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader))
 * 				.build();
 * </pre>
 *
 * @author Sebastien Deleuze
 * @author Boris Finkelshteyn
 * @since 7.0
 * @see SecurityJacksonModules
 */
@SuppressWarnings("serial")
public class WebServletJacksonModule extends SecurityJacksonModule {

	public WebServletJacksonModule() {
		super(WebServletJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(Cookie.class).allowIfSubType(DefaultCsrfToken.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(Cookie.class, CookieMixin.class);
		context.setMixIn(SavedCookie.class, SavedCookieMixin.class);
		context.setMixIn(DefaultSavedRequest.class, DefaultSavedRequestMixin.class);
		context.setMixIn(WebAuthenticationDetails.class, WebAuthenticationDetailsMixin.class);
		context.setMixIn(SwitchUserGrantedAuthority.class, SwitchUserGrantedAuthorityMixIn.class);
	}

}
