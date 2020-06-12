/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.RequestMatcherRedirectFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds password management support.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class PasswordManagementConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<PasswordManagementConfigurer<B>, B> {

	private static final String WELL_KNOWN_CHANGE_PASSWORD_PATTERN = "/.well-known/change-password";

	private static final String DEFAULT_CHANGE_PASSWORD_PAGE = "/change-password";

	private String changePasswordPage = DEFAULT_CHANGE_PASSWORD_PAGE;

	/**
	 * Sets the change password page. Defaults to
	 * {@link PasswordManagementConfigurer#DEFAULT_CHANGE_PASSWORD_PAGE}.
	 * @param changePasswordPage the change password page
	 * @return the {@link PasswordManagementConfigurer} for further customizations
	 */
	public PasswordManagementConfigurer<B> changePasswordPage(String changePasswordPage) {
		Assert.hasText(changePasswordPage, "changePasswordPage cannot be empty");
		this.changePasswordPage = changePasswordPage;
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(B http) throws Exception {
		RequestMatcherRedirectFilter changePasswordFilter = new RequestMatcherRedirectFilter(
				new AntPathRequestMatcher(WELL_KNOWN_CHANGE_PASSWORD_PATTERN), this.changePasswordPage);
		http.addFilterBefore(postProcess(changePasswordFilter), UsernamePasswordAuthenticationFilter.class);
	}

}
