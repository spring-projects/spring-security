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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.password.PasswordAdvisor;
import org.springframework.security.authentication.password.UserDetailsPasswordAdvisor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.RequestMatcherRedirectFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.password.HttpSessionPasswordAdviceRepository;
import org.springframework.security.web.authentication.password.PasswordAdviceRepository;
import org.springframework.security.web.authentication.password.PasswordAdviceSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.password.PasswordAdvisingFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.util.Assert;

/**
 * Adds password management support.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class PasswordManagementConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<PasswordManagementConfigurer<B>, B> implements ApplicationContextAware {

	private static final String WELL_KNOWN_CHANGE_PASSWORD_PATTERN = "/.well-known/change-password";

	private static final String DEFAULT_CHANGE_PASSWORD_PAGE = "/change-password";

	private ApplicationContext context;

	private boolean customChangePasswordPage = false;

	private String changePasswordPage = DEFAULT_CHANGE_PASSWORD_PAGE;

	private PasswordAdviceRepository passwordAdviceRepository;

	private PasswordAdvisor passwordAdvisor;

	/**
	 * Sets the change password page. Defaults to
	 * {@link PasswordManagementConfigurer#DEFAULT_CHANGE_PASSWORD_PAGE}.
	 * @param changePasswordPage the change password page
	 * @return the {@link PasswordManagementConfigurer} for further customizations
	 */
	public PasswordManagementConfigurer<B> changePasswordPage(String changePasswordPage) {
		Assert.hasText(changePasswordPage, "changePasswordPage cannot be empty");
		this.changePasswordPage = changePasswordPage;
		this.customChangePasswordPage = true;
		return this;
	}

	public PasswordManagementConfigurer<B> passwordAdviceRepository(PasswordAdviceRepository passwordAdviceRepository) {
		this.passwordAdviceRepository = passwordAdviceRepository;
		return this;
	}

	public PasswordManagementConfigurer<B> passwordAdvisor(PasswordAdvisor passwordAdvisor) {
		this.passwordAdvisor = passwordAdvisor;
		return this;
	}

	@Override
	public void init(B http) throws Exception {
		PasswordAdviceRepository passwordAdviceRepository = (this.passwordAdviceRepository != null)
				? this.passwordAdviceRepository : this.context.getBeanProvider(PasswordAdviceRepository.class)
					.getIfUnique(HttpSessionPasswordAdviceRepository::new);

		PasswordAdvisor passwordAdvisor = (this.passwordAdvisor != null) ? this.passwordAdvisor
				: this.context.getBeanProvider(PasswordAdvisor.class).getIfUnique(UserDetailsPasswordAdvisor::new);

		http.setSharedObject(PasswordAdviceRepository.class, passwordAdviceRepository);

		String passwordParameter = "password";
		FormLoginConfigurer<B> form = http.getConfigurer(FormLoginConfigurer.class);
		if (form != null) {
			passwordParameter = form.getPasswordParameter();
		}
		PasswordAdviceSessionAuthenticationStrategy sessionAuthenticationStrategy = new PasswordAdviceSessionAuthenticationStrategy(
				passwordParameter);
		sessionAuthenticationStrategy.setPasswordAdviceRepository(passwordAdviceRepository);
		sessionAuthenticationStrategy.setPasswordAdvisor(passwordAdvisor);
		http.getConfigurer(SessionManagementConfigurer.class)
			.addSessionAuthenticationStrategy(sessionAuthenticationStrategy);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(B http) throws Exception {
		RequestMatcherRedirectFilter changePasswordFilter = new RequestMatcherRedirectFilter(
				getRequestMatcherBuilder().matcher(WELL_KNOWN_CHANGE_PASSWORD_PATTERN), this.changePasswordPage);
		http.addFilterBefore(postProcess(changePasswordFilter), UsernamePasswordAuthenticationFilter.class);

		PasswordAdvisingFilter advising = new PasswordAdvisingFilter(this.changePasswordPage);
		advising.setPasswordAdviceRepository(http.getSharedObject(PasswordAdviceRepository.class));
		advising.setRequestCache(http.getSharedObject(RequestCache.class));
		http.addFilterBefore(advising, RequestCacheAwareFilter.class);
	}

	@Override
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

}
