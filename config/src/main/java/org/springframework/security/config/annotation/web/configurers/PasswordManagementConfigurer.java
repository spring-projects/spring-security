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
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.ChangePasswordServiceAdvisor;
import org.springframework.security.authentication.password.DelegatingChangePasswordAdvisor;
import org.springframework.security.authentication.password.UserDetailsPasswordManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.RequestMatcherRedirectFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceHandler;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceRepository;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.password.ChangePasswordAdvisingFilter;
import org.springframework.security.web.authentication.password.HttpSessionChangePasswordAdviceRepository;
import org.springframework.security.web.authentication.password.SimpleChangePasswordAdviceHandler;
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

	private ChangePasswordAdviceRepository changePasswordAdviceRepository;

	private ChangePasswordAdvisor changePasswordAdvisor;

	private ChangePasswordAdviceHandler changePasswordAdviceHandler;

	private UserDetailsPasswordManager userDetailsPasswordManager;

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

	public PasswordManagementConfigurer<B> changePasswordAdviceRepository(
			ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
		return this;
	}

	public PasswordManagementConfigurer<B> changePasswordAdvisor(ChangePasswordAdvisor changePasswordAdvisor) {
		this.changePasswordAdvisor = changePasswordAdvisor;
		return this;
	}

	public PasswordManagementConfigurer<B> changePasswordAdviceHandler(
			ChangePasswordAdviceHandler changePasswordAdviceHandler) {
		this.changePasswordAdviceHandler = changePasswordAdviceHandler;
		return this;
	}

	public PasswordManagementConfigurer<B> userDetailsPasswordManager(
			UserDetailsPasswordManager userDetailsPasswordManager) {
		this.userDetailsPasswordManager = userDetailsPasswordManager;
		return this;
	}

	@Override
	public void init(B http) throws Exception {
		UserDetailsPasswordManager passwordManager = (this.userDetailsPasswordManager == null)
				? this.context.getBeanProvider(UserDetailsPasswordManager.class).getIfUnique()
				: this.userDetailsPasswordManager;

		if (passwordManager == null) {
			return;
		}

		ChangePasswordAdviceRepository changePasswordAdviceRepository = (this.changePasswordAdviceRepository != null)
				? this.changePasswordAdviceRepository
				: this.context.getBeanProvider(ChangePasswordAdviceRepository.class)
					.getIfUnique(HttpSessionChangePasswordAdviceRepository::new);

		ChangePasswordAdvisor changePasswordAdvisor = (this.changePasswordAdvisor != null) ? this.changePasswordAdvisor
				: this.context.getBeanProvider(ChangePasswordAdvisor.class)
					.getIfUnique(() -> DelegatingChangePasswordAdvisor
						.of(new ChangePasswordServiceAdvisor(passwordManager), new ChangeCompromisedPasswordAdvisor()));

		http.setSharedObject(ChangePasswordAdviceRepository.class, changePasswordAdviceRepository);
		http.setSharedObject(UserDetailsPasswordManager.class, passwordManager);

		String passwordParameter = "password";
		FormLoginConfigurer<B> form = http.getConfigurer(FormLoginConfigurer.class);
		if (form != null) {
			passwordParameter = form.getPasswordParameter();
		}
		ChangePasswordAdviceSessionAuthenticationStrategy sessionAuthenticationStrategy = new ChangePasswordAdviceSessionAuthenticationStrategy(
				passwordParameter);
		sessionAuthenticationStrategy.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
		sessionAuthenticationStrategy.setChangePasswordAdvisor(changePasswordAdvisor);
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

		if (http.getSharedObject(UserDetailsPasswordManager.class) == null) {
			return;
		}

		ChangePasswordAdviceHandler changePasswordAdviceHandler = (this.changePasswordAdviceHandler != null)
				? this.changePasswordAdviceHandler : this.context.getBeanProvider(ChangePasswordAdviceHandler.class)
					.getIfUnique(() -> new SimpleChangePasswordAdviceHandler(this.changePasswordPage));

		ChangePasswordAdvisingFilter advising = new ChangePasswordAdvisingFilter();
		advising.setChangePasswordAdviceRepository(http.getSharedObject(ChangePasswordAdviceRepository.class));
		advising.setChangePasswordAdviceHandler(changePasswordAdviceHandler);
		http.addFilterBefore(advising, RequestCacheAwareFilter.class);
	}

	@Override
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

}
