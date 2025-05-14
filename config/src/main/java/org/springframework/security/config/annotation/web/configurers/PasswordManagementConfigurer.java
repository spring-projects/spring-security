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

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.ChangePasswordServiceAdvisor;
import org.springframework.security.authentication.password.DelegatingChangePasswordAdvisor;
import org.springframework.security.authentication.password.UserDetailsPasswordManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RequestMatcherRedirectFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceHandler;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceRepository;
import org.springframework.security.web.authentication.password.ChangePasswordAdvisingFilter;
import org.springframework.security.web.authentication.password.ChangePasswordProcessingFilter;
import org.springframework.security.web.authentication.password.DefaultChangePasswordPageGeneratingFilter;
import org.springframework.security.web.authentication.password.HttpSessionChangePasswordAdviceRepository;
import org.springframework.security.web.authentication.password.SimpleChangePasswordAdviceHandler;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
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

	private static final String DEFAULT_CHANGE_PASSWORD_PAGE = DefaultChangePasswordPageGeneratingFilter.DEFAULT_CHANGE_PASSWORD_URL;

	private ApplicationContext context;

	private boolean customChangePasswordPage = false;

	private String changePasswordPage = DEFAULT_CHANGE_PASSWORD_PAGE;

	private String changePasswordProcessingUrl = ChangePasswordProcessingFilter.DEFAULT_PASSWORD_CHANGE_PROCESSING_URL;

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

	public PasswordManagementConfigurer<B> changePasswordProcessingUrl(String changePasswordProcessingUrl) {
		this.changePasswordProcessingUrl = changePasswordProcessingUrl;
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
				: this.context.getBeanProvider(ChangePasswordAdvisor.class).getIfUnique(() -> {
					List<ChangePasswordAdvisor> advisors = new ArrayList<>();
					advisors.add(new ChangeCompromisedPasswordAdvisor());
					advisors.add(new ChangePasswordServiceAdvisor(passwordManager));
					return new DelegatingChangePasswordAdvisor(advisors);
				});

		http.setSharedObject(ChangePasswordAdviceRepository.class, changePasswordAdviceRepository);
		http.setSharedObject(UserDetailsPasswordManager.class, passwordManager);
		http.setSharedObject(ChangePasswordAdvisor.class, changePasswordAdvisor);

		FormLoginConfigurer form = http.getConfigurer(FormLoginConfigurer.class);
		String passwordParameter = (form != null) ? form.getPasswordParameter() : "password";
		http.getConfigurer(SessionManagementConfigurer.class)
			.addSessionAuthenticationStrategy((authentication, request, response) -> {
				UserDetails user = (UserDetails) authentication.getPrincipal();
				String password = request.getParameter(passwordParameter);
				ChangePasswordAdvice advice = changePasswordAdvisor.advise(user, password);
				changePasswordAdviceRepository.savePasswordAdvice(request, response, advice);
			});
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

		PasswordEncoder passwordEncoder = this.context.getBeanProvider(PasswordEncoder.class)
			.getIfUnique(PasswordEncoderFactories::createDelegatingPasswordEncoder);

		ChangePasswordAdviceHandler changePasswordAdviceHandler = (this.changePasswordAdviceHandler != null)
				? this.changePasswordAdviceHandler : this.context.getBeanProvider(ChangePasswordAdviceHandler.class)
					.getIfUnique(() -> new SimpleChangePasswordAdviceHandler(this.changePasswordPage));

		if (!this.customChangePasswordPage) {
			DefaultChangePasswordPageGeneratingFilter page = new DefaultChangePasswordPageGeneratingFilter();
			http.addFilterBefore(page, RequestCacheAwareFilter.class);
		}

		ChangePasswordProcessingFilter processing = new ChangePasswordProcessingFilter(
				http.getSharedObject(UserDetailsPasswordManager.class));
		processing
			.setRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(this.changePasswordProcessingUrl));
		processing.setChangePasswordAdvisor(http.getSharedObject(ChangePasswordAdvisor.class));
		processing.setChangePasswordAdviceRepository(http.getSharedObject(ChangePasswordAdviceRepository.class));
		processing.setPasswordEncoder(passwordEncoder);
		processing.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		http.addFilterBefore(processing, RequestCacheAwareFilter.class);

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
