/*
 * Copyright 2025 the original author or authors.
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

package org.springframework.security.web.authentication.password;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangeUpdatingPasswordAdvisor;
import org.springframework.security.authentication.password.UserDetailsPasswordManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.HttpStatusAccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class ChangePasswordProcessingFilter extends OncePerRequestFilter {

	public static final String DEFAULT_PASSWORD_CHANGE_PROCESSING_URL = "/change-password";

	private final AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
			new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));

	private final AuthorizationManager<RequestAuthorizationContext> authorizationManager = AuthenticatedAuthorizationManager
		.authenticated();

	private final AccessDeniedHandler deniedHandler = new HttpStatusAccessDeniedHandler(HttpStatus.FORBIDDEN);

	private final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.POST, DEFAULT_PASSWORD_CHANGE_PROCESSING_URL);

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	private ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	private ChangeUpdatingPasswordAdvisor changePasswordAdvisor = new ChangeCompromisedPasswordAdvisor();

	private final UserDetailsPasswordManager passwordManager;

	public ChangePasswordProcessingFilter(UserDetailsPasswordManager passwordManager) {
		this.passwordManager = passwordManager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		RequestMatcher.MatchResult match = this.requestMatcher.matcher(request);
		if (!match.isMatch()) {
			chain.doFilter(request, response);
			return;
		}
		String password = request.getParameter("newPassword");
		if (password == null) {
			chain.doFilter(request, response);
			return;
		}
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			this.failureHandler.onAuthenticationFailure(request, response,
					new InsufficientAuthenticationException("Authentication required to change password"));
			return;
		}
		AuthorizationResult authorization = this.authorizationManager.authorize(() -> authentication,
				new RequestAuthorizationContext(request, match.getVariables()));
		if (authorization == null) {
			this.deniedHandler.handle(request, response, new AuthorizationDeniedException("denied"));
			return;
		}
		if (!authorization.isGranted()) {
			this.deniedHandler.handle(request, response,
					new AuthorizationDeniedException("access denied", authorization));
			return;
		}
		UserDetails user = (UserDetails) authentication.getPrincipal();
		ChangePasswordAdvice advice = this.changePasswordAdvisor.advise(user, password);
		if (advice.getAction() == ChangePasswordAdvice.Action.KEEP) {
			this.passwordManager.updatePassword(user, this.passwordEncoder.encode(password));
			this.changePasswordAdviceRepository.removePasswordAdvice(request, response);
		}
		else {
			this.changePasswordAdviceRepository.savePasswordAdvice(request, response, advice);
		}
		this.successHandler.onAuthenticationSuccess(request, response, authentication);
	}

	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository advice) {
		this.changePasswordAdviceRepository = advice;
	}

	public void setChangePasswordAdvisor(ChangeUpdatingPasswordAdvisor advisor) {
		this.changePasswordAdvisor = advisor;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

}
