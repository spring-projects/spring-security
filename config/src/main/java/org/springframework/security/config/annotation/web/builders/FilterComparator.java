/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web.builders;

import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;
import org.springframework.web.filter.CorsFilter;

/**
 * An internal use only {@link Comparator} that sorts the Security {@link Filter}
 * instances to ensure they are in the correct order.
 *
 * @author Rob Winch
 * @since 3.2
 */

@SuppressWarnings("serial")
final class FilterComparator implements Comparator<Filter>, Serializable {

	private static final int INITIAL_ORDER = 100;

	private static final int ORDER_STEP = 100;

	private final Map<String, Integer> filterToOrder = new HashMap<>();

	FilterComparator() {
		Step order = new Step(INITIAL_ORDER, ORDER_STEP);
		put(ChannelProcessingFilter.class, order.next());
		order.next(); // gh-8105
		put(WebAsyncManagerIntegrationFilter.class, order.next());
		put(SecurityContextPersistenceFilter.class, order.next());
		put(HeaderWriterFilter.class, order.next());
		put(CorsFilter.class, order.next());
		put(CsrfFilter.class, order.next());
		put(LogoutFilter.class, order.next());
		this.filterToOrder.put(
				"org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				order.next());
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter",
				order.next());
		put(X509AuthenticationFilter.class, order.next());
		put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
		this.filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter", order.next());
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				order.next());
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter",
				order.next());
		put(UsernamePasswordAuthenticationFilter.class, order.next());
		order.next(); // gh-8105
		this.filterToOrder.put("org.springframework.security.openid.OpenIDAuthenticationFilter", order.next());
		put(DefaultLoginPageGeneratingFilter.class, order.next());
		put(DefaultLogoutPageGeneratingFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		put(DigestAuthenticationFilter.class, order.next());
		this.filterToOrder.put(
				"org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter",
				order.next());
		put(BasicAuthenticationFilter.class, order.next());
		put(RequestCacheAwareFilter.class, order.next());
		put(SecurityContextHolderAwareRequestFilter.class, order.next());
		put(JaasApiIntegrationFilter.class, order.next());
		put(RememberMeAuthenticationFilter.class, order.next());
		put(AnonymousAuthenticationFilter.class, order.next());
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				order.next());
		put(SessionManagementFilter.class, order.next());
		put(ExceptionTranslationFilter.class, order.next());
		put(FilterSecurityInterceptor.class, order.next());
		put(AuthorizationFilter.class, order.next());
		put(SwitchUserFilter.class, order.next());
	}

	@Override
	public int compare(Filter lhs, Filter rhs) {
		Integer left = getOrder(lhs.getClass());
		Integer right = getOrder(rhs.getClass());
		return left - right;
	}

	/**
	 * Determines if a particular {@link Filter} is registered to be sorted
	 * @param filter
	 * @return
	 */
	boolean isRegistered(Class<? extends Filter> filter) {
		return getOrder(filter) != null;
	}

	/**
	 * Registers a {@link Filter} to exist after a particular {@link Filter} that is
	 * already registered.
	 * @param filter the {@link Filter} to register
	 * @param afterFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed after.
	 */
	void registerAfter(Class<? extends Filter> filter, Class<? extends Filter> afterFilter) {
		Integer position = getOrder(afterFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + afterFilter);
		put(filter, position + 1);
	}

	/**
	 * Registers a {@link Filter} to exist at a particular {@link Filter} position
	 * @param filter the {@link Filter} to register
	 * @param atFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed at.
	 */
	void registerAt(Class<? extends Filter> filter, Class<? extends Filter> atFilter) {
		Integer position = getOrder(atFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + atFilter);
		put(filter, position);
	}

	/**
	 * Registers a {@link Filter} to exist before a particular {@link Filter} that is
	 * already registered.
	 * @param filter the {@link Filter} to register
	 * @param beforeFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed before.
	 */
	void registerBefore(Class<? extends Filter> filter, Class<? extends Filter> beforeFilter) {
		Integer position = getOrder(beforeFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + beforeFilter);
		put(filter, position - 1);
	}

	private void put(Class<? extends Filter> filter, int position) {
		String className = filter.getName();
		this.filterToOrder.put(className, position);
	}

	/**
	 * Gets the order of a particular {@link Filter} class taking into consideration
	 * superclasses.
	 * @param clazz the {@link Filter} class to determine the sort order
	 * @return the sort order or null if not defined
	 */
	private Integer getOrder(Class<?> clazz) {
		while (clazz != null) {
			Integer result = this.filterToOrder.get(clazz.getName());
			if (result != null) {
				return result;
			}
			clazz = clazz.getSuperclass();
		}
		return null;
	}

	private static class Step {

		private int value;

		private final int stepSize;

		Step(int initialValue, int stepSize) {
			this.value = initialValue;
			this.stepSize = stepSize;
		}

		int next() {
			int value = this.value;
			this.value += this.stepSize;
			return value;
		}

	}

}
