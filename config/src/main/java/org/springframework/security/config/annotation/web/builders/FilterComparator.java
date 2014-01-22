/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.builders;

import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
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

/**
 * An internal use only {@link Comparator} that sorts the Security {@link Filter} instances to ensure they are in the
 * correct order.
 *
 * @author Rob Winch
 * @since 3.2
 */

@SuppressWarnings("serial")
final class FilterComparator implements Comparator<Filter>, Serializable {
    private static final int STEP = 100;
    private Map<String,Integer> filterToOrder = new HashMap<String,Integer>();

    FilterComparator() {
        int order = 100;
        put(ChannelProcessingFilter.class, order);
        order += STEP;
        put(ConcurrentSessionFilter.class, order);
        order += STEP;
        put(WebAsyncManagerIntegrationFilter.class, order);
        order += STEP;
        put(SecurityContextPersistenceFilter.class, order);
        order += STEP;
        put(HeaderWriterFilter.class, order);
        order += STEP;
        put(CsrfFilter.class, order);
        order += STEP;
        put(LogoutFilter.class, order);
        order += STEP;
        put(X509AuthenticationFilter.class, order);
        order += STEP;
        put(AbstractPreAuthenticatedProcessingFilter.class, order);
        order += STEP;
        filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter", order);
        order += STEP;
        put(UsernamePasswordAuthenticationFilter.class, order);
        order += STEP;
        put(ConcurrentSessionFilter.class, order);
        order += STEP;
        filterToOrder.put("org.springframework.security.openid.OpenIDAuthenticationFilter", order);
        order += STEP;
        put(DefaultLoginPageGeneratingFilter.class, order);
        order += STEP;
        put(ConcurrentSessionFilter.class, order);
        order += STEP;
        put(DigestAuthenticationFilter.class, order);
        order += STEP;
        put(BasicAuthenticationFilter.class, order);
        order += STEP;
        put(RequestCacheAwareFilter.class, order);
        order += STEP;
        put(SecurityContextHolderAwareRequestFilter.class, order);
        order += STEP;
        put(JaasApiIntegrationFilter.class, order);
        order += STEP;
        put(RememberMeAuthenticationFilter.class, order);
        order += STEP;
        put(AnonymousAuthenticationFilter.class, order);
        order += STEP;
        put(SessionManagementFilter.class, order);
        order += STEP;
        put(ExceptionTranslationFilter.class, order);
        order += STEP;
        put(FilterSecurityInterceptor.class, order);
        order += STEP;
        put(SwitchUserFilter.class, order);
    }

    public int compare(Filter lhs, Filter rhs) {
        Integer left = getOrder(lhs.getClass());
        Integer right = getOrder(rhs.getClass());
        return left - right;
    }

    /**
     * Determines if a particular {@link Filter} is registered to be sorted
     *
     * @param filter
     * @return
     */
    public boolean isRegistered(Class<? extends Filter> filter) {
        return getOrder(filter) != null;
    }

    /**
     * Registers a {@link Filter} to exist after a particular {@link Filter} that is already registered.
     * @param filter the {@link Filter} to register
     * @param afterFilter the {@link Filter} that is already registered and that {@code filter} should be placed after.
     */
    public void registerAfter(Class<? extends Filter> filter, Class<? extends Filter> afterFilter) {
        Integer position = getOrder(afterFilter);
        if(position == null) {
            throw new IllegalArgumentException("Cannot register after unregistered Filter "+afterFilter);
        }

        put(filter, position + 1);
    }

    /**
     * Registers a {@link Filter} to exist before a particular {@link Filter} that is already registered.
     * @param filter the {@link Filter} to register
     * @param beforeFilter the {@link Filter} that is already registered and that {@code filter} should be placed before.
     */
    public void registerBefore(Class<? extends Filter> filter, Class<? extends Filter> beforeFilter) {
        Integer position = getOrder(beforeFilter);
        if(position == null) {
            throw new IllegalArgumentException("Cannot register after unregistered Filter "+beforeFilter);
        }

        put(filter, position - 1);
    }

    private void put(Class<? extends Filter> filter, int position) {
        String className = filter.getName();
        filterToOrder.put(className, position);
    }

    /**
     * Gets the order of a particular {@link Filter} class taking into consideration superclasses.
     *
     * @param clazz the {@link Filter} class to determine the sort order
     * @return the sort order or null if not defined
     */
    private Integer getOrder(Class<?> clazz) {
        while(clazz != null) {
            Integer result = filterToOrder.get(clazz.getName());
            if(result != null) {
                return result;
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }
}
