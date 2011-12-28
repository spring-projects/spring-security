/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.internal.util.reflection.Whitebox;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.AntUrlPathMatcher;

/**
 *
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultFilterChainValidatorTests {
    private DefaultFilterChainValidator validator;
    private FilterChainProxy fcp;
    @Mock
    private Log logger;
    @Mock
    private AccessDecisionManager accessDecisionManager;

    @SuppressWarnings({"unchecked","rawtypes"})
    @Before
    public void setUp() throws Exception {
        AntUrlPathMatcher matcher = new AntUrlPathMatcher();
        LinkedHashMap<RequestKey, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestKey, Collection<ConfigAttribute>>();
        requestMap.put(new RequestKey("/login"), Collections.<ConfigAttribute>emptyList());
        DefaultFilterInvocationSecurityMetadataSource metadataSource = new DefaultFilterInvocationSecurityMetadataSource(matcher,requestMap);
        AnonymousAuthenticationFilter aaf = new AnonymousAuthenticationFilter();
        aaf.setKey("anonymous");
        UserAttribute userAttribute = new UserAttribute();
        userAttribute.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        userAttribute.setPassword("password");
        aaf.setUserAttribute(userAttribute);
        FilterSecurityInterceptor fsi = new FilterSecurityInterceptor();
        fsi.setAccessDecisionManager(accessDecisionManager);
        fsi.setSecurityMetadataSource(metadataSource);
        LoginUrlAuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint();
        authenticationEntryPoint.setLoginFormUrl("/login");
        ExceptionTranslationFilter etf = new ExceptionTranslationFilter();
        etf.setAuthenticationEntryPoint(authenticationEntryPoint);
        Map filterChainMap = new HashMap();
        filterChainMap.put("/**",Arrays.asList(aaf,etf,fsi));
        fcp = new FilterChainProxy();
        fcp.setFilterChainMap(filterChainMap);
        fcp.setMatcher(matcher);
        validator = new DefaultFilterChainValidator();
        Whitebox.setInternalState(validator, "logger", logger);
    }

    // Ensure SEC-1878 does not occur later
    @SuppressWarnings("unchecked")
    @Test
    public void validateCheckLoginPageIsntProtectedThrowsIllegalArgumentException() {
        IllegalArgumentException toBeThrown = new IllegalArgumentException("failed to eval expression");
        doThrow(toBeThrown).when(accessDecisionManager).decide(any(Authentication.class), anyObject(), any(Collection.class));
        validator.validate(fcp);
        verify(logger).warn(contains(toBeThrown.toString()));
    }

}
