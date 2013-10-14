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
package org.springframework.security.config.annotation.web.configurers;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.ChannelProcessor;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint;
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds channel security (i.e. requires HTTPS or HTTP) to an application. In order for
 * {@link ChannelSecurityConfigurer} to be useful, at least one {@link RequestMatcher} should be mapped to HTTP
 * or HTTPS.
 *
 * <p>
 * By default an {@link InsecureChannelProcessor} and a {@link SecureChannelProcessor} will be registered.
 * </p>
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link ChannelProcessingFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link PortMapper} is used to create the default {@link ChannelProcessor} instances</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ChannelSecurityConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractRequestMatcherMappingConfigurer<H,ChannelSecurityConfigurer<H>.RequiresChannelUrl,DefaultSecurityFilterChain> {
    private ChannelProcessingFilter channelFilter = new ChannelProcessingFilter();
    private LinkedHashMap<RequestMatcher,Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher,Collection<ConfigAttribute>>();
    private List<ChannelProcessor> channelProcessors;

    /**
     * Creates a new instance
     * @see HttpSecurity#requiresChannel()
     */
    public ChannelSecurityConfigurer() {
    }

    @Override
    public void configure(H http) throws Exception {
        ChannelDecisionManagerImpl channelDecisionManager = new ChannelDecisionManagerImpl();
        channelDecisionManager.setChannelProcessors(getChannelProcessors(http));
        channelDecisionManager = postProcess(channelDecisionManager);

        channelFilter.setChannelDecisionManager(channelDecisionManager);

        DefaultFilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource =
                new DefaultFilterInvocationSecurityMetadataSource(requestMap);
        channelFilter.setSecurityMetadataSource(filterInvocationSecurityMetadataSource);

        channelFilter = postProcess(channelFilter);
        http.addFilter(channelFilter);
    }

    /**
     * Adds an {@link ObjectPostProcessor} for this class.
     *
     * @param objectPostProcessor
     * @return the {@link ChannelSecurityConfigurer} for further customizations
     */
    public ChannelSecurityConfigurer<H> withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        addObjectPostProcessor(objectPostProcessor);
        return this;
    }

    /**
     * Sets the {@link ChannelProcessor} instances to use in  {@link ChannelDecisionManagerImpl}
     * @param channelProcessors
     * @return
     */
    public ChannelSecurityConfigurer<H> channelProcessors(List<ChannelProcessor> channelProcessors) {
        this.channelProcessors = channelProcessors;
        return this;
    }

    private List<ChannelProcessor> getChannelProcessors(H http) {
        if(channelProcessors != null) {
            return channelProcessors;
        }

        InsecureChannelProcessor insecureChannelProcessor = new InsecureChannelProcessor();
        SecureChannelProcessor secureChannelProcessor = new SecureChannelProcessor();

        PortMapper portMapper = http.getSharedObject(PortMapper.class);
        if(portMapper != null) {
            RetryWithHttpEntryPoint httpEntryPoint = new RetryWithHttpEntryPoint();
            httpEntryPoint.setPortMapper(portMapper);
            insecureChannelProcessor.setEntryPoint(httpEntryPoint);

            RetryWithHttpsEntryPoint httpsEntryPoint = new RetryWithHttpsEntryPoint();
            httpsEntryPoint.setPortMapper(portMapper);
            secureChannelProcessor.setEntryPoint(httpsEntryPoint);
        }
        insecureChannelProcessor = postProcess(insecureChannelProcessor);
        secureChannelProcessor = postProcess(secureChannelProcessor);
        return Arrays.<ChannelProcessor>asList(insecureChannelProcessor, secureChannelProcessor);
    }


    private ChannelSecurityConfigurer<H> addAttribute(String attribute, List<RequestMatcher> matchers) {
        for(RequestMatcher matcher : matchers) {
            Collection<ConfigAttribute> attrs = Arrays.<ConfigAttribute>asList(new SecurityConfig(attribute));
            requestMap.put(matcher, attrs);
        }
        return this;
    }

    @Override
    protected RequiresChannelUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
        return new RequiresChannelUrl(requestMatchers);
    }

    public final class RequiresChannelUrl {
        private List<RequestMatcher> requestMatchers;

        private RequiresChannelUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        public ChannelSecurityConfigurer<H> requiresSecure() {
            return requires("REQUIRES_SECURE_CHANNEL");
        }

        public ChannelSecurityConfigurer<H> requiresInsecure() {
            return requires("REQUIRES_INSECURE_CHANNEL");
        }

        public ChannelSecurityConfigurer<H> requires(String attribute) {
            return addAttribute(attribute, requestMatchers);
        }
    }
}