/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web.socket;

import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.messaging.access.expression.MessageExpressionVoter;
import org.springframework.security.messaging.access.intercept.ChannelSecurityInterceptor;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.web.socket.config.annotation.AbstractWebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;

import java.util.ArrayList;
import java.util.List;

/**
 * Allows configuring WebSocket Authorization.
 *
 * <p>For example:</p>
 *
 * <pre>
 * @Configuration
 * public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {
 *
 *   @Override
 *   protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
 *     messages
 *       .antMatchers("/user/queue/errors").permitAll()
 *       .antMatchers("/admin/**").hasRole("ADMIN")
 *       .anyMessage().authenticated();
 *   }
 * }
 * </pre>
 *
 *
 * @since 4.0
 * @author Rob Winch
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
public abstract class AbstractSecurityWebSocketMessageBrokerConfigurer extends AbstractWebSocketMessageBrokerConfigurer {
    private final WebSocketMessageSecurityMetadataSourceRegistry inboundRegistry = new WebSocketMessageSecurityMetadataSourceRegistry();

    public final void registerStompEndpoints(StompEndpointRegistry registry) {}

    @Override
    public void addArgumentResolvers(
            List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
    }


    @Override
    public final void configureClientInboundChannel(ChannelRegistration registration) {
        ChannelSecurityInterceptor inboundChannelSecurity = inboundChannelSecurity();
        if(inboundRegistry.containsMapping()) {
            registration.setInterceptors(securityContextChannelInterceptor(),inboundChannelSecurity);
        }
    }

    @Bean
    public ChannelSecurityInterceptor inboundChannelSecurity() {
        ChannelSecurityInterceptor channelSecurityInterceptor = new ChannelSecurityInterceptor(inboundMessageSecurityMetadataSource());
        List<AccessDecisionVoter> voters = new ArrayList<AccessDecisionVoter>();
        voters.add(new MessageExpressionVoter());
        AffirmativeBased manager = new AffirmativeBased(voters);
        channelSecurityInterceptor.setAccessDecisionManager(manager);
        return channelSecurityInterceptor;
    }

    @Bean
    public SecurityContextChannelInterceptor securityContextChannelInterceptor() {
        return new SecurityContextChannelInterceptor();
    }

    @Bean
    public MessageSecurityMetadataSource inboundMessageSecurityMetadataSource() {
        configureInbound(inboundRegistry);
        return inboundRegistry.createMetadataSource();
    }

    /**
     *
     * @param messages
     */
    protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {}

    private class WebSocketMessageSecurityMetadataSourceRegistry extends MessageSecurityMetadataSourceRegistry {
        @Override
        public MessageSecurityMetadataSource createMetadataSource() {
            return super.createMetadataSource();
        }

        @Override
        protected boolean containsMapping() {
            return super.containsMapping();
        }
    }
}