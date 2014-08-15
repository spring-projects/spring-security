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
package org.springframework.security.config.annotation.web.messaging;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.Collection;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MessageSecurityMetadataSourceRegistryTests {
    @Mock
    private MessageMatcher<Object> matcher;

    private MessageSecurityMetadataSourceRegistry messages;

    private Message<String> message;

    @Before
    public void setup() {
        messages = new MessageSecurityMetadataSourceRegistry();
        message = MessageBuilder
                .withPayload("Hi")
                .setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "location")
                   .build();
    }

    @Test
    public void matchersFalse() {
        messages
                .matchers(matcher).permitAll();

        assertThat(getAttribute()).isNull();
    }

    @Test
    public void matchersTrue() {
        when(matcher.matches(message)).thenReturn(true);
        messages
                .matchers(matcher).permitAll();

        assertThat(getAttribute()).isEqualTo("permitAll");
    }

    @Test
    public void antMatcherExact() {
        messages
                .antMatchers("location").permitAll();

        assertThat(getAttribute()).isEqualTo("permitAll");
    }

    @Test
    public void antMatcherMulti() {
        messages
                .antMatchers("admin/**","api/**").hasRole("ADMIN")
                .antMatchers("location").permitAll();

        assertThat(getAttribute()).isEqualTo("permitAll");
    }

    @Test
    public void antMatcherRole() {
        messages
                .antMatchers("admin/**","location/**").hasRole("ADMIN")
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("hasRole('ROLE_ADMIN')");
    }

    @Test
    public void antMatcherAnyRole() {
        messages
                .antMatchers("admin/**","location/**").hasAnyRole("ADMIN", "ROOT")
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("hasAnyRole('ROLE_ADMIN','ROLE_ROOT')");
    }

    @Test
    public void antMatcherAuthority() {
        messages
                .antMatchers("admin/**","location/**").hasAuthority("ROLE_ADMIN")
                .anyMessage().fullyAuthenticated();

        assertThat(getAttribute()).isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    @Test
    public void antMatcherAccess() {
        String expected = "hasRole('ROLE_ADMIN') and fullyAuthenticated";
        messages
                .antMatchers("admin/**","location/**").access(expected)
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo(expected);
    }

    @Test
    public void antMatcherAnyAuthority() {
        messages
                .antMatchers("admin/**","location/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_ROOT")
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("hasAnyAuthority('ROLE_ADMIN','ROLE_ROOT')");
    }

    @Test
    public void antMatcherRememberMe() {
        messages
                .antMatchers("admin/**","location/**").rememberMe()
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("rememberMe");
    }

    @Test
    public void antMatcherAnonymous() {
        messages
                .antMatchers("admin/**","location/**").anonymous()
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("anonymous");
    }

    @Test
    public void antMatcherFullyAuthenticated() {
        messages
                .antMatchers("admin/**","location/**").fullyAuthenticated()
                .anyMessage().denyAll();

        assertThat(getAttribute()).isEqualTo("fullyAuthenticated");
    }

    @Test
    public void antMatcherDenyAll() {
        messages
                .antMatchers("admin/**","location/**").denyAll()
                .anyMessage().permitAll();

        assertThat(getAttribute()).isEqualTo("denyAll");
    }

    private String getAttribute() {
        MessageSecurityMetadataSource source = messages.createMetadataSource();
        Collection<ConfigAttribute> attrs = source.getAttributes(message);
        if(attrs == null) {
            return null;
        }
        assertThat(attrs.size()).isEqualTo(1);
        return attrs.iterator().next().toString();
    }
}