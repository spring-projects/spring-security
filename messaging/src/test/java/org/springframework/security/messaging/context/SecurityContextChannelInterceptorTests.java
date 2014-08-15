package org.springframework.security.messaging.context;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;

import java.security.Principal;

import static org.fest.assertions.Assertions.assertThat;
import static org.springframework.security.core.context.SecurityContextHolder.*;

@RunWith(MockitoJUnitRunner.class)
public class SecurityContextChannelInterceptorTests {
    @Mock
    MessageChannel channel;
    @Mock
    MessageHandler handler;
    @Mock
    Principal principal;

    MessageBuilder messageBuilder;

    Authentication authentication;

    SecurityContextChannelInterceptor interceptor;

    @Before
    public void setup() {
        authentication = new TestingAuthenticationToken("user","pass", "ROLE_USER");
        messageBuilder = MessageBuilder.withPayload("payload");

        interceptor = new SecurityContextChannelInterceptor();
    }

    @After
    public void cleanup() {
        clearContext();
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullHeader() {
        new SecurityContextChannelInterceptor(null);
    }

    @Test
    public void preSendCustomHeader() throws Exception {
        String headerName = "header";
        interceptor = new SecurityContextChannelInterceptor(headerName);
        messageBuilder.setHeader(headerName, authentication);

        interceptor.preSend(messageBuilder.build(), channel);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
    }

    @Test
    public void preSendUserSet() throws Exception {
        messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);

        interceptor.preSend(messageBuilder.build(), channel);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
    }

    @Test
    public void preSendUserNotAuthentication() throws Exception {
        messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, principal);

        interceptor.preSend(messageBuilder.build(), channel);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void preSendUserNotSet() throws Exception {
        interceptor.preSend(messageBuilder.build(), channel);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void afterSendCompletion() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);

        interceptor.afterSendCompletion(messageBuilder.build(), channel, true, null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void afterSendCompletionNullAuthentication() throws Exception {
        interceptor.afterSendCompletion(messageBuilder.build(), channel, true, null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void beforeHandleUserSet() throws Exception {
        messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);

        interceptor.beforeHandle(messageBuilder.build(), channel, handler);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
    }

    @Test
    public void beforeHandleUserNotAuthentication() throws Exception {
        messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, principal);

        interceptor.beforeHandle(messageBuilder.build(), channel, handler);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void beforeHandleUserNotSet() throws Exception {
        interceptor.beforeHandle(messageBuilder.build(), channel, handler);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }


    @Test
    public void afterMessageHandledUserNotSet() throws Exception {
        interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    public void afterMessageHandled() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);

        interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}