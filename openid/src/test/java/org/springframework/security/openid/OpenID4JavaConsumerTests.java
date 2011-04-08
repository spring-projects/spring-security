package org.springframework.security.openid;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import static org.powermock.api.mockito.PowerMockito.*;

import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.junit.*;
import org.junit.runner.RunWith;

import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;

import org.springframework.mock.web.MockHttpServletRequest;

import java.util.*;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({MultiThreadedHttpConnectionManager.class,Message.class})
public class OpenID4JavaConsumerTests {
    List<OpenIDAttribute> attributes = Arrays.asList(new OpenIDAttribute("a","b"), new OpenIDAttribute("b","b", Arrays.asList("c")));

    @Test
    public void beginConsumptionCreatesExpectedSessionData() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        AuthRequest authReq = mock(AuthRequest.class);
        DiscoveryInformation di = mock(DiscoveryInformation.class);

        when(mgr.authenticate(any(DiscoveryInformation.class), anyString(), anyString())).thenReturn(authReq);
        when(mgr.associate(anyList())).thenReturn(di);

        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, attributes);

        MockHttpServletRequest request = new MockHttpServletRequest();
        consumer.beginConsumption(request, "", "", "");

        assertEquals(attributes, request.getSession().getAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST"));
        assertSame(di, request.getSession().getAttribute(DiscoveryInformation.class.getName()));

        // Check with empty attribute fetch list
        consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());

        request = new MockHttpServletRequest();
        consumer.beginConsumption(request, "", "", "");
    }

    @Test(expected = OpenIDConsumerException.class)
    public void discoveryExceptionRaisesOpenIDException() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
        when(mgr.discover(anyString())).thenThrow(new DiscoveryException("msg"));
        consumer.beginConsumption(new MockHttpServletRequest(), "", "", "");
    }

    @Test
    public void messageOrConsumerAuthenticationExceptionRaisesOpenIDException() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());

        when(mgr.authenticate(any(DiscoveryInformation.class), anyString(), anyString()))
                .thenThrow(new MessageException("msg"), new ConsumerException("msg"));

        try {
            consumer.beginConsumption(new MockHttpServletRequest(), "", "", "");
            fail();
        } catch (OpenIDConsumerException expected) {
        }

        try {
            consumer.beginConsumption(new MockHttpServletRequest(), "", "", "");
            fail();
        } catch (OpenIDConsumerException expected) {
        }
    }

    @Test
    public void failedVerificationReturnsFailedAuthenticationStatus() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
        VerificationResult vr = mock(VerificationResult.class);
        DiscoveryInformation di = mock(DiscoveryInformation.class);

        when(mgr.verify(anyString(), any(ParameterList.class), any(DiscoveryInformation.class))).thenReturn(vr);

        MockHttpServletRequest request = new MockHttpServletRequest();

        request.getSession().setAttribute(DiscoveryInformation.class.getName(), di);

        OpenIDAuthenticationToken auth = consumer.endConsumption(request);

        assertEquals(OpenIDAuthenticationStatus.FAILURE, auth.getStatus());
    }

    @Test
    public void verificationExceptionsRaiseOpenIDException() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());

        when(mgr.verify(anyString(), any(ParameterList.class), any(DiscoveryInformation.class)))
                .thenThrow(new MessageException(""))
                .thenThrow(new AssociationException(""))
                .thenThrow(new DiscoveryException(""));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("x=5");

        try {
            consumer.endConsumption(request);
            fail();
        } catch (OpenIDConsumerException expected) {
        }

        try {
            consumer.endConsumption(request);
            fail();
        } catch (OpenIDConsumerException expected) {
        }

        try {
            consumer.endConsumption(request);
            fail();
        } catch (OpenIDConsumerException expected) {
        }

    }

    @Test
    public void successfulVerificationReturnsExpectedAuthentication() throws Exception {
        ConsumerManager mgr = mock(ConsumerManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
        VerificationResult vr = mock(VerificationResult.class);
        DiscoveryInformation di = mock(DiscoveryInformation.class);
        Identifier id = new Identifier() {
            public String getIdentifier() {
                return "id";
            }
        };
        Message msg = mock(Message.class);

        when(mgr.verify(anyString(), any(ParameterList.class), any(DiscoveryInformation.class))).thenReturn(vr);
        when(vr.getVerifiedId()).thenReturn(id);
        when(vr.getAuthResponse()).thenReturn(msg);

        MockHttpServletRequest request = new MockHttpServletRequest();

        request.getSession().setAttribute(DiscoveryInformation.class.getName(), di);
        request.getSession().setAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST", attributes);

        OpenIDAuthenticationToken auth = consumer.endConsumption(request);

        assertEquals(OpenIDAuthenticationStatus.SUCCESS, auth.getStatus());
    }

    @Test
    public void fetchAttributesReturnsExpectedValues() throws Exception {
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(new NullAxFetchListFactory());
        Message msg = mock(Message.class);
        FetchResponse fr = mock(FetchResponse.class);
        when(msg.hasExtension(AxMessage.OPENID_NS_AX)).thenReturn(true);
        when(msg.getExtension(AxMessage.OPENID_NS_AX)).thenReturn(fr);
        when(fr.getAttributeValues("a")).thenReturn(Arrays.asList("x","y"));

        List<OpenIDAttribute> fetched = consumer.fetchAxAttributes(msg, attributes);

        assertEquals(1, fetched.size());
        assertEquals(2, fetched.get(0).getValues().size());
    }

    @Test(expected = OpenIDConsumerException.class)
    public void messageExceptionFetchingAttributesRaisesOpenIDException() throws Exception {
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(new NullAxFetchListFactory());
        Message msg = mock(Message.class);
        FetchResponse fr = mock(FetchResponse.class);
        when(msg.hasExtension(AxMessage.OPENID_NS_AX)).thenReturn(true);
        when(msg.getExtension(AxMessage.OPENID_NS_AX)).thenThrow(new MessageException(""));
        when(fr.getAttributeValues("a")).thenReturn(Arrays.asList("x","y"));

        consumer.fetchAxAttributes(msg, attributes);
    }


    @Test
    public void additionalConstructorsWork() throws Exception {
        new OpenID4JavaConsumer();
        new OpenID4JavaConsumer(attributes);
    }

    @Test
    public void afterPropertiesSetRegister() throws Exception {
        mockStatic(Message.class);
        new OpenID4JavaConsumer().afterPropertiesSet();

        verifyStatic();
        Message.addExtensionFactory(SignedAxMessageExtensionFactory.class);
    }

    @Test
    public void afterPropertiesSetSkipRegister() throws Exception {
        mockStatic(Message.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer();
        consumer.setSkipSignedAxMessageRegistration(true);
        consumer.afterPropertiesSet();

        verifyStatic(never());
        Message.addExtensionFactory(SignedAxMessageExtensionFactory.class);
    }

    @Test
    public void destroyInvokesShutdownAll() throws Exception {
        mockStatic(MultiThreadedHttpConnectionManager.class);
        new OpenID4JavaConsumer().destroy();

        verifyStatic();
        MultiThreadedHttpConnectionManager.shutdownAll();
    }

    @Test
    public void destroyOverrideShutdownAll() throws Exception {
        mockStatic(MultiThreadedHttpConnectionManager.class);
        OpenID4JavaConsumer consumer = new OpenID4JavaConsumer();
        consumer.setSkipShutdownConnectionManager(true);

        consumer.destroy();

        verifyStatic(never());
        MultiThreadedHttpConnectionManager.shutdownAll();
    }
}
