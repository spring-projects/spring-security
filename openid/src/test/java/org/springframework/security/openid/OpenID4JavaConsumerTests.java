/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.openid;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to
 * migrate</a> to <a href="https://openid.net/connect/">OpenID Connect</a>, which is
 * supported by <code>spring-security-oauth2</code>.
 */
@Deprecated
public class OpenID4JavaConsumerTests {

	List<OpenIDAttribute> attributes = Arrays.asList(new OpenIDAttribute("a", "b"),
			new OpenIDAttribute("b", "b", Arrays.asList("c")));

	@SuppressWarnings("deprecation")
	@Test
	public void beginConsumptionCreatesExpectedSessionData() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		AuthRequest authReq = mock(AuthRequest.class);
		DiscoveryInformation di = mock(DiscoveryInformation.class);
		given(mgr.authenticate(any(DiscoveryInformation.class), any(), any())).willReturn(authReq);
		given(mgr.associate(any())).willReturn(di);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new MockAttributesFactory());
		MockHttpServletRequest request = new MockHttpServletRequest();
		consumer.beginConsumption(request, "", "", "");
		assertThat(request.getSession().getAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST"))
				.isEqualTo(this.attributes);
		assertThat(request.getSession().getAttribute(DiscoveryInformation.class.getName())).isEqualTo(di);
		// Check with empty attribute fetch list
		consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		request = new MockHttpServletRequest();
		consumer.beginConsumption(request, "", "", "");
	}

	@Test
	public void discoveryExceptionRaisesOpenIDException() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		given(mgr.discover(any())).willThrow(new DiscoveryException("msg"));
		assertThatExceptionOfType(OpenIDConsumerException.class)
				.isThrownBy(() -> consumer.beginConsumption(new MockHttpServletRequest(), "", "", ""));
	}

	@Test
	public void messageOrConsumerAuthenticationExceptionRaisesOpenIDException() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		given(mgr.authenticate(ArgumentMatchers.<DiscoveryInformation>any(), any(), any()))
				.willThrow(new MessageException("msg"), new ConsumerException("msg"));
		assertThatExceptionOfType(OpenIDConsumerException.class)
				.isThrownBy(() -> consumer.beginConsumption(new MockHttpServletRequest(), "", "", ""));
		assertThatExceptionOfType(OpenIDConsumerException.class)
				.isThrownBy(() -> consumer.beginConsumption(new MockHttpServletRequest(), "", "", ""));
	}

	@Test
	public void failedVerificationReturnsFailedAuthenticationStatus() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		VerificationResult vr = mock(VerificationResult.class);
		DiscoveryInformation di = mock(DiscoveryInformation.class);
		given(mgr.verify(any(), any(ParameterList.class), any(DiscoveryInformation.class))).willReturn(vr);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession().setAttribute(DiscoveryInformation.class.getName(), di);
		OpenIDAuthenticationToken auth = consumer.endConsumption(request);
		assertThat(auth.getStatus()).isEqualTo(OpenIDAuthenticationStatus.FAILURE);
	}

	@Test
	public void verificationExceptionsRaiseOpenIDException() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		given(mgr.verify(any(), any(ParameterList.class), any(DiscoveryInformation.class)))
				.willThrow(new MessageException(""), new AssociationException(""), new DiscoveryException(""));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("x=5");
		assertThatExceptionOfType(OpenIDConsumerException.class).isThrownBy(() -> consumer.endConsumption(request));
		assertThatExceptionOfType(OpenIDConsumerException.class).isThrownBy(() -> consumer.endConsumption(request));
		assertThatExceptionOfType(OpenIDConsumerException.class).isThrownBy(() -> consumer.endConsumption(request));
	}

	@SuppressWarnings("serial")
	@Test
	public void successfulVerificationReturnsExpectedAuthentication() throws Exception {
		ConsumerManager mgr = mock(ConsumerManager.class);
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(mgr, new NullAxFetchListFactory());
		VerificationResult vr = mock(VerificationResult.class);
		DiscoveryInformation di = mock(DiscoveryInformation.class);
		Identifier id = (Identifier) () -> "id";
		Message msg = mock(Message.class);
		given(mgr.verify(any(), any(ParameterList.class), any(DiscoveryInformation.class))).willReturn(vr);
		given(vr.getVerifiedId()).willReturn(id);
		given(vr.getAuthResponse()).willReturn(msg);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession().setAttribute(DiscoveryInformation.class.getName(), di);
		request.getSession().setAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST", this.attributes);
		OpenIDAuthenticationToken auth = consumer.endConsumption(request);
		assertThat(auth.getStatus()).isEqualTo(OpenIDAuthenticationStatus.SUCCESS);
	}

	@Test
	public void fetchAttributesReturnsExpectedValues() throws Exception {
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(new NullAxFetchListFactory());
		Message msg = mock(Message.class);
		FetchResponse fr = mock(FetchResponse.class);
		given(msg.hasExtension(AxMessage.OPENID_NS_AX)).willReturn(true);
		given(msg.getExtension(AxMessage.OPENID_NS_AX)).willReturn(fr);
		given(fr.getAttributeValues("a")).willReturn(Arrays.asList("x", "y"));
		List<OpenIDAttribute> fetched = consumer.fetchAxAttributes(msg, this.attributes);
		assertThat(fetched).hasSize(1);
		assertThat(fetched.get(0).getValues()).hasSize(2);
	}

	@Test
	public void messageExceptionFetchingAttributesRaisesOpenIDException() throws Exception {
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(new NullAxFetchListFactory());
		Message msg = mock(Message.class);
		FetchResponse fr = mock(FetchResponse.class);
		given(msg.hasExtension(AxMessage.OPENID_NS_AX)).willReturn(true);
		given(msg.getExtension(AxMessage.OPENID_NS_AX)).willThrow(new MessageException(""));
		given(fr.getAttributeValues("a")).willReturn(Arrays.asList("x", "y"));
		assertThatExceptionOfType(OpenIDConsumerException.class)
				.isThrownBy(() -> consumer.fetchAxAttributes(msg, this.attributes));
	}

	@Test
	public void missingDiscoveryInformationThrowsException() throws Exception {
		OpenID4JavaConsumer consumer = new OpenID4JavaConsumer(new NullAxFetchListFactory());
		assertThatExceptionOfType(OpenIDConsumerException.class)
				.isThrownBy(() -> consumer.endConsumption(new MockHttpServletRequest()));
	}

	@Test
	public void additionalConstructorsWork() throws Exception {
		new OpenID4JavaConsumer();
		new OpenID4JavaConsumer(new MockAttributesFactory());
	}

	private class MockAttributesFactory implements AxFetchListFactory {

		@Override
		public List<OpenIDAttribute> createAttributeList(String identifier) {
			return OpenID4JavaConsumerTests.this.attributes;
		}

	}

}
