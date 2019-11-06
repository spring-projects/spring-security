/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.springframework.util.StringUtils;

/**
 * @author Ray Krueger
 * @author Luke Taylor
 */
@SuppressWarnings("unchecked")
public class OpenID4JavaConsumer implements OpenIDConsumer {
	private static final String DISCOVERY_INFO_KEY = DiscoveryInformation.class.getName();
	private static final String ATTRIBUTE_LIST_KEY = "SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST";

	// ~ Instance fields
	// ================================================================================================

	protected final Log logger = LogFactory.getLog(getClass());

	private final ConsumerManager consumerManager;
	private final AxFetchListFactory attributesToFetchFactory;

	// ~ Constructors
	// ===================================================================================================

	public OpenID4JavaConsumer() throws ConsumerException {
		this(new ConsumerManager(), new NullAxFetchListFactory());
	}

	public OpenID4JavaConsumer(AxFetchListFactory attributesToFetchFactory)
			throws ConsumerException {
		this(new ConsumerManager(), attributesToFetchFactory);
	}

	public OpenID4JavaConsumer(ConsumerManager consumerManager,
			AxFetchListFactory attributesToFetchFactory) {
		this.consumerManager = consumerManager;
		this.attributesToFetchFactory = attributesToFetchFactory;
	}

	// ~ Methods
	// ========================================================================================================

	public String beginConsumption(HttpServletRequest req, String identityUrl,
			String returnToUrl, String realm) throws OpenIDConsumerException {
		List<DiscoveryInformation> discoveries;

		try {
			discoveries = consumerManager.discover(identityUrl);
		}
		catch (DiscoveryException e) {
			throw new OpenIDConsumerException("Error during discovery", e);
		}

		DiscoveryInformation information = consumerManager.associate(discoveries);
		req.getSession().setAttribute(DISCOVERY_INFO_KEY, information);

		AuthRequest authReq;

		try {
			authReq = consumerManager.authenticate(information, returnToUrl, realm);

			logger.debug("Looking up attribute fetch list for identifier: " + identityUrl);

			List<OpenIDAttribute> attributesToFetch = attributesToFetchFactory
					.createAttributeList(identityUrl);

			if (!attributesToFetch.isEmpty()) {
				req.getSession().setAttribute(ATTRIBUTE_LIST_KEY, attributesToFetch);
				FetchRequest fetchRequest = FetchRequest.createFetchRequest();
				for (OpenIDAttribute attr : attributesToFetch) {
					if (logger.isDebugEnabled()) {
						logger.debug("Adding attribute " + attr.getType()
								+ " to fetch request");
					}
					fetchRequest.addAttribute(attr.getName(), attr.getType(),
							attr.isRequired(), attr.getCount());
				}
				authReq.addExtension(fetchRequest);
			}
		}
		catch (MessageException | ConsumerException e) {
			throw new OpenIDConsumerException(
					"Error processing ConsumerManager authentication", e);
		}

		return authReq.getDestinationUrl(true);
	}

	public OpenIDAuthenticationToken endConsumption(HttpServletRequest request)
			throws OpenIDConsumerException {
		// extract the parameters from the authentication response
		// (which comes in as a HTTP request from the OpenID provider)
		ParameterList openidResp = new ParameterList(request.getParameterMap());

		// retrieve the previously stored discovery information
		DiscoveryInformation discovered = (DiscoveryInformation) request.getSession()
				.getAttribute(DISCOVERY_INFO_KEY);

		if (discovered == null) {
			throw new OpenIDConsumerException(
					"DiscoveryInformation is not available. Possible causes are lost session or replay attack");
		}

		List<OpenIDAttribute> attributesToFetch = (List<OpenIDAttribute>) request
				.getSession().getAttribute(ATTRIBUTE_LIST_KEY);

		request.getSession().removeAttribute(DISCOVERY_INFO_KEY);
		request.getSession().removeAttribute(ATTRIBUTE_LIST_KEY);

		// extract the receiving URL from the HTTP request
		StringBuffer receivingURL = request.getRequestURL();
		String queryString = request.getQueryString();

		if (StringUtils.hasLength(queryString)) {
			receivingURL.append("?").append(request.getQueryString());
		}

		// verify the response
		VerificationResult verification;

		try {
			verification = consumerManager.verify(receivingURL.toString(), openidResp,
					discovered);
		}
		catch (MessageException | AssociationException | DiscoveryException e) {
			throw new OpenIDConsumerException("Error verifying openid response", e);
		}

		// examine the verification result and extract the verified identifier
		Identifier verified = verification.getVerifiedId();

		if (verified == null) {
			Identifier id = discovered.getClaimedIdentifier();
			return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE,
					id == null ? "Unknown" : id.getIdentifier(),
					"Verification status message: [" + verification.getStatusMsg() + "]",
					Collections.<OpenIDAttribute> emptyList());
		}

		List<OpenIDAttribute> attributes = fetchAxAttributes(
				verification.getAuthResponse(), attributesToFetch);

		return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS,
				verified.getIdentifier(), "some message", attributes);
	}

	List<OpenIDAttribute> fetchAxAttributes(Message authSuccess,
			List<OpenIDAttribute> attributesToFetch) throws OpenIDConsumerException {

		if (attributesToFetch == null
				|| !authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
			return Collections.emptyList();
		}

		logger.debug("Extracting attributes retrieved by attribute exchange");

		List<OpenIDAttribute> attributes = Collections.emptyList();

		try {
			MessageExtension ext = authSuccess.getExtension(AxMessage.OPENID_NS_AX);
			if (ext instanceof FetchResponse) {
				FetchResponse fetchResp = (FetchResponse) ext;
				attributes = new ArrayList<>(attributesToFetch.size());

				for (OpenIDAttribute attr : attributesToFetch) {
					List<String> values = fetchResp.getAttributeValues(attr.getName());
					if (!values.isEmpty()) {
						OpenIDAttribute fetched = new OpenIDAttribute(attr.getName(),
								attr.getType(), values);
						fetched.setRequired(attr.isRequired());
						attributes.add(fetched);
					}
				}
			}
		}
		catch (MessageException e) {
			throw new OpenIDConsumerException("Attribute retrieval failed", e);
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Retrieved attributes" + attributes);
		}

		return attributes;
	}
}
