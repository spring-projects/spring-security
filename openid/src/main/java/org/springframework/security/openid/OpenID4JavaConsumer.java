/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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


/**
 * @author Ray Krueger
 */
public class OpenID4JavaConsumer implements OpenIDConsumer {
    private static final String DISCOVERY_INFO_KEY = DiscoveryInformation.class.getName();

    //~ Instance fields ================================================================================================

    protected final Log logger = LogFactory.getLog(getClass());

    private final ConsumerManager consumerManager;
    private List<OpenIDAttribute> attributesToFetch = Collections.emptyList();

    //~ Constructors ===================================================================================================

    public OpenID4JavaConsumer() throws ConsumerException {
        this.consumerManager = new ConsumerManager();
    }

    public OpenID4JavaConsumer(List<OpenIDAttribute> attributes) throws ConsumerException {
        this(new ConsumerManager(), attributes);
    }

    public OpenID4JavaConsumer(ConsumerManager consumerManager, List<OpenIDAttribute> attributes)
            throws ConsumerException {
        this.consumerManager = consumerManager;
        this.attributesToFetch = Collections.unmodifiableList(attributes);
    }

    //~ Methods ========================================================================================================

    @SuppressWarnings("unchecked")
    public String beginConsumption(HttpServletRequest req, String identityUrl, String returnToUrl, String realm)
            throws OpenIDConsumerException {
        List<DiscoveryInformation> discoveries;

        try {
            discoveries = consumerManager.discover(identityUrl);
        } catch (DiscoveryException e) {
            throw new OpenIDConsumerException("Error during discovery", e);
        }

        DiscoveryInformation information = consumerManager.associate(discoveries);
        req.getSession().setAttribute(DISCOVERY_INFO_KEY, information);

        AuthRequest authReq;

        try {
            authReq = consumerManager.authenticate(information, returnToUrl, realm);
            if (!attributesToFetch.isEmpty()) {
                FetchRequest fetchRequest = FetchRequest.createFetchRequest();
                for (OpenIDAttribute attr : attributesToFetch) {
                    fetchRequest.addAttribute(attr.getName(), attr.getType(), attr.isRequired(), attr.getCount());
                }
                authReq.addExtension(fetchRequest);
            }
        } catch (MessageException e) {
            throw new OpenIDConsumerException("Error processing ConsumerManager authentication", e);
        } catch (ConsumerException e) {
            throw new OpenIDConsumerException("Error processing ConsumerManager authentication", e);
        }

        return authReq.getDestinationUrl(true);
    }

    @SuppressWarnings("unchecked")
    public OpenIDAuthenticationToken endConsumption(HttpServletRequest request) throws OpenIDConsumerException {
        final boolean debug = logger.isDebugEnabled();
        // extract the parameters from the authentication response
        // (which comes in as a HTTP request from the OpenID provider)
        ParameterList openidResp = new ParameterList(request.getParameterMap());

        // retrieve the previously stored discovery information
        DiscoveryInformation discovered = (DiscoveryInformation) request.getSession().getAttribute(DISCOVERY_INFO_KEY);

        // extract the receiving URL from the HTTP request
        StringBuffer receivingURL = request.getRequestURL();
        String queryString = request.getQueryString();

        if ((queryString != null) && (queryString.length() > 0)) {
            receivingURL.append("?").append(request.getQueryString());
        }

        // verify the response
        VerificationResult verification;

        try {
            verification = consumerManager.verify(receivingURL.toString(), openidResp, discovered);
        } catch (MessageException e) {
            throw new OpenIDConsumerException("Error verifying openid response", e);
        } catch (DiscoveryException e) {
            throw new OpenIDConsumerException("Error verifying openid response", e);
        } catch (AssociationException e) {
            throw new OpenIDConsumerException("Error verifying openid response", e);
        }

        // fetch the attributesToFetch of the response
        Message authSuccess = verification.getAuthResponse();
        List<OpenIDAttribute> attributes = new ArrayList<OpenIDAttribute>(this.attributesToFetch.size());

        if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
            if (debug) {
                logger.debug("Extracting attributes retrieved by attribute exchange");
            }
            try {
                MessageExtension ext = authSuccess.getExtension(AxMessage.OPENID_NS_AX);
                if (ext instanceof FetchResponse) {
                    FetchResponse fetchResp = (FetchResponse) ext;
                    for (OpenIDAttribute attr : attributesToFetch) {
                        List<String> values = fetchResp.getAttributeValues(attr.getName());
                        if (!values.isEmpty()) {
                            OpenIDAttribute fetched = new OpenIDAttribute(attr.getName(), attr.getType(), values);
                            fetched.setRequired(attr.isRequired());
                            attributes.add(fetched);
                        }
                    }
                }
            } catch (MessageException e) {
                attributes.clear();
                throw new OpenIDConsumerException("Attribute retrievel failed", e);
            }
            if (debug) {
                logger.debug("Retrieved attributes" + attributes);
            }
        }

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();

        if (verified == null) {
            return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE,
                    discovered.getClaimedIdentifier().getIdentifier(),
                    "Verification status message: [" + verification.getStatusMsg() + "]", attributes);
        }

        return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, verified.getIdentifier(),
                        "some message", attributes);
    }
}
