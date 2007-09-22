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
package org.acegisecurity.ui.openid.consumers;

import org.acegisecurity.providers.openid.OpenIDAuthenticationStatus;
import org.acegisecurity.providers.openid.OpenIDAuthenticationToken;

import org.acegisecurity.ui.openid.OpenIDConsumer;
import org.acegisecurity.ui.openid.OpenIDConsumerException;

import org.openid4java.association.AssociationException;

import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;

import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;

import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * DOCUMENT ME!
 *
 * @author Ray Krueger
 */
public class OpenId4JavaConsumer implements OpenIDConsumer {
    //~ Instance fields ================================================================================================

    private final ConsumerManager consumerManager;

    //~ Constructors ===================================================================================================

    public OpenId4JavaConsumer(ConsumerManager consumerManager) {
        this.consumerManager = consumerManager;
    }

    public OpenId4JavaConsumer() throws ConsumerException {
        this(new ConsumerManager());
    }

    //~ Methods ========================================================================================================

    public String beginConsumption(HttpServletRequest req, String identityUrl, String returnToUrl)
        throws OpenIDConsumerException {
        List discoveries;

        try {
            discoveries = consumerManager.discover(identityUrl);
        } catch (DiscoveryException e) {
            throw new OpenIDConsumerException("Error during discovery", e);
        }

        DiscoveryInformation information = consumerManager.associate(discoveries);
        HttpSession session = req.getSession(true);
        session.setAttribute(DiscoveryInformation.class.getName(), information);

        AuthRequest authReq;

        try {
            authReq = consumerManager.authenticate(information, returnToUrl);
        } catch (MessageException e) {
            throw new OpenIDConsumerException("Error processing ConumerManager authentication", e);
        } catch (ConsumerException e) {
            throw new OpenIDConsumerException("Error processing ConumerManager authentication", e);
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
                                                                        .getAttribute(DiscoveryInformation.class.getName());

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

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();

        if (verified != null) {
            return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, verified.getIdentifier(),
                "some message");
        } else {
            return new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE,
                discovered.getClaimedIdentifier().getIdentifier(),
                "Verification status message: [" + verification.getStatusMsg() + "]");
        }
    }
}
