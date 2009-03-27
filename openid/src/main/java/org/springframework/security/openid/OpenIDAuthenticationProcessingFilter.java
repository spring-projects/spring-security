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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.web.authentication.AbstractProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationProcessingFilter;
import org.springframework.security.web.util.FilterChainOrder;
import org.springframework.util.StringUtils;


/**
 * Filter which processes OpenID authentication requests.
 * <p>
 * The OpenID authentication involves two stages.
 *
 * <h2>Submission of OpenID identity</h2>
 *
 * The user's OpenID identity is submitted via a login form, just as it would be for a normal form login. At this stage
 * the filter will extract the identity from the submitted request (by default, the parameter is called
 * <tt>j_username</tt>, as it is for form login. It then passes the identity to the configured <tt>OpenIDConsumer</tt>,
 * which returns the URL to which the request should be redirected for authentication. A "return_to" URL is also supplied,
 * which matches the URL processed by this filter, to allow the filter to handle the request once the user has
 * been successfully authenticated. The OpenID server will then authenticate the user and redirect back to the
 * application.
 *
 * <h2>Processing the Redirect from the OpenID Server</h2>
 *
 * Once the user has been authenticated externally, the redirected request will be passed to the <tt>OpenIDConsumer</tt>
 * again for validation. The returned <tt>OpenIDAuthentication</tt> will be passed to the <tt>AuthenticationManager</tt>
 * where it should (normally) be processed by an <tt>OpenIDAuthenticationProvider</tt> in order to load the authorities
 * for the user.
 *
 * @author Robin Bramley
 * @author Ray Krueger
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 * @see OpenIDAuthenticationProvider
 */
public class OpenIDAuthenticationProcessingFilter extends AbstractProcessingFilter {
    //~ Static fields/initializers =====================================================================================

    public static final String DEFAULT_CLAIMED_IDENTITY_FIELD = "j_username";

    //~ Instance fields ================================================================================================

    private OpenIDConsumer consumer;
    private String claimedIdentityFieldName = DEFAULT_CLAIMED_IDENTITY_FIELD;
    private Map<String,String> realmMapping = Collections.emptyMap();

    //~ Constructors ===================================================================================================

    public OpenIDAuthenticationProcessingFilter() {
        super("/j_spring_openid_security_check");
    }

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        if (consumer == null) {
            consumer = new OpenID4JavaConsumer();
        }
    }

    /**
     * Authentication has two phases.
     * <ol>
     * <li>The initial submission of the claimed OpenID. A redirect to the URL returned from the consumer
     * will be performed and null will be returned.</li>
     * <li>The redirection from the OpenID server to the return_to URL, once it has authenticated the user</li>
     * </ol>
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        OpenIDAuthenticationToken token;

        String identity = request.getParameter("openid.identity");

        if (!StringUtils.hasText(identity)) {
            String claimedIdentity = obtainUsername(request);
            // Make the username available to the view
            setLastUsername(claimedIdentity, request);

            try {
                String returnToUrl = buildReturnToUrl(request);
                String realm = lookupRealm(returnToUrl);
                String openIdUrl = consumer.beginConsumption(request, claimedIdentity, returnToUrl, realm);
                if (logger.isDebugEnabled()) {
                    logger.debug("return_to is '" + returnToUrl + "', realm is '" + realm + "'");
                    logger.debug("Redirecting to " + openIdUrl);
                }
                response.sendRedirect(openIdUrl);

                // Indicate to parent class that authentication is continuing.
                return null;
            } catch (OpenIDConsumerException e) {
                logger.debug("Failed to consume claimedIdentity: " + claimedIdentity, e);
                throw new AuthenticationServiceException("Unable to process claimed identity '" + claimedIdentity + "'");
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Supplied OpenID identity is " + identity);
        }

        try {
            token = consumer.endConsumption(request);
        } catch (OpenIDConsumerException oice) {
            throw new AuthenticationServiceException("Consumer error", oice);
        }

        token.setDetails(authenticationDetailsSource.buildDetails(request));

        // delegate to the authentication provider
        Authentication authentication = this.getAuthenticationManager().authenticate(token);

        if (authentication.isAuthenticated()) {
            setLastUsername(token.getIdentityUrl(), request);
        }

        return authentication;
    }

    private void setLastUsername(String username, HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null || getAllowSessionCreation()) {
            request.getSession().setAttribute(AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY, username);
        }
    }

    protected String lookupRealm(String returnToUrl) {
        String mapping = realmMapping.get(returnToUrl);

        if (mapping == null) {
            try {

                URL url = new URL(returnToUrl);
                int port = (url.getPort() == -1) ? 80 : url.getPort();
                StringBuffer realmBuffer = new StringBuffer(returnToUrl.length())
                        .append(url.getProtocol())
                        .append("://")
                        .append(url.getHost())
                        .append(":").append(port)
                        .append("/");
                mapping = realmBuffer.toString();
            } catch (MalformedURLException e) {
                logger.warn("returnToUrl was not a valid URL: [" + returnToUrl + "]", e);
            }
        }

        return mapping;
    }

    /**
     * Builds the <tt>return_to</tt> URL that will be sent to the OpenID service provider.
     * By default returns the URL of the current request.
     *
     * @param request the current request which is being processed by this filter
     * @return The <tt>return_to</tt> URL.
     */
    protected String buildReturnToUrl(HttpServletRequest request) {
        return request.getRequestURL().toString();
    }

    /**
     * Reads the <tt>claimedIdentityFieldName</tt> from the submitted request.
     */
    protected String obtainUsername(HttpServletRequest req) {
        return req.getParameter(claimedIdentityFieldName);
    }

    /**
     * Maps the <tt>return_to url</tt> to a realm, for example:
     * <pre>
     * http://www.example.com/j_spring_openid_security_check -> http://www.example.com/realm</tt>
     * </pre>
     * If no mapping is provided then the returnToUrl will be parsed to extract the protocol, hostname and port followed
     * by a trailing slash.
     * This means that <tt>http://www.example.com/j_spring_openid_security_check</tt> will automatically become
     * <tt>http://www.example.com:80/</tt>
     *
     * @param realmMapping containing returnToUrl -> realm mappings
     */
    public void setRealmMapping(Map<String,String> realmMapping) {
        this.realmMapping = realmMapping;
    }

    /**
     * The name of the request parameter containing the OpenID identity, as submitted from the initial login form.
     *
     * @param claimedIdentityFieldName defaults to "j_username"
     */
    public void setClaimedIdentityFieldName(String claimedIdentityFieldName) {
        this.claimedIdentityFieldName = claimedIdentityFieldName;
    }

    public void setConsumer(OpenIDConsumer consumer) {
        this.consumer = consumer;
    }

    public int getOrder() {
        return FilterChainOrder.OPENID_PROCESSING_FILTER;
    }
}
