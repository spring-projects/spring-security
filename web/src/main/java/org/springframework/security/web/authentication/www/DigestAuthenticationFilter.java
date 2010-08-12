/* Copyright 2004, 2005, 2006 2009 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.www;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.codec.Base64;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;


/**
 * Processes a HTTP request's Digest authorization headers, putting the result into the
 * <code>SecurityContextHolder</code>.
 * <p>
 * For a detailed background on what this filter is designed to process, refer to
 * <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617</a> (which superseded RFC 2069, although this
 * filter support clients that implement either RFC 2617 or RFC 2069).
 * <p>
 * This filter can be used to provide Digest authentication services to both remoting protocol clients (such as
 * Hessian and SOAP) as well as standard user agents (such as Internet Explorer and FireFox).
 * <p>
 * This Digest implementation has been designed to avoid needing to store session state between invocations.
 * All session management information is stored in the "nonce" that is sent to the client by the {@link
 * DigestAuthenticationEntryPoint}.
 * <p>
 * If authentication is successful, the resulting {@link org.springframework.security.core.Authentication Authentication}
 * object will be placed into the <code>SecurityContextHolder</code>.
 * <p>
 * If authentication fails, an {@link org.springframework.security.web.AuthenticationEntryPoint AuthenticationEntryPoint}
 * implementation is called. This must always be {@link DigestAuthenticationEntryPoint}, which will prompt the user
 * to authenticate again via Digest authentication.
 * <p>
 * Note there are limitations to Digest authentication, although it is a more comprehensive and secure solution
 * than Basic authentication. Please see RFC 2617 section 4 for a full discussion on the advantages of Digest
 * authentication over Basic authentication, including commentary on the limitations that it still imposes.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @since 1.0.0
 */
public class DigestAuthenticationFilter extends GenericFilterBean implements MessageSourceAware {
    //~ Static fields/initializers =====================================================================================


    private static final Log logger = LogFactory.getLog(DigestAuthenticationFilter.class);

    //~ Instance fields ================================================================================================

    private AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private DigestAuthenticationEntryPoint authenticationEntryPoint;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private UserCache userCache = new NullUserCache();
    private UserDetailsService userDetailsService;
    private boolean passwordAlreadyEncoded = false;
    private boolean createAuthenticatedToken = false;

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(userDetailsService, "A UserDetailsService is required");
        Assert.notNull(authenticationEntryPoint, "A DigestAuthenticationEntryPoint is required");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Digest ")) {
            chain.doFilter(request, response);

            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Digest Authorization header received from user agent: " + header);
        }

        DigestData digestAuth = new DigestData(header);

        try {
            digestAuth.validateAndDecode(authenticationEntryPoint.getKey(), authenticationEntryPoint.getRealmName());
        } catch (BadCredentialsException e) {
            fail(request, response, e);

            return;
        }

        // Lookup password for presented username
        // NB: DAO-provided password MUST be clear text - not encoded/salted
        // (unless this instance's passwordAlreadyEncoded property is 'false')
        boolean cacheWasUsed = true;
        UserDetails user = userCache.getUserFromCache(digestAuth.getUsername());
        String serverDigestMd5;

        try {
            if (user == null) {
                cacheWasUsed = false;
                user = userDetailsService.loadUserByUsername(digestAuth.getUsername());

                if (user == null) {
                    throw new AuthenticationServiceException(
                            "AuthenticationDao returned null, which is an interface contract violation");
                }

                userCache.putUserInCache(user);
            }

            serverDigestMd5 = digestAuth.calculateServerDigest(user.getPassword(), request.getMethod());

            // If digest is incorrect, try refreshing from backend and recomputing
            if (!serverDigestMd5.equals(digestAuth.getResponse()) && cacheWasUsed) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                            "Digest comparison failure; trying to refresh user from DAO in case password had changed");
                }

                user = userDetailsService.loadUserByUsername(digestAuth.getUsername());
                userCache.putUserInCache(user);
                serverDigestMd5 = digestAuth.calculateServerDigest(user.getPassword(), request.getMethod());
            }

        } catch (UsernameNotFoundException notFound) {
            fail(request, response,
                    new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.usernameNotFound",
                            new Object[]{digestAuth.getUsername()}, "Username {0} not found")));

            return;
        }


        // If digest is still incorrect, definitely reject authentication attempt
        if (!serverDigestMd5.equals(digestAuth.getResponse())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Expected response: '" + serverDigestMd5 + "' but received: '" + digestAuth.getResponse()
                        + "'; is AuthenticationDao returning clear text passwords?");
            }

            fail(request, response,
                    new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.incorrectResponse",
                            "Incorrect response")));
            return;
        }

        // To get this far, the digest must have been valid
        // Check the nonce has not expired
        // We do this last so we can direct the user agent its nonce is stale
        // but the request was otherwise appearing to be valid
        if (digestAuth.isNonceExpired()) {
            fail(request, response,
                    new NonceExpiredException(messages.getMessage("DigestAuthenticationFilter.nonceExpired",
                            "Nonce has expired/timed out")));

            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success for user: '" + digestAuth.getUsername()
                    + "' with response: '" + digestAuth.getResponse() + "'");
        }

        SecurityContextHolder.getContext().setAuthentication(createSuccessfulAuthentication(request, user));

        chain.doFilter(request, response);
    }

    private Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
        UsernamePasswordAuthenticationToken authRequest;
        if (createAuthenticatedToken) {
            authRequest = new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
        }
        else {
            authRequest = new UsernamePasswordAuthenticationToken(user, user.getPassword());
        }

        authRequest.setDetails(authenticationDetailsSource.buildDetails((HttpServletRequest) request));

        return authRequest;
    }

    private void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(null);

        if (logger.isDebugEnabled()) {
            logger.debug(failed);
        }

        authenticationEntryPoint.commence(request, response, failed);
    }

    protected final DigestAuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public UserCache getUserCache() {
        return userCache;
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setAuthenticationEntryPoint(DigestAuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setPasswordAlreadyEncoded(boolean passwordAlreadyEncoded) {
        this.passwordAlreadyEncoded = passwordAlreadyEncoded;
    }

    public void setUserCache(UserCache userCache) {
        this.userCache = userCache;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    /**
     * If you set this property, the Authentication object, which is
     * created after the successful digest authentication will be marked
     * as <b>authenticated</b> and filled with the authorities loaded by
     * the UserDetailsService. It therefore will not be re-authenticated
     * by your AuthenticationProvider. This means, that only the password
     * of the user is checked, but not the flags like isEnabled() or
     * isAccountNonExpired(). You will save some time by enabling this flag,
     * as otherwise your UserDetailsService will be called twice. A more secure
     * option would be to introduce a cache around your UserDetailsService, but
     * if you don't use these flags, you can also safely enable this option.
     *
     * @param createAuthenticatedToken default is false
     */
    public void setCreateAuthenticatedToken(boolean createAuthenticatedToken) {
        this.createAuthenticatedToken = createAuthenticatedToken;
    }

    private class DigestData {
        private final String username;
        private final String realm;
        private final String nonce;
        private final String uri;
        private final String response;
        private final String qop;
        private final String nc;
        private final String cnonce;
        private final String section212response;
        private long nonceExpiryTime;

        DigestData(String header) {
            section212response = header.substring(7);
            String[] headerEntries = DigestAuthUtils.splitIgnoringQuotes(section212response, ',');
            Map<String,String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

            username = headerMap.get("username");
            realm = headerMap.get("realm");
            nonce = headerMap.get("nonce");
            uri = headerMap.get("uri");
            response = headerMap.get("response");
            qop = headerMap.get("qop"); // RFC 2617 extension
            nc = headerMap.get("nc"); // RFC 2617 extension
            cnonce = headerMap.get("cnonce"); // RFC 2617 extension

            if (logger.isDebugEnabled()) {
                logger.debug("Extracted username: '" + username + "'; realm: '" + realm + "'; nonce: '"
                        + nonce + "'; uri: '" + uri + "'; response: '" + response + "'");
            }
        }

        void validateAndDecode(String entryPointKey, String expectedRealm) throws BadCredentialsException {
            // Check all required parameters were supplied (ie RFC 2069)
            if ((username == null) || (realm == null) || (nonce == null) || (uri == null) || (response == null)) {
                throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.missingMandatory",
                            new Object[]{section212response}, "Missing mandatory digest value; received header {0}"));
            }
            // Check all required parameters for an "auth" qop were supplied (ie RFC 2617)
            if ("auth".equals(qop)) {
                if ((nc == null) || (cnonce == null)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("extracted nc: '" + nc + "'; cnonce: '" + cnonce + "'");
                    }

                    throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.missingAuth",
                            new Object[]{section212response}, "Missing mandatory digest value; received header {0}"));
                }
            }

            // Check realm name equals what we expected
            if (!expectedRealm.equals(realm)) {
                throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.incorrectRealm",
                            new Object[]{realm, expectedRealm},
                            "Response realm name '{0}' does not match system realm name of '{1}'"));
            }

            // Check nonce was Base64 encoded (as sent by DigestAuthenticationEntryPoint)
            if (!Base64.isBase64(nonce.getBytes())) {
                throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.nonceEncoding",
                           new Object[]{nonce}, "Nonce is not encoded in Base64; received nonce {0}"));
            }

            // Decode nonce from Base64
            // format of nonce is:
            // base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
            String nonceAsPlainText = new String(Base64.decode(nonce.getBytes()));
            String[] nonceTokens = StringUtils.delimitedListToStringArray(nonceAsPlainText, ":");

            if (nonceTokens.length != 2) {
                throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.nonceNotTwoTokens",
                                new Object[]{nonceAsPlainText}, "Nonce should have yielded two tokens but was {0}"));
            }

            // Extract expiry time from nonce

            try {
                nonceExpiryTime = new Long(nonceTokens[0]).longValue();
            } catch (NumberFormatException nfe) {
                throw new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.nonceNotNumeric",
                                new Object[]{nonceAsPlainText},
                                "Nonce token should have yielded a numeric first token, but was {0}"));
            }

            // Check signature of nonce matches this expiry time
            String expectedNonceSignature = DigestAuthUtils.md5Hex(nonceExpiryTime + ":" + entryPointKey);

            if (!expectedNonceSignature.equals(nonceTokens[1])) {
                new BadCredentialsException(messages.getMessage("DigestAuthenticationFilter.nonceCompromised",
                                new Object[]{nonceAsPlainText}, "Nonce token compromised {0}"));
            }
        }

        String calculateServerDigest(String password, String httpMethod) {
            // Compute the expected response-digest (will be in hex form)

            // Don't catch IllegalArgumentException (already checked validity)
            return DigestAuthUtils.generateDigest(passwordAlreadyEncoded, username, realm, password,
                    httpMethod, uri, qop, nonce, nc, cnonce);
        }

        boolean isNonceExpired() {
            long now = System.currentTimeMillis();
            return nonceExpiryTime < now;
        }

        String getUsername() {
            return username;
        }

        String getResponse() {
            return response;
        }
    }
}
