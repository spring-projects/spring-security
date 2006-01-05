/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.ui.digestauth;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.UserCache;
import org.acegisecurity.providers.dao.cache.NullUserCache;
import org.acegisecurity.ui.WebAuthenticationDetails;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.util.StringSplitUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


/**
 * Processes a HTTP request's Digest authorization headers, putting the result
 * into the <code>SecurityContextHolder</code>.
 * 
 * <p>
 * For a detailed background on what this filter is designed to process, refer
 * to <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617</a> (which
 * superseded RFC 2069, although this filter support clients that implement
 * either RFC 2617 or RFC 2069).
 * </p>
 * 
 * <p>
 * This filter can be used to provide Digest authentication services to both
 * remoting protocol clients (such as Hessian and SOAP) as well as standard
 * user agents (such as Internet Explorer and FireFox).
 * </p>
 * 
 * <p>
 * This Digest implementation has been designed to avoid needing to store
 * session state between invocations. All session management information is
 * stored in the "nonce" that is sent to the client by the {@link
 * DigestProcessingFilterEntryPoint}.
 * </p>
 * 
 * <P>
 * If authentication is successful, the resulting {@link
 * org.acegisecurity.Authentication Authentication} object will be placed into
 * the <code>SecurityContextHolder</code>.
 * </p>
 * 
 * <p>
 * If authentication fails, an {@link
 * org.acegisecurity.intercept.web.AuthenticationEntryPoint
 * AuthenticationEntryPoint} implementation is called. This must always be
 * {@link DigestProcessingFilterEntryPoint}, which will prompt the user to
 * authenticate again via Digest authentication.
 * </p>
 * 
 * <p>
 * Note there are limitations to Digest authentication, although it is a more
 * comprehensive and secure solution than Basic authentication. Please see RFC
 * 2617 section 4 for a full discussion on the advantages of Digest
 * authentication over Basic authentication, including commentary on the
 * limitations that it still imposes.
 * </p>
 * 
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 */
public class DigestProcessingFilter implements Filter, InitializingBean,
    MessageSourceAware {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(DigestProcessingFilter.class);

    //~ Instance fields ========================================================

    private UserDetailsService userDetailsService;
    private DigestProcessingFilterEntryPoint authenticationEntryPoint;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private UserCache userCache = new NullUserCache();
    private boolean passwordAlreadyEncoded = false;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userDetailsService, "A UserDetailsService is required");
        Assert.notNull(authenticationEntryPoint,
            "A DigestProcessingFilterEntryPoint is required");
    }

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        String header = httpRequest.getHeader("Authorization");

        if (logger.isDebugEnabled()) {
            logger.debug("Authorization header received from user agent: "
                + header);
        }

        if ((header != null) && header.startsWith("Digest ")) {
            String section212response = header.substring(7);

            String[] headerEntries = StringUtils.commaDelimitedListToStringArray(section212response);
            Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries,
                    "=", "\"");

            String username = (String) headerMap.get("username");
            String realm = (String) headerMap.get("realm");
            String nonce = (String) headerMap.get("nonce");
            String uri = (String) headerMap.get("uri");
            String responseDigest = (String) headerMap.get("response");
            String qop = (String) headerMap.get("qop"); // RFC 2617 extension
            String nc = (String) headerMap.get("nc"); // RFC 2617 extension
            String cnonce = (String) headerMap.get("cnonce"); // RFC 2617 extension

            // Check all required parameters were supplied (ie RFC 2069)
            if ((username == null) || (realm == null) || (nonce == null)
                || (uri == null) || (response == null)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("extracted username: '" + username
                        + "'; realm: '" + username + "'; nonce: '" + username
                        + "'; uri: '" + username + "'; response: '" + username
                        + "'");
                }

                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.missingMandatory",
                            new Object[] {section212response},
                            "Missing mandatory digest value; received header {0}")));

                return;
            }

            // Check all required parameters for an "auth" qop were supplied (ie RFC 2617)
            if ("auth".equals(qop)) {
                if ((nc == null) || (cnonce == null)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("extracted nc: '" + nc + "'; cnonce: '"
                            + cnonce + "'");
                    }

                    fail(request, response,
                        new BadCredentialsException(messages.getMessage(
                                "DigestProcessingFilter.missingAuth",
                                new Object[] {section212response},
                                "Missing mandatory digest value; received header {0}")));

                    return;
                }
            }

            // Check realm name equals what we expected
            if (!this.getAuthenticationEntryPoint().getRealmName().equals(realm)) {
                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.incorrectRealm",
                            new Object[] {realm, this.getAuthenticationEntryPoint()
                                                     .getRealmName()},
                            "Response realm name '{0}' does not match system realm name of '{1}'")));

                return;
            }

            // Check nonce was a Base64 encoded (as sent by DigestProcessingFilterEntryPoint)
            if (!Base64.isArrayByteBase64(nonce.getBytes())) {
                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.nonceEncoding",
                            new Object[] {nonce},
                            "Nonce is not encoded in Base64; received nonce {0}")));

                return;
            }

            // Decode nonce from Base64
            // format of nonce is:  
            //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
            String nonceAsPlainText = new String(Base64.decodeBase64(
                        nonce.getBytes()));
            String[] nonceTokens = StringUtils.delimitedListToStringArray(nonceAsPlainText,
                    ":");

            if (nonceTokens.length != 2) {
                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.nonceNotTwoTokens",
                            new Object[] {nonceAsPlainText},
                            "Nonce should have yielded two tokens but was {0}")));

                return;
            }

            // Extract expiry time from nonce
            long nonceExpiryTime;

            try {
                nonceExpiryTime = new Long(nonceTokens[0]).longValue();
            } catch (NumberFormatException nfe) {
                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.nonceNotNumeric",
                            new Object[] {nonceAsPlainText},
                            "Nonce token should have yielded a numeric first token, but was {0}")));

                return;
            }

            // Check signature of nonce matches this expiry time
            String expectedNonceSignature = DigestUtils.md5Hex(nonceExpiryTime
                    + ":" + this.getAuthenticationEntryPoint().getKey());

            if (!expectedNonceSignature.equals(nonceTokens[1])) {
                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.nonceCompromised",
                            new Object[] {nonceAsPlainText},
                            "Nonce token compromised {0}")));

                return;
            }

            // Lookup password for presented username
            // NB: DAO-provided password MUST be clear text - not encoded/salted
            // (unless this instance's passwordAlreadyEncoded property is 'false')
            boolean loadedFromDao = false;
            UserDetails user = userCache.getUserFromCache(username);

            if (user == null) {
                loadedFromDao = true;

                try {
                    user = userDetailsService.loadUserByUsername(username);
                } catch (UsernameNotFoundException notFound) {
                    fail(request, response,
                        new BadCredentialsException(messages.getMessage(
                                "DigestProcessingFilter.usernameNotFound",
                                new Object[] {username},
                                "Username {0} not found")));

                    return;
                }

                if (user == null) {
                    throw new AuthenticationServiceException(
                        "AuthenticationDao returned null, which is an interface contract violation");
                }

                userCache.putUserInCache(user);
            }

            // Compute the expected response-digest (will be in hex form)
            String serverDigestMd5;

            // Don't catch IllegalArgumentException (already checked validity)
            serverDigestMd5 = generateDigest(passwordAlreadyEncoded, username,
                    realm, user.getPassword(),
                    ((HttpServletRequest) request).getMethod(), uri, qop,
                    nonce, nc, cnonce);

            // If digest is incorrect, try refreshing from backend and recomputing
            if (!serverDigestMd5.equals(responseDigest) && !loadedFromDao) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "Digest comparison failure; trying to refresh user from DAO in case password had changed");
                }

                try {
                    user = userDetailsService.loadUserByUsername(username);
                } catch (UsernameNotFoundException notFound) {
                    // Would very rarely happen, as user existed earlier
                    fail(request, response,
                        new BadCredentialsException(messages.getMessage(
                                "DigestProcessingFilter.usernameNotFound",
                                new Object[] {username},
                                "Username {0} not found")));
                }

                userCache.putUserInCache(user);

                // Don't catch IllegalArgumentException (already checked validity)
                serverDigestMd5 = generateDigest(passwordAlreadyEncoded,
                        username, realm, user.getPassword(),
                        ((HttpServletRequest) request).getMethod(), uri, qop,
                        nonce, nc, cnonce);
            }

            // If digest is still incorrect, definitely reject authentication attempt
            if (!serverDigestMd5.equals(responseDigest)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Expected response: '" + serverDigestMd5
                        + "' but received: '" + responseDigest
                        + "'; is AuthenticationDao returning clear text passwords?");
                }

                fail(request, response,
                    new BadCredentialsException(messages.getMessage(
                            "DigestProcessingFilter.incorrectResponse",
                            "Incorrect response")));

                return;
            }

            // To get this far, the digest must have been valid
            // Check the nonce has not expired
            // We do this last so we can direct the user agent its nonce is stale
            // but the request was otherwise appearing to be valid
            if (nonceExpiryTime < System.currentTimeMillis()) {
                fail(request, response,
                    new NonceExpiredException(messages.getMessage(
                            "DigestProcessingFilter.nonceExpired",
                            "Nonce has expired/timed out")));

                return;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Authentication success for user: '" + username
                    + "' with response: '" + responseDigest + "'");
            }

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(user,
                    user.getPassword());
            authRequest.setDetails(new WebAuthenticationDetails(httpRequest));

            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }

        chain.doFilter(request, response);
    }

    public static String encodePasswordInA1Format(String username,
        String realm, String password) {
        String a1 = username + ":" + realm + ":" + password;
        String a1Md5 = new String(DigestUtils.md5Hex(a1));

        return a1Md5;
    }

    private void fail(ServletRequest request, ServletResponse response,
        AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(null);

        if (logger.isDebugEnabled()) {
            logger.debug(failed);
        }

        authenticationEntryPoint.commence(request, response, failed);
    }

    /**
     * Computes the <code>response</code> portion of a Digest authentication
     * header. Both the server and user agent should compute the
     * <code>response</code> independently. Provided as a static method to
     * simplify the coding of user agents.
     *
     * @param passwordAlreadyEncoded true if the password argument is already encoded in
     *                               the correct format. False if it is plain text.
     * @param username the user's login name.
     * @param realm the name of the realm.
     * @param password the user's password in plaintext or ready-encoded.
     * @param httpMethod the HTTP request method (GET, POST etc.)
     * @param uri the request URI.
     * @param qop the qop directive, or null if not set.
     * @param nonce the nonce supplied by the server
     * @param nc the "nonce-count" as defined in RFC 2617.
     * @param cnonce opaque string supplied by the client when qop is set.
     *
     * @return the MD5 of the digest authentication response, encoded in hex
     *
     * @throws IllegalArgumentException if the supplied qop value is unsupported.
     */
    public static String generateDigest(boolean passwordAlreadyEncoded,
        String username, String realm, String password, String httpMethod,
        String uri, String qop, String nonce, String nc, String cnonce)
        throws IllegalArgumentException {
        String a1Md5 = null;
        String a2 = httpMethod + ":" + uri;
        String a2Md5 = new String(DigestUtils.md5Hex(a2));

        if (passwordAlreadyEncoded) {
            a1Md5 = password;
        } else {
            a1Md5 = encodePasswordInA1Format(username, realm, password);
        }

        String digest;

        if (qop == null) {
            // as per RFC 2069 compliant clients (also reaffirmed by RFC 2617)
            digest = a1Md5 + ":" + nonce + ":" + a2Md5;
        } else if ("auth".equals(qop)) {
            // As per RFC 2617 compliant clients
            digest = a1Md5 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop
                + ":" + a2Md5;
        } else {
            throw new IllegalArgumentException(
                "This method does not support a qop: '" + qop + "'");
        }

        String digestMd5 = new String(DigestUtils.md5Hex(digest));

        return digestMd5;
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public DigestProcessingFilterEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public UserCache getUserCache() {
        return userCache;
    }

    public void init(FilterConfig ignored) throws ServletException {}

    public void setUserDetailsService(UserDetailsService authenticationDao) {
        this.userDetailsService = authenticationDao;
    }

    public void setAuthenticationEntryPoint(
        DigestProcessingFilterEntryPoint authenticationEntryPoint) {
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
}
