/* Copyright 2004-2007 Acegi Technology Pty Limited
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

package org.springframework.security.ui.ntlm;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainOrder;
import org.springframework.security.web.SpringSecurityFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import jcifs.Config;
import jcifs.UniAddress;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmChallenge;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbSession;
import jcifs.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * A clean-room implementation for Spring Security of an NTLM HTTP filter
 * leveraging the JCIFS library.
 * <p>
 * NTLM is a Microsoft-developed protocol providing single sign-on capabilities
 * to web applications and other integrated applications.  It allows a web
 * server to automatically discover the username of a browser client when that
 * client is logged into a Windows domain and is using an NTLM-aware browser.
 * A web application can then reuse the user's Windows credentials without
 * having to ask for them again.
 * <p>
 * Because NTLM only provides the username of the Windows client, a Spring
 * Security NTLM deployment must have a <code>UserDetailsService</code> that
 * provides a <code>UserDetails</code> object with the empty string as the
 * password and whatever <code>GrantedAuthority</code> values necessary to
 * pass the <code>FilterSecurityInterceptor</code>.
 * <p>
 * The Spring Security bean configuration file must also place the
 * <code>ExceptionTranslationFilter</code> before this filter in the
 * <code>FilterChainProxy</code> definition.
 *
 * @author Davide Baroncelli
 * @author Edward Smith
 * @version $Id$
 */
public class NtlmProcessingFilter extends SpringSecurityFilter implements InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static Log    logger = LogFactory.getLog(NtlmProcessingFilter.class);

    private static final String    STATE_ATTR = "SpringSecurityNtlm";
    private static final String    CHALLENGE_ATTR = "NtlmChal";
    private static final Integer BEGIN = new Integer(0);
    private static final Integer NEGOTIATE = new Integer(1);
    private static final Integer COMPLETE = new Integer(2);
    private static final Integer DELAYED = new Integer(3);

    //~ Instance fields ================================================================================================

    /** Should the filter load balance among multiple domain controllers, default <code>false</code> */
    private boolean    loadBalance;

    /** Should the domain name be stripped from the username, default <code>true</code> */
    private boolean stripDomain = true;

    /** Should the filter initiate NTLM negotiations, default <code>true</code>    */
    private boolean forceIdentification = true;

    /** Should the filter retry NTLM on authorization failure, default <code>false</code> */
    private boolean retryOnAuthFailure;

    private String    soTimeout;
    private String    cachePolicy;
    private String    defaultDomain;
    private String    domainController;
    private AuthenticationManager authenticationManager;
    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();

    //~ Methods ========================================================================================================

    /**
     * Ensures an <code>AuthenticationManager</code> and authentication failure
     * URL have been provided in the bean configuration file.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");

        // Default to 5 minutes if not already specified
        Config.setProperty("jcifs.smb.client.soTimeout", soTimeout == null ? "300000" : soTimeout);
        // Default to 20 minutes if not already specified
        Config.setProperty("jcifs.netbios.cachePolicy", cachePolicy == null ? "1200" : cachePolicy);

        if (domainController == null) {
            domainController = defaultDomain;
        }
    }

    /**
     * Sets the <code>AuthenticationManager</code> to use.
     *
     * @param authenticationManager the <code>AuthenticationManager</code> to use.
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * The NT domain against which clients should be authenticated. If the SMB
     * client username and password are also set, then preauthentication will
     * be used which is necessary to initialize the SMB signing digest. SMB
     * signatures are required by default on Windows 2003 domain controllers.
     *
     * @param defaultDomain The name of the default domain.
     */
    public void setDefaultDomain(String defaultDomain) {
        this.defaultDomain = defaultDomain;
        Config.setProperty("jcifs.smb.client.domain", defaultDomain);
    }

    /**
     * Sets the SMB client username.
     *
     * @param smbClientUsername The SMB client username.
     */
    public void setSmbClientUsername(String smbClientUsername) {
        Config.setProperty("jcifs.smb.client.username", smbClientUsername);
    }

    /**
     * Sets the SMB client password.
     *
     * @param smbClientPassword The SMB client password.
     */
    public void setSmbClientPassword(String smbClientPassword) {
        Config.setProperty("jcifs.smb.client.password", smbClientPassword);
    }

    /**
     * Sets the SMB client SSN limit. When set to <code>1</code>, every
     * authentication is forced to use a separate transport. This effectively
     * ignores SMB signing requirements, however at the expense of reducing
     * scalability. Preauthentication with a domain, username, and password is
     * the preferred method for working with servers that require signatures.
     *
     * @param smbClientSSNLimit The SMB client SSN limit.
     */
    public void setSmbClientSSNLimit(String smbClientSSNLimit) {
        Config.setProperty("jcifs.smb.client.ssnLimit", smbClientSSNLimit);
    }

    /**
     * Configures JCIFS to use a WINS server.  It is preferred to use a WINS
     * server over a specific domain controller.  Set this property instead of
     * <code>domainController</code> if there is a WINS server available.
     *
     * @param netbiosWINS The WINS server JCIFS will use.
     */
    public void setNetbiosWINS(String netbiosWINS) {
        Config.setProperty("jcifs.netbios.wins", netbiosWINS);
    }

    /**
     * The IP address of any SMB server that should be used to authenticate
     * HTTP clients.
     *
     * @param domainController The IP address of the domain controller.
     */
    public void setDomainController(String domainController) {
        this.domainController = domainController;
    }

    /**
     * If the default domain is specified and the domain controller is not
     * specified, then query for domain controllers by name.  When load
     * balance is <code>true</code>, rotate through the list of domain
     * controllers when authenticating users.
     *
     * @param loadBalance The load balance flag value.
     */
    public void setLoadBalance(boolean loadBalance) {
        this.loadBalance = loadBalance;
    }

    /**
     * Configures <code>NtlmProcessingFilter</code> to strip the Windows
     * domain name from the username when set to <code>true</code>, which
     * is the default value.
     *
     * @param stripDomain The strip domain flag value.
     */
    public void setStripDomain(boolean stripDomain) {
        this.stripDomain = stripDomain;
    }

    /**
     * Sets the <code>jcifs.smb.client.soTimeout</code> property to the
     * timeout value specified in milliseconds. Defaults to 5 minutes
     * if not specified.
     *
     * @param timeout The milliseconds timeout value.
     */
    public void setSoTimeout(String timeout) {
        this.soTimeout = timeout;
    }

    /**
     * Sets the <code>jcifs.netbios.cachePolicy</code> property to the
     * number of seconds a NetBIOS address is cached by JCIFS. Defaults to
     * 20 minutes if not specified.
     *
     * @param numSeconds The number of seconds a NetBIOS address is cached.
     */
    public void setCachePolicy(String numSeconds) {
        this.cachePolicy = numSeconds;
    }

    /**
     * Loads properties starting with "jcifs" into the JCIFS configuration.
     * Any other properties are ignored.
     *
     * @param props The JCIFS properties to set.
     */
    public void setJcifsProperties(Properties props) {
        String name;

        for (Enumeration e=props.keys(); e.hasMoreElements();) {
            name = (String) e.nextElement();
            if (name.startsWith("jcifs.")) {
                Config.setProperty(name, props.getProperty(name));
            }
        }
    }

    /**
     * Returns <code>true</code> if NTLM authentication is forced.
     *
     * @return <code>true</code> if NTLM authentication is forced.
     */
    public boolean isForceIdentification() {
        return this.forceIdentification;
    }

    /**
     * Sets a flag denoting whether NTLM authentication should be forced.
     *
     * @param forceIdentification the force identification flag value to set.
     */
    public void setForceIdentification(boolean forceIdentification) {
        this.forceIdentification = forceIdentification;
    }

    /**
     * Sets a flag denoting whether NTLM should retry whenever authentication
     * fails.  Retry will occur if the credentials are rejected by the domain controller or if an
     * an {@link AuthenticationCredentialsNotFoundException}
     * or {@link InsufficientAuthenticationException} is thrown.
     *
     * @param retryOnFailure the retry on failure flag value to set.
     */
    public void setRetryOnAuthFailure(boolean retryOnFailure) {
        this.retryOnAuthFailure = retryOnFailure;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    protected void doFilterHttp(final HttpServletRequest request,
            final HttpServletResponse response, final FilterChain chain) throws IOException, ServletException {
        final HttpSession session = request.getSession();
        Integer ntlmState = (Integer) session.getAttribute(STATE_ATTR);

        // Start NTLM negotiations the first time through the filter
        if (ntlmState == null) {
            if (forceIdentification) {
                logger.debug("Starting NTLM handshake");
                session.setAttribute(STATE_ATTR, BEGIN);
                throw new NtlmBeginHandshakeException();
            } else {
                logger.debug("NTLM handshake not yet started");
                session.setAttribute(STATE_ATTR, DELAYED);
            }
        }

        // IE will send a Type 1 message to reauthenticate the user during an HTTP POST
        if (ntlmState == COMPLETE && this.reAuthOnIEPost(request))
            ntlmState = BEGIN;

        final String authMessage = request.getHeader("Authorization");
        if (ntlmState != COMPLETE && authMessage != null && authMessage.startsWith("NTLM ")) {
            final UniAddress dcAddress = this.getDCAddress(session);
            if (ntlmState == BEGIN) {
                logger.debug("Processing NTLM Type 1 Message");
                session.setAttribute(STATE_ATTR, NEGOTIATE);
                this.processType1Message(authMessage, session, dcAddress);
            } else {
                logger.debug("Processing NTLM Type 3 Message");
                final NtlmPasswordAuthentication auth = this.processType3Message(authMessage, session, dcAddress);
                logger.debug("NTLM negotiation complete");
                this.logon(session, dcAddress, auth);
                session.setAttribute(STATE_ATTR, COMPLETE);

                // Do not reauthenticate the user in Spring Security during an IE POST
                final Authentication myCurrentAuth = SecurityContextHolder.getContext().getAuthentication();
                if (myCurrentAuth == null || myCurrentAuth instanceof AnonymousAuthenticationToken) {
                    logger.debug("Authenticating user credentials");
                    this.authenticate(request, response, session, auth);
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Returns <code>true</code> if reauthentication is needed on an IE POST.
     */
    private boolean reAuthOnIEPost(final HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return (request.getMethod().equalsIgnoreCase("POST") && ua != null && ua.indexOf("MSIE") != -1);
    }

    /**
     * Creates and returns a Type 2 message from the provided Type 1 message.
     *
     * @param message the Type 1 message to process.
     * @param session the <code>HTTPSession</code> object.
     * @param dcAddress the domain controller address.
     * @throws IOException
     */
    private void processType1Message(final String message, final HttpSession session, final UniAddress dcAddress) throws IOException {
        final Type2Message type2msg = new Type2Message(
                new Type1Message(Base64.decode(message.substring(5))),
                this.getChallenge(session, dcAddress),
                null);
        throw new NtlmType2MessageException(Base64.encode(type2msg.toByteArray()));
    }

    /**
     * Builds and returns an <code>NtlmPasswordAuthentication</code> object
     * from the provided Type 3 message.
     *
     * @param message the Type 3 message to process.
     * @param session the <code>HTTPSession</code> object.
     * @param dcAddress the domain controller address.
     * @return an <code>NtlmPasswordAuthentication</code> object.
     * @throws IOException
     */
    private NtlmPasswordAuthentication processType3Message(final String message, final HttpSession session, final UniAddress dcAddress) throws IOException {
        final Type3Message type3msg = new Type3Message(Base64.decode(message.substring(5)));
        final byte[] lmResponse = (type3msg.getLMResponse() != null) ? type3msg.getLMResponse() : new byte[0];
        final byte[] ntResponse = (type3msg.getNTResponse() != null) ? type3msg.getNTResponse() : new byte[0];
        return new NtlmPasswordAuthentication(
                type3msg.getDomain(),
                type3msg.getUser(),
                this.getChallenge(session, dcAddress),
                lmResponse,
                ntResponse);
    }

    /**
     * Checks the user credentials against the domain controller.
     *
     * @param session the <code>HTTPSession</code> object.
     * @param dcAddress the domain controller address.
     * @param auth the <code>NtlmPasswordAuthentication</code> object.
     * @throws IOException
     */
    private void logon(final HttpSession session, final UniAddress dcAddress, final NtlmPasswordAuthentication auth) throws IOException {
        try {
            SmbSession.logon(dcAddress, auth);
            if (logger.isDebugEnabled()) {
                logger.debug(auth + " successfully authenticated against " + dcAddress);
            }
        } catch(SmbAuthException e) {
            logger.error("Credentials " + auth + " were not accepted by the domain controller " + dcAddress);

            if (retryOnAuthFailure) {
                logger.debug("Restarting NTLM authentication handshake");
                session.setAttribute(STATE_ATTR, BEGIN);
                throw new NtlmBeginHandshakeException();
            }

            throw new BadCredentialsException("Bad NTLM credentials");
        } finally {
            session.removeAttribute(CHALLENGE_ATTR);
        }
    }

    /**
     * Authenticates the user credentials acquired from NTLM against the Spring
     * Security <code>AuthenticationManager</code>.
     *
     * @param request the <code>HttpServletRequest</code> object.
     * @param response the <code>HttpServletResponse</code> object.
     * @param session the <code>HttpSession</code> object.
     * @param auth the <code>NtlmPasswordAuthentication</code> object.
     * @throws IOException
     */
    private void authenticate(final HttpServletRequest request, final HttpServletResponse response, final HttpSession session, final NtlmPasswordAuthentication auth) throws IOException {
        final Authentication authResult;
        final UsernamePasswordAuthenticationToken authRequest;
        final Authentication backupAuth;

        authRequest = new NtlmUsernamePasswordAuthenticationToken(auth, stripDomain);
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        // Place the last username attempted into HttpSession for views
        session.setAttribute(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY, authRequest.getName());

        // Backup the current authentication in case of an AuthenticationException
        backupAuth = SecurityContextHolder.getContext().getAuthentication();

        try {
            // Authenitcate the user with the authentication manager
            authResult = authenticationManager.authenticate(authRequest);
        } catch (AuthenticationException failed) {
            if (logger.isInfoEnabled()) {
                logger.info("Authentication request for user: " + authRequest.getName() + " failed: " + failed.toString());
            }

            // Reset the backup Authentication object and rethrow the AuthenticationException
            SecurityContextHolder.getContext().setAuthentication(backupAuth);

            if (retryOnAuthFailure && (failed instanceof AuthenticationCredentialsNotFoundException || failed instanceof InsufficientAuthenticationException)) {
                logger.debug("Restart NTLM authentication handshake due to AuthenticationException");
                session.setAttribute(STATE_ATTR, BEGIN);
                throw new NtlmBeginHandshakeException();
            }

            throw failed;
        }

        // Set the Authentication object with the valid authentication result
        SecurityContextHolder.getContext().setAuthentication(authResult);
    }

    /**
     * Returns the domain controller address based on the <code>loadBalance</code>
     * setting.
     *
     * @param session the <code>HttpSession</code> object.
     * @return the domain controller address.
     * @throws UnknownHostException
     * @throws SmbException
     */
    private UniAddress getDCAddress(final HttpSession session) throws UnknownHostException, SmbException {
        if (loadBalance) {
            NtlmChallenge chal = (NtlmChallenge) session.getAttribute(CHALLENGE_ATTR);
            if (chal == null) {
                chal = SmbSession.getChallengeForDomain();
                session.setAttribute(CHALLENGE_ATTR, chal);
            }
            return chal.dc;
        }

        return UniAddress.getByName(domainController, true);
    }

    /**
     * Returns the domain controller challenge based on the <code>loadBalance</code>
     * setting.
     *
     * @param session the <code>HttpSession</code> object.
     * @param dcAddress the domain controller address.
     * @return the domain controller challenge.
     * @throws UnknownHostException
     * @throws SmbException
     */
    private byte[] getChallenge(final HttpSession session, final UniAddress dcAddress) throws UnknownHostException, SmbException {
        if (loadBalance) {
            return ((NtlmChallenge) session.getAttribute(CHALLENGE_ATTR)).challenge;
        }

        return SmbSession.getChallenge(dcAddress);
    }

    public int getOrder() {
        return FilterChainOrder.NTLM_FILTER;
    }
}
