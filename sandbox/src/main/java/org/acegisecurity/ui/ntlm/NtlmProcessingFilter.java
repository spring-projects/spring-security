/*
 * LICENSE IS UNKNOWN (SEE TODO COMMENT LATER IN SOURCE CODE)
 */
package net.sf.acegisecurity.ui.ntlm;

import jcifs.Config;
import jcifs.UniAddress;

import jcifs.http.NtlmSsp;

import jcifs.smb.NtlmChallenge;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;
import net.sf.acegisecurity.providers.smb.NtlmAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import java.util.Iterator;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


/**
 * A reimplementation of the jcifs NtlmHttpFilter suitable for use with the
 * Acegi Security System.
 * 
 * <p>
 * This servlet Filter can be used to negotiate password hashes with MSIE
 * clients using NTLM SSP. This is similar to <code>Authentication:
 * BASIC</code> but weakly encrypted and without requiring the user to
 * re-supply authentication credentials.
 * </p>
 *
 * @author Davide Baroncelli
 * @version $Id$
 */
public class NtlmProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final String CHALLENGE_ATTR_NAME = "NtlmHttpChal";

    //~ Instance fields ========================================================

    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationManager authenticationManager;

    // TODO: Verify licensing, as original contributor reported that large parts of this code where taken from jCifs NtmlHttpFilter: can this be re-licensed to APL (?).
    private Log log = LogFactory.getLog(this.getClass());
    private String defaultDomain;
    private String domainController;
    private boolean loadBalance;

    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @param authenticationEntryPoint The entry point that will be called if
     *        the "transparent" authentication fails for some reason: don't
     *        use the same {@link NtlmProcessingFilterEntryPoint} that is used
     *        in order to commence the NTLM authentication or the user's
     *        browser would probably loop
     */
    public void setAuthenticationEntryPoint(
        AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * DOCUMENT ME!
     *
     * @param defaultDomain The domain that will be specified as part of the
     *        authentication credentials if not specified by the username.
     */
    public void setDefaultDomain(String defaultDomain) {
        this.defaultDomain = defaultDomain;
    }

    /**
     * DOCUMENT ME!
     *
     * @param domainController The domain controller address: if not set the
     *        default domain is used.
     */
    public void setDomainController(String domainController) {
        this.domainController = domainController;
    }

    /**
     * DOCUMENT ME!
     *
     * @param properties A {@link Properties} object whose properties with
     *        names starting with "jcifs." will be set into the jCifs {@link
     *        Config}.
     */
    public void setJCifsProperties(Properties properties) {
        for (Iterator iterator = properties.keySet().iterator();
            iterator.hasNext();) {
            String propertyName = (String) iterator.next();
            String propertyValue = properties.getProperty(propertyName);

            if (propertyName.startsWith("jcifs.")) {
                if (log.isInfoEnabled()) {
                    log.info("setting jcifs property " + propertyName + ":"
                        + propertyValue);
                }

                Config.setProperty(propertyName, propertyValue);
            } else {
                if (log.isInfoEnabled()) {
                    log.info("ignoring non-jcifs property " + propertyName
                        + ":" + propertyValue);
                }
            }
        }
    }

    public void setLoadBalance(boolean loadBalance) {
        this.loadBalance = loadBalance;
    }

    public void afterPropertiesSet() throws Exception {
        // Set jcifs properties we know we want; soTimeout and cachePolicy to 10min
        Config.setProperty("jcifs.smb.client.soTimeout", "300000");
        Config.setProperty("jcifs.netbios.cachePolicy", "1200");

        if (domainController == null) {
            domainController = defaultDomain;
        }

        if (defaultDomain != null) {
            Config.setProperty("jcifs.smb.client.domain", defaultDomain);
        }

        Assert.notNull(authenticationEntryPoint,
            "The authenticationEntryPoint property must be set before "
            + "NtlmProcessingFilter bean initialization");
        Assert.notNull(authenticationManager,
            "The authenticationManager property must be set before "
            + "NtlmProcessingFilter bean initialization");
    }

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        NtlmPasswordAuthentication ntlm = null;
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        try {
            String msg = req.getHeader("Authorization");

            UniAddress dc = null;

            // the "basic" authentication case (both secure + insecure) originally in jcifs NtlmFilter has been
            // refactored out, in order for it to be supported by the acegi BasicProcessingFilter +
            // SmbNtlmAuthenticationProvider ( + SecureChannelProcessor) combination */
            if ((msg != null) && (msg.startsWith("NTLM "))) {
                if (log.isDebugEnabled()) {
                    log.debug("NTLM Authorization header received");
                }

                HttpSession ssn = req.getSession();
                byte[] challenge;

                if (loadBalance) {
                    NtlmChallenge chal = (NtlmChallenge) ssn.getAttribute(CHALLENGE_ATTR_NAME);

                    if (chal == null) {
                        chal = SmbSession.getChallengeForDomain();

                        if (log.isDebugEnabled()) {
                            log.debug(
                                "got load balanced challenge for domain: "
                                + chal);
                        }

                        ssn.setAttribute(CHALLENGE_ATTR_NAME, chal);
                    }

                    dc = chal.dc;
                    challenge = chal.challenge;
                } else {
                    // no challenge in session, here: the server itself keeps the challenge alive for a certain time
                    dc = UniAddress.getByName(domainController, true);
                    challenge = SmbSession.getChallenge(dc);

                    if (log.isDebugEnabled()) {
                        log.debug("domain controller is " + dc
                            + ", challenge is " + challenge);
                    }
                }

                ntlm = NtlmSsp.authenticate(req, resp, challenge);

                if (ntlm == null) {
                    if (log.isDebugEnabled()) {
                        log.debug(
                            "null ntlm authentication results: sending challenge to browser");
                    }

                    return; // this means we must send the challenge to the browser
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("ntlm negotiation complete");
                    }

                    ssn.removeAttribute(CHALLENGE_ATTR_NAME); /* negotiation complete, remove the challenge object */
                }

                NtlmAuthenticationToken ntlmToken = newNtlmAuthenticationToken(ntlm,
                        dc);
                Authentication authResult = authenticationManager.authenticate(ntlmToken);

                if (log.isDebugEnabled()) {
                    log.debug("ntlm token authenticated ");
                }

                successfulAuthentication(req, resp, authResult);
            }
        } catch (AuthenticationException ae) {
            unsuccessfulAuthentication(req, resp, ntlm, ae);

            return;
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}

    protected NtlmAuthenticationToken newNtlmAuthenticationToken(
        NtlmPasswordAuthentication ntlm, UniAddress dc) {
        return new NtlmAuthenticationToken(ntlm, dc);
    }

    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, Authentication authResult) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication success: " + authResult.toString());
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest req,
        HttpServletResponse resp, NtlmPasswordAuthentication ntlm,
        AuthenticationException ae) throws IOException, ServletException {
        if (log.isDebugEnabled()) {
            log.debug("Authentication request for user: " + ntlm.getUsername()
                + " failed: " + ae.toString());
        }

        SecurityContextHolder.getContext().setAuthentication(null);
        authenticationEntryPoint.commence(req, resp,
            new BadCredentialsException(ae.getMessage(), ae));
    }
}
