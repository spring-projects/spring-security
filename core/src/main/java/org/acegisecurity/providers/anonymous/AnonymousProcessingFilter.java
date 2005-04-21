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

package net.sf.acegisecurity.providers.anonymous;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;
import net.sf.acegisecurity.providers.dao.memory.UserAttribute;
import net.sf.acegisecurity.ui.basicauth.BasicProcessingFilterEntryPoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Detects if there is no <code>Authentication</code> object in the
 * <code>ContextHolder</code>,  and populates it with one if needed.
 * 
 * <P></p>
 * 
 * <p>
 * In summary, this filter is responsible for processing any request that has a
 * HTTP request header of <code>Authorization</code> with an authentication
 * scheme of <code>Basic</code> and a Base64-encoded
 * <code>username:password</code> token. For example, to authenticate user
 * "Aladdin" with password "open sesame" the following header would be
 * presented:
 * </p>
 * 
 * <p>
 * <code>Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</code>.
 * </p>
 * 
 * <p>
 * This filter can be used to provide BASIC authentication services to both
 * remoting protocol clients (such as Hessian and SOAP) as well as standard
 * user agents (such as Internet Explorer and Netscape).
 * </p>
 * 
 * <P>
 * If authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>ContextHolder</code>.
 * </p>
 * 
 * <p>
 * If authentication fails, an {@link AuthenticationEntryPoint} implementation
 * is called. Usually this should be {@link BasicProcessingFilterEntryPoint},
 * which will prompt the user to authenticate again via BASIC authentication.
 * </p>
 * 
 * <P>
 * Basic authentication is an attractive protocol because it is simple and
 * widely deployed. However, it still transmits a password in clear text and
 * as such is undesirable in many situations. Digest authentication is also
 * provided by Acegi Security and should be used instead of Basic
 * authentication wherever possible. See {@link
 * net.sf.acegisecurity.ui.digestauth.DigestProcessingFilter}.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(AnonymousProcessingFilter.class);

    //~ Instance fields ========================================================

    private String key;
    private UserAttribute userAttribute;

    //~ Methods ================================================================

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        this.userAttribute = userAttributeDefinition;
    }

    public UserAttribute getUserAttribute() {
        return userAttribute;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userAttribute);
        Assert.hasLength(key);
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        SecureContext sc = SecureContextUtils.getSecureContext();

        if (applyAnonymousForThisRequest(request)) {
            if (sc.getAuthentication() == null) {
                sc.setAuthentication(createAuthentication(request));

                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "Replaced ContextHolder with anonymous token: '"
                        + sc.getAuthentication() + "'");
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "ContextHolder not replaced with anonymous token, as ContextHolder already contained: '"
                        + sc.getAuthentication() + "'");
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     *
     * @param arg0 DOCUMENT ME!
     *
     * @throws ServletException DOCUMENT ME!
     */
    public void init(FilterConfig arg0) throws ServletException {}

    /**
     * Enables subclasses to determine whether or not an anonymous
     * authentication token should be setup for this request. This is useful
     * if anonymous authentication should be allowed only for specific IP
     * subnet ranges etc.
     *
     * @param request to assist the method determine request details
     *
     * @return <code>true</code> if the anonymous token should be setup for
     *         this request (provided that the request doesn't already have
     *         some other <code>Authentication</code> inside it), or
     *         <code>false</code> if no anonymous token should be setup for
     *         this request
     */
    protected boolean applyAnonymousForThisRequest(ServletRequest request) {
        return true;
    }

    protected Authentication createAuthentication(ServletRequest request) {
        return new AnonymousAuthenticationToken(key,
            userAttribute.getPassword(), userAttribute.getAuthorities());
    }
}
