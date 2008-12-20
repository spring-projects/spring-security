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

package org.springframework.security.ui.cas;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;


/**
 * Used by the <code>ExceptionTranslationFilter</code> to commence authentication via the JA-SIG Central
 * Authentication Service (CAS).
 * <p>
 * The user's browser will be redirected to the JA-SIG CAS enterprise-wide login page. 
 * This page is specified by the <code>loginUrl</code> property. Once login is complete, the CAS login page will
 * redirect to the page indicated by the <code>service</code> property. The <code>service</code> is a HTTP URL
 * belonging to the current application. The <code>service</code> URL is monitored by the {@link CasProcessingFilter},
 * which will validate the CAS login was successful.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @version $Id$
 */
public class CasProcessingFilterEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    //~ Instance fields ================================================================================================

    private ServiceProperties serviceProperties;
    private String loginUrl;

    /**
     * Determines whether the Service URL should include the session id for the specific user.  As of CAS 3.0.5, the
     * session id will automatically be stripped.  However, older versions of CAS (i.e. CAS 2), do not automatically
     * strip the session identifier (this is a bug on the part of the older server implementations), so an option to
     * disable the session encoding is provided for backwards compatibility.
     *
     * By default, encoding is enabled.
     */
    private boolean encodeServiceUrlWithSessionId = true;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(this.loginUrl, "loginUrl must be specified");
        Assert.notNull(this.serviceProperties, "serviceProperties must be specified");
    }

    public void commence(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse,
            final AuthenticationException authenticationException) throws IOException, ServletException {

        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final String urlEncodedService = CommonUtils.constructServiceUrl(null, response, this.serviceProperties.getService(), null, "ticket", this.encodeServiceUrlWithSessionId);
        final String redirectUrl = CommonUtils.constructRedirectUrl(this.loginUrl, "service", urlEncodedService, this.serviceProperties.isSendRenew(), false);

        response.sendRedirect(redirectUrl);
    }

    /**
     * The enterprise-wide CAS login URL. Usually something like
     * <code>https://www.mycompany.com/cas/login</code>.
     *
     * @return the enterprise-wide CAS login URL
     */
    public String getLoginUrl() {
        return this.loginUrl;
    }

    public ServiceProperties getServiceProperties() {
        return this.serviceProperties;
    }

    public void setLoginUrl(final String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public void setServiceProperties(final ServiceProperties serviceProperties) {
        this.serviceProperties = serviceProperties;
    }

    public void setEncodeServiceUrlWithSessionId(final boolean encodeServiceUrlWithSessionId) {
        this.encodeServiceUrlWithSessionId = encodeServiceUrlWithSessionId;
    }
}
