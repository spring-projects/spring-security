/* Copyright 2004 Acegi Technology Pty Limited
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

package org.acegisecurity.ui.cas;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.ui.AuthenticationEntryPoint;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.io.IOException;

import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;


/**
 * Used by the <code>SecurityEnforcementFilter</code> to commence
 * authentication via the Yale Central Authentication Service (CAS).
 * 
 * <P>
 * The user's browser will be redirected to the JA-SIG CAS enterprise-wide login
 * page. This page is specified by the <code>loginUrl</code> property. Once
 * login is complete, the CAS login page will redirect to the page indicated
 * by the <code>service</code> property. The <code>service</code> is a HTTP
 * URL belonging to the current application. The <code>service</code> URL is
 * monitored by the {@link CasProcessingFilter}, which will validate the CAS
 * login was successful.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasProcessingFilterEntryPoint implements AuthenticationEntryPoint,
    InitializingBean {
    //~ Instance fields ========================================================

    private ServiceProperties serviceProperties;
    private String loginUrl;

    //~ Methods ================================================================

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * The enterprise-wide CAS login URL. Usually something like
     * <code>https://www.mycompany.com/cas/login</code>.
     *
     * @return the enterprise-wide CAS login URL
     */
    public String getLoginUrl() {
        return loginUrl;
    }

    public void setServiceProperties(ServiceProperties serviceProperties) {
        this.serviceProperties = serviceProperties;
    }

    public ServiceProperties getServiceProperties() {
        return serviceProperties;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(loginUrl, "loginUrl must be specified");
        Assert.notNull(serviceProperties, "serviceProperties must be specified");
    }

    public void commence(ServletRequest request, ServletResponse response,
        AuthenticationException authenticationException)
        throws IOException, ServletException {
        String url;

        if (serviceProperties.isSendRenew()) {
            url = loginUrl + "?renew=true" + "&service="
                + serviceProperties.getService();
        } else {
            url = loginUrl + "?service="
                + URLEncoder.encode(serviceProperties.getService(), "UTF-8");
        }

        ((HttpServletResponse) response).sendRedirect(url);
    }
}
