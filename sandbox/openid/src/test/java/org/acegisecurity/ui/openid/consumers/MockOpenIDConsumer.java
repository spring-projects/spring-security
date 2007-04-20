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

import org.acegisecurity.providers.openid.OpenIDAuthenticationToken;

import org.acegisecurity.ui.openid.OpenIDConsumer;
import org.acegisecurity.ui.openid.OpenIDConsumerException;

import javax.servlet.http.HttpServletRequest;


/**
 * DOCUMENT ME!
 *
 * @author Robin Bramley, Opsera Ltd
 */
public class MockOpenIDConsumer implements OpenIDConsumer {
    //~ Instance fields ================================================================================================

    private OpenIDAuthenticationToken token;
    private String redirectUrl;

    //~ Methods ========================================================================================================

    /* (non-Javadoc)
     * @see org.acegisecurity.ui.openid.OpenIDConsumer#beginConsumption(javax.servlet.http.HttpServletRequest, java.lang.String)
     */
    public String beginConsumption(HttpServletRequest req, String identityUrl)
        throws OpenIDConsumerException {
        return redirectUrl;
    }

    /* (non-Javadoc)
     * @see org.acegisecurity.ui.openid.OpenIDConsumer#endConsumption(javax.servlet.http.HttpServletRequest)
     */
    public OpenIDAuthenticationToken endConsumption(HttpServletRequest req)
        throws OpenIDConsumerException {
        return token;
    }

    /**
     * Set the redirectUrl to be returned by beginConsumption
     *
     * @param redirectUrl
     */
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    /* (non-Javadoc)
     * @see org.acegisecurity.ui.openid.OpenIDConsumer#setReturnToUrl(java.lang.String)
     */
    public void setReturnToUrl(String returnToUrl) {
        // TODO Auto-generated method stub
    }

    /**
     * Set the token to be returned by endConsumption
     *
     * @param token
     */
    public void setToken(OpenIDAuthenticationToken token) {
        this.token = token;
    }
}
