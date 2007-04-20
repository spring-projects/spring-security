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
package org.acegisecurity.ui.openid;

import org.acegisecurity.providers.openid.OpenIDAuthenticationToken;

import javax.servlet.http.HttpServletRequest;


/**
 * An interface for OpenID library implementations
 *
 * @author Robin Bramley, Opsera Ltd
 *
 */
public interface OpenIDConsumer {
    //~ Methods ========================================================================================================

    /**
     * Start the authentication process
     *
     * @param req
     * @param identityUrl
     *
     * @return redirection URL
     *
     * @throws OpenIDConsumerException
     */
    public String beginConsumption(HttpServletRequest req, String identityUrl)
        throws OpenIDConsumerException;

    /**
     * DOCUMENT ME!
     *
     * @param req
     *
     * @return
     *
     * @throws OpenIDConsumerException
     */
    public OpenIDAuthenticationToken endConsumption(HttpServletRequest req)
        throws OpenIDConsumerException;

    /**
     * DOCUMENT ME!
     *
     * @param returnToUrl
     */
    public void setReturnToUrl(String returnToUrl);
}
