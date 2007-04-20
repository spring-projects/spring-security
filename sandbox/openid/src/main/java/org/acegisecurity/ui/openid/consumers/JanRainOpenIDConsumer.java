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

import com.janrain.openid.consumer.AuthRequest;
import com.janrain.openid.consumer.Consumer;
import com.janrain.openid.consumer.ErrorResponse;
import com.janrain.openid.consumer.Response;
import com.janrain.openid.consumer.StatusCode;
import com.janrain.openid.store.OpenIDStore;

import org.acegisecurity.providers.openid.OpenIDAuthenticationStatus;
import org.acegisecurity.providers.openid.OpenIDAuthenticationToken;

import org.acegisecurity.ui.openid.OpenIDConstants;
import org.acegisecurity.ui.openid.OpenIDConsumer;
import org.acegisecurity.ui.openid.OpenIDConsumerException;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * OpenIDConsumer implementation using the JanRain OpenID library
 *
 * @author Robin Bramley, Opsera Ltd
 * @version $Id:$
 */
public class JanRainOpenIDConsumer implements OpenIDConsumer, InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final String SAVED_ID_SESSION_KEY = "savedId";

    //~ Instance fields ================================================================================================

    private OpenIDStore store;
    private String returnToUrl = "j_acegi_openid_security_check";

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.store, "An OpenIDStore must be set on the store property");
    }

    /* (non-Javadoc)
     * @see org.acegisecurity.ui.openid.OpenIDConsumer#beginConsumption(java.lang.String)
     */
    public String beginConsumption(HttpServletRequest req, String identityUrl)
        throws OpenIDConsumerException {
        // fetch/create a session Map for the consumer's use
        HttpSession session = req.getSession();
        Map sessionMap = (Map) session.getAttribute(OpenIDConstants.OPENID_SESSION_MAP_KEY);

        if (sessionMap == null) {
            sessionMap = new HashMap();
            session.setAttribute(OpenIDConstants.OPENID_SESSION_MAP_KEY, sessionMap);
        }

        Consumer openIdConsumer = new Consumer(sessionMap, store);

        // Create an Authrequest object from the submitted value
        AuthRequest ar;

        try {
            ar = openIdConsumer.begin(identityUrl);
        } catch (IOException ioe) {
            req.getSession().setAttribute(SAVED_ID_SESSION_KEY, escapeAttr(identityUrl));
            throw new OpenIDConsumerException("Error on begin consumption for " + identityUrl, ioe);
        }

        // construct trust root and return to URLs.
        String port = "";

        if (req.getServerPort() != 80) {
            port = ":" + req.getServerPort();
        }

        String trustRoot = req.getScheme() + "://" + req.getServerName() + port + "/";
        String cp = req.getContextPath();

        if (!cp.equals("")) {
            cp = cp.substring(1) + "/";
        }

        String returnTo = trustRoot + cp + returnToUrl;

        // send the user the redirect url to proceed with OpenID authentication
        return ar.redirectUrl(trustRoot, returnTo);
    }

    /* (non-Javadoc)
     * @see org.acegisecurity.ui.openid.OpenIDConsumer#endConsumption(javax.servlet.http.HttpServletRequest)
     */
    public OpenIDAuthenticationToken endConsumption(HttpServletRequest req)
        throws OpenIDConsumerException {
        HttpSession session = req.getSession();
        Map sessionMap = (Map) session.getAttribute(OpenIDConstants.OPENID_SESSION_MAP_KEY);

        if (sessionMap == null) {
            sessionMap = new HashMap();
            session.setAttribute(OpenIDConstants.OPENID_SESSION_MAP_KEY, sessionMap);
        }

        // get a Consumer instance
        Consumer openIdConsumer = new Consumer(sessionMap, store);

        // convert the argument map into the form the library uses with a handy
        // convenience function
        Map query = Consumer.filterArgs(req.getParameterMap());

        // Check the arguments to see what the response was.
        Response response = openIdConsumer.complete(query);

        String message = "";
        OpenIDAuthenticationStatus status;

        StatusCode statusCode = response.getStatus();

        if (statusCode == StatusCode.CANCELLED) {
            status = OpenIDAuthenticationStatus.CANCELLED;
        } else if (statusCode == StatusCode.ERROR) {
            status = OpenIDAuthenticationStatus.ERROR;
            message = ((ErrorResponse) response).getMessage();
        } else if (statusCode == StatusCode.FAILURE) {
            status = OpenIDAuthenticationStatus.FAILURE;
        } else if (statusCode == StatusCode.SETUP_NEEDED) {
            status = OpenIDAuthenticationStatus.SETUP_NEEDED;
        } else if (statusCode == StatusCode.SUCCESS) {
            status = OpenIDAuthenticationStatus.SUCCESS;
        } else {
            // unknown status code
            throw new OpenIDConsumerException("Unknown response status " + statusCode.toString());
        }

        return new OpenIDAuthenticationToken(status, response.getIdentityUrl(), message);
    }

    /*
     * This method escapes characters in a string that can cause problems in
     * HTML
     */
    private String escapeAttr(String s) {
        if (s == null) {
            return "";
        }

        StringBuffer result = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (c == '<') {
                result.append("&lt;");
            } else if (c == '>') {
                result.append("&gt;");
            } else if (c == '&') {
                result.append("&amp;");
            } else if (c == '\"') {
                result.append("&quot;");
            } else if (c == '\'') {
                result.append("&#039;");
            } else if (c == '\\') {
                result.append("&#092;");
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    public void setReturnToUrl(String returnToUrl) {
        this.returnToUrl = returnToUrl;
    }

    // dependency injection
    public void setStore(OpenIDStore store) {
        this.store = store;
    }
}
