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
package org.springframework.security.ui.openid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * This servlet starts the OpenID authentication process.
 * <br/>
 * <br/>Sample web.xml configuration:
 * <br/>
 * <br/>        &lt;servlet&gt;
 * <br/>        &nbsp;&nbsp; &lt;servlet-name&gt;openid&lt;/servlet-name&gt;
 * <br/>        &nbsp;&nbsp; &lt;servlet-class&gt;org.springframework.security.ui.openid.OpenIDLoginInitiationServlet&lt;/servlet-class&gt;
 * <br/>        &nbsp;&nbsp; &lt;load-on-startup&gt;1&lt;/load-on-startup&gt;
 * <br/>        &nbsp;&nbsp; &lt;init-param&gt;
 * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;description&gt;The error page - will receive error "message"&lt;/description&gt;
 * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-name&gt;errorPage&lt;/param-name&gt;
 * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-value&gt;index.jsp&lt;/param-value&gt;
 * <br/>        &nbsp;&nbsp; &lt;/init-param&gt;
 * <br/>        &lt;/servlet&gt;
 * <br/>        &lt;servlet-mapping&gt;
 * <br/>        &nbsp;&nbsp; &lt;servlet-name&gt;openid&lt;/servlet-name&gt;
 * <br/>        &nbsp;&nbsp; &lt;url-pattern&gt;/j_spring_security_openid_start&lt;/url-pattern&gt;
 * <br/>        &lt;/servlet-mapping&gt;
 * <br/>
 * <br/>Sample login form:
 * <br/>&lt;form method="POST" action="j_spring_security_openid_start"&gt;
 * <br/>&nbsp;&nbsp; &lt;input type="text" name="j_username" /&gt;
 * <br/>&nbsp;&nbsp; &lt;input type="password" name="j_password" /&gt;
 * <br/>&nbsp;&nbsp; &lt;input type="submit" value="Verify" /&gt;
 * <br/>&lt;/form&gt;
 * <br/>
 * <br/>Usage notes:
 * <li>Requires an <code>openIDConsumer</code> Spring bean implementing the {@link OpenIDConsumer} interface</li>
 * <li>It will pass off to standard form-based authentication if appropriate</li>
 * (note that <code>AuthenticationProcessingFilter</code> requires j_username, j_password)
 * <br/>
 * <br/>Outstanding items:
 * TODO: config flag for whether OpenID only or dual mode?
 * TODO: username matching logic
 *
 * @author Robin Bramley, Opsera Ltd
 * @version $Id:$
 */
public class OpenIDLoginInitiationServlet extends HttpServlet {
    final static long serialVersionUID = -997766L;
    private static final Log logger = LogFactory.getLog(OpenIDLoginInitiationServlet.class);
    private static final String passwordField = "j_password";

    /**
     * Servlet config key for looking up the the HttpServletRequest parameter name
     * containing the OpenID Identity URL from the Servlet config.
     * <br/><b>Only set the identityField servlet init-param if you are not using</b> <code>j_username</code>
     * <br/>
     * <br/>        &nbsp;&nbsp; &lt;init-param&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;description&gt;The identity form field parameter&lt;/description&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-name&gt;identityField&lt;/param-name&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-value&gt;/openid_url&lt;/param-value&gt;
     * <br/>        &nbsp;&nbsp; &lt;/init-param&gt;
     */
    public static final String IDENTITY_FIELD_KEY = "identityField";

    /**
     * Servlet config key for the return to URL
     */
    public static final String ERROR_PAGE_KEY = "errorPage";

    /**
     * Servlet config key for looking up the form login URL from the Servlet config.
     * <br/><b>Only set the formLogin servlet init-param if you are not using</b> <code>/j_spring_security_check</code>
     * <br/>
     * <br/>        &nbsp;&nbsp; &lt;init-param&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;description&gt;The form login URL - for standard authentication&lt;/description&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-name&gt;formLogin&lt;/param-name&gt;
     * <br/>        &nbsp;&nbsp;&nbsp;&nbsp; &lt;param-value&gt;/custom_acegi_security_check&lt;/param-value&gt;
     * <br/>        &nbsp;&nbsp; &lt;/init-param&gt;
     */
    public static final String FORM_LOGIN_URL_KEY = "formLogin";

    /**
     * Spring context key for the OpenID consumer bean
     */
    public static final String CONSUMER_KEY = "openIDConsumer";
    private String errorPage = "index.jsp";
    private String identityField = "j_username";
    private String formLoginUrl = "/j_spring_security_check";

    /**
     * Check for init-params
     *
     * @Override
     */
    public void init() throws ServletException {
        super.init();

        String configErrorPage = getServletConfig()
                .getInitParameter(ERROR_PAGE_KEY);

        if (StringUtils.hasText(configErrorPage)) {
            errorPage = configErrorPage;
        }

        String configIdentityField = getServletConfig()
                .getInitParameter(IDENTITY_FIELD_KEY);

        if (StringUtils.hasText(configIdentityField)) {
            identityField = configIdentityField;
        }

        String configFormLoginUrl = getServletConfig()
                .getInitParameter(FORM_LOGIN_URL_KEY);

        if (StringUtils.hasText(configFormLoginUrl)) {
            formLoginUrl = configFormLoginUrl;
        }
    }

    /**
     * Process the form post - all the work is done by the OpenIDConsumer.beginConsumption method
     *
     * @Override
     */
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getRequiredWebApplicationContext(getServletContext());
        OpenIDConsumer consumer = (OpenIDConsumer) webApplicationContext.getBean(CONSUMER_KEY);

        // get the submitted id field
        String id = req.getParameter(identityField);

        // assume page will validate?
        //TODO: null checking!

        //TODO: pattern matching
        String password = req.getParameter(passwordField);

        if ((password != null) && (password.length() > 0)) {
            logger.debug("Attempting to authenticate using username/password");

            // forward to authenticationProcessingFilter (/j_spring_security_check - depends on param names)
            req.getRequestDispatcher(formLoginUrl).forward(req, res);

        } else {
            // send the user the redirect url to proceed with OpenID authentication
            try {
                String redirect = consumer.beginConsumption(req, id, req.getRequestURL().toString());
                logger.debug("Redirecting to: " + redirect);
                res.sendRedirect(redirect);
            } catch (OpenIDConsumerException oice) {
                logger.error("Consumer error!", oice);
                req.setAttribute("message", oice.getMessage());
                req.getRequestDispatcher(errorPage).forward(req, res);
            }
        }
    }
}
