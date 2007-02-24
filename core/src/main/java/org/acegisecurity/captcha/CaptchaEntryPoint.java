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

package org.acegisecurity.captcha;

import org.acegisecurity.securechannel.ChannelEntryPoint;

import org.acegisecurity.util.PortMapper;
import org.acegisecurity.util.PortMapperImpl;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * The captcha entry point : redirect to the captcha test page.
 * <p>
 * This entry point can force the use of SSL : see {@link #getForceHttps()}
 * </p>
 * <p>
 * This entry point allows internal OR external redirect : see {@link #setOutsideWebApp(boolean)}<br />
 * / Original request can be added to the redirect path using a custom translation : see
 * {@link #setIncludeOriginalRequest(boolean)}<br />
 * The original request is translated using URLEncoding and the following translation mapping in the redirect url :
 *  <ul>
 *      <li>original url => {@link #getOriginalRequestUrlParameterName()}</li>
 *      <li>If {@link #isIncludeOriginalParameters()}</li>
 *      <li>original method => {@link #getOriginalRequestMethodParameterName()}</li>
 *      <li>original parameters => {@link #getOriginalRequestParametersParameterName()}</li>
 *      <li>The original parameters string is contructed using :
 *      <ul>
 *          <li>a parameter separator {@link #getOriginalRequestParametersSeparator()}</li>
 *          <li>a parameter name value pair separator for each parameter {@link
 *          #getOriginalRequestParametersNameValueSeparator()}</li>
 *      </ul>
 *      </li>
 *  </ul>
 *  <br><br>
 * Default values :
 * <pre>
 * forceHttps = false
 * includesOriginalRequest = true
 * includesOriginalParameters = false
 * isOutsideWebApp = false
 * originalRequestUrlParameterName = original_requestUrl
 * originalRequestParametersParameterName = original_request_parameters
 * originalRequestParametersNameValueSeparator = __
 * originalRequestParametersSeparator = ;;
 * originalRequestMethodParameterName = original_request_method
 * urlEncodingCharset = UTF-8
 * </pre>
 * </p>
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaEntryPoint implements ChannelEntryPoint, InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(CaptchaEntryPoint.class);

    //~ Instance fields ================================================================================================

    // ~ Instance fields
    // ========================================================
    private PortMapper portMapper = new PortMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();
    private String captchaFormUrl;
    private String originalRequestMethodParameterName = "original_request_method";
    private String originalRequestParametersNameValueSeparator = "__";
    private String originalRequestParametersParameterName = "original_request_parameters";
    private String originalRequestParametersSeparator = ";;";
    private String originalRequestUrlParameterName = "original_requestUrl";
    private String urlEncodingCharset = "UTF-8";
    private boolean forceHttps = false;
    private boolean includeOriginalParameters = false;
    private boolean includeOriginalRequest = true;
    private boolean isOutsideWebApp = false;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(captchaFormUrl, "captchaFormUrl must be specified");
        Assert.hasLength(originalRequestMethodParameterName, "originalRequestMethodParameterName must be specified");
        Assert.hasLength(originalRequestParametersNameValueSeparator,
            "originalRequestParametersNameValueSeparator must be specified");
        Assert.hasLength(originalRequestParametersParameterName,
            "originalRequestParametersParameterName must be specified");
        Assert.hasLength(originalRequestParametersSeparator, "originalRequestParametersSeparator must be specified");
        Assert.hasLength(originalRequestUrlParameterName, "originalRequestUrlParameterName must be specified");
        Assert.hasLength(urlEncodingCharset, "urlEncodingCharset must be specified");
        Assert.notNull(portMapper, "portMapper must be specified");
        Assert.notNull(portResolver, "portResolver must be specified");
        URLEncoder.encode("   fzaef é& à ", urlEncodingCharset);
    }

    private void buildInternalRedirect(StringBuffer redirectUrl, HttpServletRequest req) {
        // construct it
        StringBuffer simpleRedirect = new StringBuffer();

        String scheme = req.getScheme();
        String serverName = req.getServerName();
        int serverPort = portResolver.getServerPort(req);
        String contextPath = req.getContextPath();
        boolean includePort = true;

        if ("http".equals(scheme.toLowerCase()) && (serverPort == 80)) {
            includePort = false;
        }

        if ("https".equals(scheme.toLowerCase()) && (serverPort == 443)) {
            includePort = false;
        }

        simpleRedirect.append(scheme);
        simpleRedirect.append("://");
        simpleRedirect.append(serverName);

        if (includePort) {
            simpleRedirect.append(":");
            simpleRedirect.append(serverPort);
        }

        simpleRedirect.append(contextPath);
        simpleRedirect.append(captchaFormUrl);

        if (forceHttps && req.getScheme().equals("http")) {
            Integer httpPort = new Integer(portResolver.getServerPort(req));
            Integer httpsPort = (Integer) portMapper.lookupHttpsPort(httpPort);

            if (httpsPort != null) {
                if (httpsPort.intValue() == 443) {
                    includePort = false;
                } else {
                    includePort = true;
                }

                redirectUrl.append("https://");
                redirectUrl.append(serverName);

                if (includePort) {
                    redirectUrl.append(":");
                    redirectUrl.append(httpsPort);
                }

                redirectUrl.append(contextPath);
                redirectUrl.append(captchaFormUrl);
            } else {
                redirectUrl.append(simpleRedirect);
            }
        } else {
            redirectUrl.append(simpleRedirect);
        }
    }

    public void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
        StringBuffer redirectUrl = new StringBuffer();
        HttpServletRequest req = (HttpServletRequest) request;

        if (isOutsideWebApp) {
            redirectUrl = redirectUrl.append(captchaFormUrl);
        } else {
            buildInternalRedirect(redirectUrl, req);
        }

        if (includeOriginalRequest) {
            includeOriginalRequest(redirectUrl, req);
        }

        // add post parameter? DONE!
        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to: " + redirectUrl);
        }

        ((HttpServletResponse) response).sendRedirect(redirectUrl.toString());
    }

    /**
     * DOCUMENT ME!
     *
     * @return the captcha test page to redirect to.
     */
    public String getCaptchaFormUrl() {
        return captchaFormUrl;
    }

    public boolean getForceHttps() {
        return forceHttps;
    }

    public String getOriginalRequestMethodParameterName() {
        return originalRequestMethodParameterName;
    }

    public String getOriginalRequestParametersNameValueSeparator() {
        return originalRequestParametersNameValueSeparator;
    }

    public String getOriginalRequestParametersParameterName() {
        return originalRequestParametersParameterName;
    }

    public String getOriginalRequestParametersSeparator() {
        return originalRequestParametersSeparator;
    }

    public String getOriginalRequestUrlParameterName() {
        return originalRequestUrlParameterName;
    }

    public PortMapper getPortMapper() {
        return portMapper;
    }

    public PortResolver getPortResolver() {
        return portResolver;
    }

    public String getUrlEncodingCharset() {
        return urlEncodingCharset;
    }

    private void includeOriginalRequest(StringBuffer redirectUrl, HttpServletRequest req) {
        // add original request to the url
        if (redirectUrl.indexOf("?") >= 0) {
            redirectUrl.append("&");
        } else {
            redirectUrl.append("?");
        }

        redirectUrl.append(originalRequestUrlParameterName);
        redirectUrl.append("=");

        try {
            redirectUrl.append(URLEncoder.encode(req.getRequestURL().toString(), urlEncodingCharset));
        } catch (UnsupportedEncodingException e) {
            logger.warn(e);
        }

        //append method
        redirectUrl.append("&");
        redirectUrl.append(originalRequestMethodParameterName);
        redirectUrl.append("=");
        redirectUrl.append(req.getMethod());

        if (includeOriginalParameters) {
            // append query params
            redirectUrl.append("&");
            redirectUrl.append(originalRequestParametersParameterName);
            redirectUrl.append("=");

            StringBuffer qp = new StringBuffer();
            Enumeration parameters = req.getParameterNames();

            if ((parameters != null) && parameters.hasMoreElements()) {
                //qp.append("?");
                while (parameters.hasMoreElements()) {
                    String name = parameters.nextElement().toString();
                    String value = req.getParameter(name);
                    qp.append(name);
                    qp.append(originalRequestParametersNameValueSeparator);
                    qp.append(value);

                    if (parameters.hasMoreElements()) {
                        qp.append(originalRequestParametersSeparator);
                    }
                }
            }

            try {
                redirectUrl.append(URLEncoder.encode(qp.toString(), urlEncodingCharset));
            } catch (Exception e) {
                logger.warn(e);
            }
        }
    }

    public boolean isIncludeOriginalParameters() {
        return includeOriginalParameters;
    }

    public boolean isIncludeOriginalRequest() {
        return includeOriginalRequest;
    }

    public boolean isOutsideWebApp() {
        return isOutsideWebApp;
    }

    /**
     * The URL where the <code>CaptchaProcessingFilter</code> login page can be found. Should be relative to
     * the web-app context path, and include a leading <code>/</code>
     *
     * @param captchaFormUrl
     */
    public void setCaptchaFormUrl(String captchaFormUrl) {
        this.captchaFormUrl = captchaFormUrl;
    }

    // ~ Methods
    // ================================================================
    /**
     * Set to true to force captcha form access to be via https. If this value is ture (the default is false),
     * and the incoming request for the protected resource which triggered the interceptor was not already
     * <code>https</code>, then
     *
     * @param forceHttps
     */
    public void setForceHttps(boolean forceHttps) {
        this.forceHttps = forceHttps;
    }

    public void setIncludeOriginalParameters(boolean includeOriginalParameters) {
        this.includeOriginalParameters = includeOriginalParameters;
    }

    /**
     * If set to true, the original request url will be appended to the redirect url using the {@link
     * #getOriginalRequestUrlParameterName()}.
     *
     * @param includeOriginalRequest
     */
    public void setIncludeOriginalRequest(boolean includeOriginalRequest) {
        this.includeOriginalRequest = includeOriginalRequest;
    }

    public void setOriginalRequestMethodParameterName(String originalRequestMethodParameterName) {
        this.originalRequestMethodParameterName = originalRequestMethodParameterName;
    }

    public void setOriginalRequestParametersNameValueSeparator(String originalRequestParametersNameValueSeparator) {
        this.originalRequestParametersNameValueSeparator = originalRequestParametersNameValueSeparator;
    }

    public void setOriginalRequestParametersParameterName(String originalRequestParametersParameterName) {
        this.originalRequestParametersParameterName = originalRequestParametersParameterName;
    }

    public void setOriginalRequestParametersSeparator(String originalRequestParametersSeparator) {
        this.originalRequestParametersSeparator = originalRequestParametersSeparator;
    }

    public void setOriginalRequestUrlParameterName(String originalRequestUrlParameterName) {
        this.originalRequestUrlParameterName = originalRequestUrlParameterName;
    }

    /**
     * if set to true, the {@link #commence(ServletRequest, ServletResponse)} method uses the {@link
     * #getCaptchaFormUrl()} as a complete URL, else it as a 'inside WebApp' path.
     *
     * @param isOutsideWebApp
     */
    public void setOutsideWebApp(boolean isOutsideWebApp) {
        this.isOutsideWebApp = isOutsideWebApp;
    }

    public void setPortMapper(PortMapper portMapper) {
        this.portMapper = portMapper;
    }

    public void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }

    public void setUrlEncodingCharset(String urlEncodingCharset) {
        this.urlEncodingCharset = urlEncodingCharset;
    }
}
