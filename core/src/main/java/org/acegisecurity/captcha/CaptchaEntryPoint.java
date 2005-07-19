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
package net.sf.acegisecurity.captcha;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.acegisecurity.securechannel.ChannelEntryPoint;
import net.sf.acegisecurity.util.PortMapper;
import net.sf.acegisecurity.util.PortMapperImpl;
import net.sf.acegisecurity.util.PortResolver;
import net.sf.acegisecurity.util.PortResolverImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * The captcha entry point : redirect to the captcha test page. <br/>
 * 
 * This entry point can force the use of SSL : see {@link #getForceHttps()}<br/>
 * 
 * This entry point allows internal OR external redirect : see
 * {@link #setOutsideWebApp(boolean)}<br/>/ Original request can be added to
 * the redirect path using a special parameter : see
 * {@link #getOriginalRequestParameterName()} and
 * {@link #setIncludeOriginalRequest()} <br/> <br/> Default values :<br/>
 * forceHttps = false<br/> includesOriginalRequest = false<br/>
 * originalRequestParameterName= "originalRequest"<br/> isOutsideWebApp=false<br/>
 * 
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaEntryPoint implements ChannelEntryPoint, InitializingBean {
	// ~ Static fields/initializers
	// =============================================

	private static final Log logger = LogFactory
			.getLog(CaptchaEntryPoint.class);

	// ~ Instance fields
	// ========================================================

	private PortMapper portMapper = new PortMapperImpl();

	private PortResolver portResolver = new PortResolverImpl();

	private String captchaFormUrl;

	private boolean forceHttps = false;

	private String originalRequestParameterName = "originalRequest";

	private boolean isOutsideWebApp = false;

	private boolean includeOriginalRequest = false;

	// ~ Methods
	// ================================================================

	/**
	 * Set to true to force captcha form access to be via https. If this value
	 * is ture (the default is false), and the incoming request for the
	 * protected resource which triggered the interceptor was not already
	 * <code>https</code>, then
	 * 
	 * @param forceHttps
	 */
	public void setForceHttps(boolean forceHttps) {
		this.forceHttps = forceHttps;
	}

	public boolean getForceHttps() {
		return forceHttps;
	}

	/**
	 * The URL where the <code>CaptchaProcessingFilter</code> login page can
	 * be found. Should be relative to the web-app context path, and include a
	 * leading <code>/</code>
	 * 
	 * @param captchaFormUrl
	 */
	public void setCaptchaFormUrl(String loginFormUrl) {
		this.captchaFormUrl = loginFormUrl;
	}

	/**
	 * @return the captcha test page to redirect to.
	 */
	public String getCaptchaFormUrl() {
		return captchaFormUrl;
	}

	public void setPortMapper(PortMapper portMapper) {
		this.portMapper = portMapper;
	}

	public PortMapper getPortMapper() {
		return portMapper;
	}

	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	public PortResolver getPortResolver() {
		return portResolver;
	}

	public boolean isOutsideWebApp() {
		return isOutsideWebApp;
	}

	/**
	 * if set to true, the {@link #commence(ServletRequest, ServletResponse)}
	 * method uses the {@link #getCaptchaFormUrl()} as a complete URL, else it
	 * as a 'inside WebApp' path.
	 * 
	 * @param isOutsideWebApp
	 */
	public void setOutsideWebApp(boolean isOutsideWebApp) {
		this.isOutsideWebApp = isOutsideWebApp;
	}

	public String getOriginalRequestParameterName() {
		return originalRequestParameterName;
	}

	/**
	 * sets the parameter under which the original request url will be appended
	 * to the redirect url (only if {@link #isIncludeOriginalRequest()}==true).
	 * 
	 * @param originalRequestParameterName
	 */
	public void setOriginalRequestParameterName(
			String originalRequestParameterName) {
		this.originalRequestParameterName = originalRequestParameterName;
	}

	public boolean isIncludeOriginalRequest() {
		return includeOriginalRequest;
	}

	/**
	 * If set to true, the original request url will be appended to the redirect
	 * url using the {@link #getOriginalRequestParameterName()}.
	 * 
	 * @param includeOriginalRequest
	 */
	public void setIncludeOriginalRequest(boolean includeOriginalRequest) {
		this.includeOriginalRequest = includeOriginalRequest;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(captchaFormUrl, "captchaFormUrl must be specified");
		Assert.notNull(portMapper, "portMapper must be specified");
		Assert.notNull(portResolver, "portResolver must be specified");
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
		// add post parameter? TODO?
		if (logger.isDebugEnabled()) {
			logger.debug("Redirecting to: " + redirectUrl);
		}

		((HttpServletResponse) response)
				.sendRedirect(((HttpServletResponse) response)
						.encodeRedirectURL(redirectUrl.toString()));
	}

	private void includeOriginalRequest(StringBuffer redirectUrl,
			HttpServletRequest req) {
		// add original request to the url
		if (redirectUrl.indexOf("?") >= 0) {
			redirectUrl.append("&");
		} else {
			redirectUrl.append("?");
		}
		redirectUrl.append(originalRequestParameterName);
		redirectUrl.append("=");
		redirectUrl.append(req.getRequestURL().toString());
		// append query params
		Enumeration parameters = req.getParameterNames();
		if (parameters != null && parameters.hasMoreElements()) {
			redirectUrl.append("?");
			while (parameters.hasMoreElements()) {
				String name = parameters.nextElement().toString();
				String value = req.getParameter(name);
				redirectUrl.append(name);
				redirectUrl.append("=");
				redirectUrl.append(value);
				if (parameters.hasMoreElements()) {
					redirectUrl.append("&");
				}
			}
		}

	}

	private void buildInternalRedirect(StringBuffer redirectUrl,
			HttpServletRequest req) {
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

}
