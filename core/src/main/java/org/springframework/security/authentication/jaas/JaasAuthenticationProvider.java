/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.jaas;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.Security;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from a
 * JAAS login configuration.
 *
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating
 * {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
 * requests contain the correct username and password.
 * </p>
 * <p>
 * This implementation is backed by a
 * <a href="https://java.sun.com/j2se/1.5.0/docs/guide/security/jaas/JAASRefGuide.html" >
 * JAAS</a> configuration. The loginConfig property must be set to a given JAAS
 * configuration file. This setter accepts a Spring
 * {@link org.springframework.core.io.Resource} instance. It should point to a JAAS
 * configuration file containing an index matching the
 * {@link #setLoginContextName(java.lang.String) loginContextName} property.
 * </p>
 * <p>
 * For example: If this JaasAuthenticationProvider were configured in a Spring
 * WebApplicationContext the xml to set the loginConfiguration could be as follows...
 *
 * <pre>
 * &lt;property name="loginConfig"&gt;
 *   &lt;value&gt;/WEB-INF/login.conf&lt;/value&gt;
 * &lt;/property&gt;
 * </pre>
 *
 * <p>
 * The loginContextName should coincide with a given index in the loginConfig specifed.
 * The loginConfig file used in the JUnit tests appears as the following...
 *
 * <pre>
 * JAASTest {
 *   org.springframework.security.authentication.jaas.TestLoginModule required;
 * };
 * </pre>
 *
 * Using the example login configuration above, the loginContextName property would be set
 * as <i>JAASTest</i>...
 *
 * <pre>
 *  &lt;property name="loginContextName"&gt; &lt;value&gt;JAASTest&lt;/value&gt; &lt;/property&gt;
 * </pre>
 *
 * <p>
 * When using JAAS login modules as the authentication source, sometimes the <a href=
 * "https://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/login/LoginContext.html"
 * > LoginContext</a> will require <i>CallbackHandler</i>s. The JaasAuthenticationProvider
 * uses an internal <a href=
 * "https://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/callback/CallbackHandler.html"
 * >CallbackHandler </a> to wrap the {@link JaasAuthenticationCallbackHandler}s configured
 * in the ApplicationContext. When the LoginContext calls the internal CallbackHandler,
 * control is passed to each {@link JaasAuthenticationCallbackHandler} for each Callback
 * passed.
 *
 * <p>
 * {@link JaasAuthenticationCallbackHandler}s are passed to the JaasAuthenticationProvider
 * through the
 * {@link #setCallbackHandlers(org.springframework.security.authentication.jaas.JaasAuthenticationCallbackHandler[])
 * callbackHandlers} property.
 *
 * <pre>
 * &lt;property name="callbackHandlers"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.authentication.jaas.TestCallbackHandler"/&gt;
 *     &lt;bean class="{@link JaasNameCallbackHandler org.springframework.security.authentication.jaas.JaasNameCallbackHandler}"/&gt;
 *     &lt;bean class="{@link JaasPasswordCallbackHandler org.springframework.security.authentication.jaas.JaasPasswordCallbackHandler}"/&gt;
 *  &lt;/list&gt;
 * &lt;/property&gt;
 * </pre>
 *
 * <p>
 * After calling LoginContext.login(), the JaasAuthenticationProvider will retrieve the
 * returned Principals from the Subject (LoginContext.getSubject().getPrincipals). Each
 * returned principal is then passed to the configured {@link AuthorityGranter}s. An
 * AuthorityGranter is a mapping between a returned Principal, and a role name. If an
 * AuthorityGranter wishes to grant an Authorization a role, it returns that role name
 * from it's {@link AuthorityGranter#grant(java.security.Principal)} method. The returned
 * role will be applied to the Authorization object as a {@link GrantedAuthority}.
 * </p>
 * <p>
 * AuthorityGranters are configured in spring xml as follows...
 *
 * <pre>
 * &lt;property name="authorityGranters"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/&gt;
 *   &lt;/list&gt;
 *  &lt;/property&gt;
 * </pre>
 *
 * A configuration note: The JaasAuthenticationProvider uses the security properties
 * "login.config.url.X" to configure jaas. If you would like to customize the way Jaas
 * gets configured, create a subclass of this and override the
 * {@link #configureJaas(Resource)} method.
 *
 * @author Ray Krueger
 * @author Rob Winch
 */
public class JaasAuthenticationProvider extends AbstractJaasAuthenticationProvider {

	// exists for passivity
	protected static final Log log = LogFactory.getLog(JaasAuthenticationProvider.class);

	private Resource loginConfig;

	private boolean refreshConfigurationOnStartup = true;

	@Override
	public void afterPropertiesSet() throws Exception {
		// the superclass is not called because it does additional checks that are
		// non-passive
		Assert.hasLength(getLoginContextName(), () -> "loginContextName must be set on " + getClass());
		Assert.notNull(this.loginConfig, () -> "loginConfig must be set on " + getClass());
		configureJaas(this.loginConfig);

		Assert.notNull(Configuration.getConfiguration(),
				"As per https://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/login/Configuration.html "
						+ "\"If a Configuration object was set via the Configuration.setConfiguration method, then that object is "
						+ "returned. Otherwise, a default Configuration object is returned\". Your JRE returned null to "
						+ "Configuration.getConfiguration().");
	}

	@Override
	protected LoginContext createLoginContext(CallbackHandler handler) throws LoginException {
		return new LoginContext(getLoginContextName(), handler);
	}

	/**
	 * Hook method for configuring Jaas.
	 * @param loginConfig URL to Jaas login configuration
	 * @throws IOException if there is a problem reading the config resource.
	 */
	protected void configureJaas(Resource loginConfig) throws IOException {
		configureJaasUsingLoop();

		if (this.refreshConfigurationOnStartup) {
			// Overcome issue in SEC-760
			Configuration.getConfiguration().refresh();
		}
	}

	/**
	 * Loops through the login.config.url.1,login.config.url.2 properties looking for the
	 * login configuration. If it is not set, it will be set to the last available
	 * login.config.url.X property.
	 *
	 */
	private void configureJaasUsingLoop() throws IOException {
		String loginConfigUrl = convertLoginConfigToUrl();
		boolean alreadySet = false;

		int n = 1;
		final String prefix = "login.config.url.";
		String existing;

		while ((existing = Security.getProperty(prefix + n)) != null) {
			alreadySet = existing.equals(loginConfigUrl);

			if (alreadySet) {
				break;
			}

			n++;
		}

		if (!alreadySet) {
			String key = prefix + n;
			log.debug("Setting security property [" + key + "] to: " + loginConfigUrl);
			Security.setProperty(key, loginConfigUrl);
		}
	}

	private String convertLoginConfigToUrl() throws IOException {
		String loginConfigPath;

		try {
			loginConfigPath = this.loginConfig.getFile().getAbsolutePath().replace(File.separatorChar, '/');

			if (!loginConfigPath.startsWith("/")) {
				loginConfigPath = "/" + loginConfigPath;
			}

			return new URL("file", "", loginConfigPath).toString();
		}
		catch (IOException e) {
			// SEC-1700: May be inside a jar
			return this.loginConfig.getURL().toString();
		}
	}

	/**
	 * Publishes the {@link JaasAuthenticationFailedEvent}. Can be overridden by
	 * subclasses for different functionality
	 * @param token The authentication token being processed
	 * @param ase The excetion that caused the authentication failure
	 */
	@Override
	protected void publishFailureEvent(UsernamePasswordAuthenticationToken token, AuthenticationException ase) {
		// exists for passivity (the superclass does a null check before publishing)
		getApplicationEventPublisher().publishEvent(new JaasAuthenticationFailedEvent(token, ase));
	}

	public Resource getLoginConfig() {
		return this.loginConfig;
	}

	/**
	 * Set the JAAS login configuration file.
	 * @param loginConfig
	 *
	 * @see <a href=
	 * "https://java.sun.com/j2se/1.5.0/docs/guide/security/jaas/JAASRefGuide.html">JAAS
	 * Reference</a>
	 */
	public void setLoginConfig(Resource loginConfig) {
		this.loginConfig = loginConfig;
	}

	/**
	 * If set, a call to {@code Configuration#refresh()} will be made by
	 * {@code #configureJaas(Resource) } method. Defaults to {@code true}.
	 *
	 * @see <a href="https://jira.springsource.org/browse/SEC-1320">SEC-1320</a>
	 * @param refresh set to {@code false} to disable reloading of the configuration. May
	 * be useful in some environments.
	 */
	public void setRefreshConfigurationOnStartup(boolean refresh) {
		this.refreshConfigurationOnStartup = refresh;
	}

}
