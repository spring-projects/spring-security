/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.client;

import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.KerberosConfig;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.SPNegoSchemeFactory;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.jspecify.annotations.Nullable;

import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * {@code RestTemplate} that is able to make kerberos SPNEGO authenticated REST requests.
 * Under a hood this {@code KerberosRestTemplate} is using {@link HttpClient} to support
 * Kerberos.
 *
 * <p>
 * Generally this template can be configured in few different ways.
 * <ul>
 * <li>Leave keyTabLocation and userPrincipal empty if you want to use cached ticket</li>
 * <li>Use keyTabLocation and userPrincipal if you want to use keytab file</li>
 * <li>Use userPrincipal and password if you want to use user/password</li>
 * <li>Use loginOptions if you want to customise Krb5LoginModule options</li>
 * <li>Use a customised httpClient</li>
 * </ul>
 *
 * @author Janne Valkealahti
 *
 */
public class KerberosRestTemplate extends RestTemplate {

	private static final Credentials credentials = new NullCredentials();

	private final @Nullable String keyTabLocation;

	private final @Nullable String userPrincipal;

	private final @Nullable String password;

	private final @Nullable Map<String, Object> loginOptions;

	/**
	 * Instantiates a new kerberos rest template.
	 */
	public KerberosRestTemplate() {
		this(null, null, null, null, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(HttpClient httpClient) {
		this(null, null, null, null, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 */
	public KerberosRestTemplate(@Nullable String keyTabLocation, @Nullable String userPrincipal) {
		this(keyTabLocation, userPrincipal, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(@Nullable String keyTabLocation, @Nullable String userPrincipal,
			HttpClient httpClient) {
		this(keyTabLocation, userPrincipal, null, null, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param loginOptions the login options
	 */
	public KerberosRestTemplate(@Nullable Map<String, Object> loginOptions) {
		this(null, null, null, loginOptions, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param loginOptions the login options
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(@Nullable Map<String, Object> loginOptions, HttpClient httpClient) {
		this(null, null, null, loginOptions, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param loginOptions the login options
	 */
	public KerberosRestTemplate(@Nullable String keyTabLocation, @Nullable String userPrincipal,
			@Nullable Map<String, Object> loginOptions) {
		this(keyTabLocation, userPrincipal, null, loginOptions, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param password the password
	 * @param loginOptions the login options
	 */
	public KerberosRestTemplate(@Nullable String keyTabLocation, @Nullable String userPrincipal,
			@Nullable String password, @Nullable Map<String, Object> loginOptions) {
		this(keyTabLocation, userPrincipal, password, loginOptions, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param password the password
	 * @param loginOptions the login options
	 * @param httpClient the http client
	 */
	private KerberosRestTemplate(@Nullable String keyTabLocation, @Nullable String userPrincipal,
			@Nullable String password, @Nullable Map<String, Object> loginOptions, HttpClient httpClient) {
		super(new HttpComponentsClientHttpRequestFactory(httpClient));
		this.keyTabLocation = keyTabLocation;
		this.userPrincipal = userPrincipal;
		this.password = password;
		this.loginOptions = loginOptions;
	}

	/**
	 * Builds the default instance of {@link HttpClient} having kerberos support.
	 * @return the http client with SPNEGO auth scheme
	 */
	private static HttpClient buildHttpClient() {
		HttpClientBuilder builder = HttpClientBuilder.create();

		Lookup<AuthSchemeFactory> authSchemeRegistry = RegistryBuilder.<AuthSchemeFactory>create()
			.register(StandardAuthScheme.SPNEGO,
					new SPNegoSchemeFactory(KerberosConfig.custom()
						.setStripPort(KerberosConfig.Option.ENABLE)
						.setUseCanonicalHostname(KerberosConfig.Option.DISABLE)
						.build(), SystemDefaultDnsResolver.INSTANCE))
			.build();

		builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
		RequestConfig negotiate = RequestConfig.copy(RequestConfig.DEFAULT)
			.setTargetPreferredAuthSchemes(Set.of(StandardAuthScheme.SPNEGO, StandardAuthScheme.KERBEROS))
			.build();
		builder.setDefaultRequestConfig(negotiate);
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(null, -1), credentials);
		builder.setDefaultCredentialsProvider(credentialsProvider);
		CloseableHttpClient httpClient = builder.build();
		return httpClient;
	}

	/**
	 * Setup the {@link LoginContext} with credentials and options for authentication
	 * against kerberos.
	 * @return the login context
	 */
	private LoginContext buildLoginContext() throws LoginException {
		ClientLoginConfig loginConfig = new ClientLoginConfig(this.keyTabLocation, this.userPrincipal, this.password,
				this.loginOptions);
		Set<Principal> princ = new HashSet<Principal>(1);
		if (this.userPrincipal != null) {
			princ.add(new KerberosPrincipal(this.userPrincipal));
		}
		Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
		CallbackHandler callbackHandler = new CallbackHandlerImpl(this.userPrincipal, this.password);
		LoginContext lc = new LoginContext("", sub, callbackHandler, loginConfig);
		return lc;
	}

	@Override
	protected final <T> T doExecute(final URI url, final @Nullable String uriTemplate,
			final @Nullable HttpMethod method, final @Nullable RequestCallback requestCallback,
			final @Nullable ResponseExtractor<T> responseExtractor) throws RestClientException {

		try {
			LoginContext lc = buildLoginContext();
			lc.login();
			Subject serviceSubject = lc.getSubject();
			return Subject.doAs(serviceSubject, new PrivilegedAction<T>() {

				@Override
				public T run() {
					return KerberosRestTemplate.this.doExecuteSubject(url, uriTemplate, method, requestCallback,
							responseExtractor);
				}
			});

		}
		catch (Exception ex) {
			throw new RestClientException("Error running rest call", ex);
		}
	}

	private <T> T doExecuteSubject(URI url, @Nullable String uriTemplate, @Nullable HttpMethod method,
			@Nullable RequestCallback requestCallback, @Nullable ResponseExtractor<T> responseExtractor)
			throws RestClientException {
		T result = super.doExecute(url, uriTemplate, method, requestCallback, responseExtractor);
		if (result == null) {
			throw new RestClientException("doExecute returned null");
		}
		return result;
	}

	private static final class ClientLoginConfig extends Configuration {

		private final @Nullable String keyTabLocation;

		private final @Nullable String userPrincipal;

		private final @Nullable String password;

		private final @Nullable Map<String, Object> loginOptions;

		private ClientLoginConfig(@Nullable String keyTabLocation, @Nullable String userPrincipal,
				@Nullable String password, @Nullable Map<String, Object> loginOptions) {
			super();
			this.keyTabLocation = keyTabLocation;
			this.userPrincipal = userPrincipal;
			this.password = password;
			this.loginOptions = loginOptions;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

			Map<String, Object> options = new HashMap<String, Object>();

			// if we don't have keytab or principal only option is to rely on
			// credentials cache.
			if (!StringUtils.hasText(this.keyTabLocation) || !StringUtils.hasText(this.userPrincipal)) {
				// cache
				options.put("useTicketCache", "true");
			}
			else {
				// keytab
				options.put("useKeyTab", "true");
				options.put("keyTab", this.keyTabLocation);
				options.put("principal", this.userPrincipal);
				options.put("storeKey", "true");
			}

			options.put("doNotPrompt", Boolean.toString(this.password == null));
			options.put("isInitiator", "true");

			if (this.loginOptions != null) {
				options.putAll(this.loginOptions);
			}

			return new AppConfigurationEntry[] {
					new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
							AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
		}

	}

	private static class NullCredentials implements Credentials {

		@Override
		public @Nullable Principal getUserPrincipal() {
			return null;
		}

		@Override
		public char @Nullable [] getPassword() {
			return null;
		}

	}

	private static final class CallbackHandlerImpl implements CallbackHandler {

		private final @Nullable String userPrincipal;

		private final @Nullable String password;

		private CallbackHandlerImpl(@Nullable String userPrincipal, @Nullable String password) {
			super();
			this.userPrincipal = userPrincipal;
			this.password = password;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

			for (Callback callback : callbacks) {
				if (callback instanceof NameCallback) {
					NameCallback nc = (NameCallback) callback;
					nc.setName(this.userPrincipal);
				}
				else if (callback instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callback;
					if (this.password != null) {
						pc.setPassword(this.password.toCharArray());
					}
				}
				else {
					throw new UnsupportedCallbackException(callback, "Unknown Callback");
				}
			}
		}

	}

}
