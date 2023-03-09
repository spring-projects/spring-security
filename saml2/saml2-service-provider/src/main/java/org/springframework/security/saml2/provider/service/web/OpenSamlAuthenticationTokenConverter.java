/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a {@link Saml2AuthenticationToken}
 * appropriate for authenticated a SAML 2.0 Assertion against an
 * {@link org.springframework.security.authentication.AuthenticationManager}.
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class OpenSamlAuthenticationTokenConverter implements AuthenticationConverter {

	static {
		OpenSamlInitializationService.initialize();
	}

	// MimeDecoder allows extra line-breaks as well as other non-alphabet values.
	// This matches the behaviour of the commons-codec decoder.
	private static final Base64.Decoder BASE64 = Base64.getMimeDecoder();

	private static final Base64Checker BASE_64_CHECKER = new Base64Checker();

	private final RelyingPartyRegistrationRepository registrations;

	private RequestMatcher requestMatcher = new OrRequestMatcher(
			new AntPathRequestMatcher("/login/saml2/sso/{registrationId}"),
			new AntPathRequestMatcher("/login/saml2/sso"));

	private final ParserPool parserPool;

	private final ResponseUnmarshaller unmarshaller;

	private Function<HttpServletRequest, AbstractSaml2AuthenticationRequest> loader;

	/**
	 * Constructs a {@link OpenSamlAuthenticationTokenConverter} given a repository for
	 * {@link RelyingPartyRegistration}s
	 * @param registrations the repository for {@link RelyingPartyRegistration}s
	 * {@link RelyingPartyRegistration}s
	 */
	public OpenSamlAuthenticationTokenConverter(RelyingPartyRegistrationRepository registrations) {
		Assert.notNull(registrations, "relyingPartyRegistrationRepository cannot be null");
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (ResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
		this.registrations = registrations;
		this.loader = new HttpSessionSaml2AuthenticationRequestRepository()::loadAuthenticationRequest;
	}

	/**
	 * Resolve an authentication request from the given {@link HttpServletRequest}.
	 *
	 * <p>
	 * First uses the configured {@link RequestMatcher} to deduce whether an
	 * authentication request is being made and optionally for which
	 * {@code registrationId}.
	 *
	 * <p>
	 * If there is an associated {@code <saml2:AuthnRequest>}, then the
	 * {@code registrationId} is looked up and used.
	 *
	 * <p>
	 * If a {@code registrationId} is found in the request, then it is looked up and used.
	 * In that case, if none is found a {@link Saml2AuthenticationException} is thrown.
	 *
	 * <p>
	 * Finally, if no {@code registrationId} is found in the request, then the code
	 * attempts to resolve the {@link RelyingPartyRegistration} from the SAML Response's
	 * Issuer.
	 * @param request the HTTP request
	 * @return the {@link Saml2AuthenticationToken} authentication request
	 * @throws Saml2AuthenticationException if the {@link RequestMatcher} specifies a
	 * non-existent {@code registrationId}
	 */
	@Override
	public Saml2AuthenticationToken convert(HttpServletRequest request) {
		String serialized = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		if (serialized == null) {
			return null;
		}
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		Saml2AuthenticationToken token = tokenByAuthenticationRequest(request);
		if (token == null) {
			token = tokenByRegistrationId(request, result);
		}
		if (token == null) {
			token = tokenByEntityId(request);
		}
		return token;
	}

	private Saml2AuthenticationToken tokenByAuthenticationRequest(HttpServletRequest request) {
		AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
		if (authenticationRequest == null) {
			return null;
		}
		String registrationId = authenticationRequest.getRelyingPartyRegistrationId();
		RelyingPartyRegistration registration = this.registrations.findByRegistrationId(registrationId);
		return tokenByRegistration(request, registration, authenticationRequest);
	}

	private Saml2AuthenticationToken tokenByRegistrationId(HttpServletRequest request,
			RequestMatcher.MatchResult result) {
		String registrationId = result.getVariables().get("registrationId");
		if (registrationId == null) {
			return null;
		}
		RelyingPartyRegistration registration = this.registrations.findByRegistrationId(registrationId);
		return tokenByRegistration(request, registration, null);
	}

	private Saml2AuthenticationToken tokenByEntityId(HttpServletRequest request) {
		String serialized = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		String decoded = new String(samlDecode(serialized), StandardCharsets.UTF_8);
		Response response = parse(decoded);
		String issuer = response.getIssuer().getValue();
		RelyingPartyRegistration registration = this.registrations.findUniqueByAssertingPartyEntityId(issuer);
		return tokenByRegistration(request, registration, null);
	}

	private Saml2AuthenticationToken tokenByRegistration(HttpServletRequest request,
			RelyingPartyRegistration registration, AbstractSaml2AuthenticationRequest authenticationRequest) {
		if (registration == null) {
			return null;
		}
		String serialized = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		String decoded = inflateIfRequired(request, samlDecode(serialized));
		UriResolver resolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		registration = registration.mutate().entityId(resolver.resolve(registration.getEntityId()))
				.assertionConsumerServiceLocation(resolver.resolve(registration.getAssertionConsumerServiceLocation()))
				.build();
		return new Saml2AuthenticationToken(registration, decoded, authenticationRequest);
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to load authentication
	 * request.
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.loader = authenticationRequestRepository::loadAuthenticationRequest;
	}

	/**
	 * Use the given {@link RequestMatcher} to match the request.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	private AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		return this.loader.apply(request);
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private byte[] samlDecode(String base64EncodedPayload) {
		try {
			BASE_64_CHECKER.checkAcceptable(base64EncodedPayload);
			return BASE64.decode(base64EncodedPayload);
		}
		catch (Exception ex) {
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Failed to decode SAMLResponse"), ex);
		}
	}

	private String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
			inflaterOutputStream.write(b);
			inflaterOutputStream.finish();
			return out.toString(StandardCharsets.UTF_8.name());
		}
		catch (Exception ex) {
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Unable to inflate string"), ex);
		}
	}

	private Response parse(String request) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(request.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (Response) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutRequest", ex);
		}
	}

	static class Base64Checker {

		private static final int[] values = genValueMapping();

		Base64Checker() {

		}

		private static int[] genValueMapping() {
			byte[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
					.getBytes(StandardCharsets.ISO_8859_1);

			int[] values = new int[256];
			Arrays.fill(values, -1);
			for (int i = 0; i < alphabet.length; i++) {
				values[alphabet[i] & 0xff] = i;
			}
			return values;
		}

		boolean isAcceptable(String s) {
			int goodChars = 0;
			int lastGoodCharVal = -1;

			// count number of characters from Base64 alphabet
			for (int i = 0; i < s.length(); i++) {
				int val = values[0xff & s.charAt(i)];
				if (val != -1) {
					lastGoodCharVal = val;
					goodChars++;
				}
			}

			// in cases of an incomplete final chunk, ensure the unused bits are zero
			switch (goodChars % 4) {
			case 0:
				return true;
			case 2:
				return (lastGoodCharVal & 0b1111) == 0;
			case 3:
				return (lastGoodCharVal & 0b11) == 0;
			default:
				return false;
			}
		}

		void checkAcceptable(String ins) {
			if (!isAcceptable(ins)) {
				throw new IllegalArgumentException("Unaccepted Encoding");
			}
		}

	}

}
