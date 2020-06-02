/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.http;

import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Elements;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.springframework.web.client.RestOperations;

/**
 * A {@link BeanDefinitionParser} for &lt;http&gt;'s &lt;oauth2-resource-server&gt; element.
 *
 * @since 5.3
 * @author Josh Cummings
 */
final class OAuth2ResourceServerBeanDefinitionParser implements BeanDefinitionParser {
	static final String AUTHENTICATION_MANAGER_RESOLVER_REF = "authentication-manager-resolver-ref";
	static final String BEARER_TOKEN_RESOLVER_REF = "bearer-token-resolver-ref";
	static final String ENTRY_POINT_REF = "entry-point-ref";

	static final String BEARER_TOKEN_RESOLVER = "bearerTokenResolver";
	static final String AUTHENTICATION_ENTRY_POINT = "authenticationEntryPoint";

	private final BeanReference authenticationManager;
	private final List<BeanReference> authenticationProviders;
	private final Map<BeanDefinition, BeanMetadataElement> entryPoints;
	private final Map<BeanDefinition, BeanMetadataElement> deniedHandlers;
	private final List<BeanDefinition> ignoreCsrfRequestMatchers;

	private final BeanDefinition authenticationEntryPoint =
			new RootBeanDefinition(BearerTokenAuthenticationEntryPoint.class);
	private final BeanDefinition accessDeniedHandler =
			new RootBeanDefinition(BearerTokenAccessDeniedHandler.class);

	OAuth2ResourceServerBeanDefinitionParser(BeanReference authenticationManager,
			List<BeanReference> authenticationProviders,
			Map<BeanDefinition, BeanMetadataElement> entryPoints,
			Map<BeanDefinition, BeanMetadataElement> deniedHandlers,
			List<BeanDefinition> ignoreCsrfRequestMatchers) {
		this.authenticationManager = authenticationManager;
		this.authenticationProviders = authenticationProviders;
		this.entryPoints = entryPoints;
		this.deniedHandlers = deniedHandlers;
		this.ignoreCsrfRequestMatchers = ignoreCsrfRequestMatchers;
	}

	/**
	 * Parse a &lt;oauth2-resource-server&gt; element and return the corresponding
	 * {@link BearerTokenAuthenticationFilter}
	 *
	 * @param oauth2ResourceServer the &lt;oauth2-resource-server&gt; element.
	 * @param pc the {@link ParserContext}
	 * @return a {@link BeanDefinition} representing a {@link BearerTokenAuthenticationFilter} definition
	 */
	@Override
	public BeanDefinition parse(Element oauth2ResourceServer, ParserContext pc) {
		Element jwt = DomUtils.getChildElementByTagName(oauth2ResourceServer, Elements.JWT);
		Element opaqueToken = DomUtils.getChildElementByTagName(oauth2ResourceServer, Elements.OPAQUE_TOKEN);

		validateConfiguration(oauth2ResourceServer, jwt, opaqueToken, pc);

		if (jwt != null) {
			BeanDefinition jwtAuthenticationProvider =
					new JwtBeanDefinitionParser().parse(jwt, pc);
			this.authenticationProviders.add(new RuntimeBeanReference
					(pc.getReaderContext().registerWithGeneratedName(jwtAuthenticationProvider)));
		}

		if (opaqueToken != null) {
			BeanDefinition opaqueTokenAuthenticationProvider =
					new OpaqueTokenBeanDefinitionParser().parse(opaqueToken, pc);
			this.authenticationProviders.add(new RuntimeBeanReference
					(pc.getReaderContext().registerWithGeneratedName(opaqueTokenAuthenticationProvider)));
		}

		BeanMetadataElement bearerTokenResolver = getBearerTokenResolver(oauth2ResourceServer);
		BeanDefinitionBuilder requestMatcherBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(BearerTokenRequestMatcher.class);
		requestMatcherBuilder.addConstructorArgValue(bearerTokenResolver);
		BeanDefinition requestMatcher = requestMatcherBuilder.getBeanDefinition();

		BeanMetadataElement authenticationEntryPoint = getEntryPoint(oauth2ResourceServer);

		this.entryPoints.put(requestMatcher, authenticationEntryPoint);
		this.deniedHandlers.put(requestMatcher, this.accessDeniedHandler);
		this.ignoreCsrfRequestMatchers.add(requestMatcher);

		BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(BearerTokenAuthenticationFilter.class);
		BeanMetadataElement authenticationManagerResolver = getAuthenticationManagerResolver(oauth2ResourceServer);
		filterBuilder.addConstructorArgValue(authenticationManagerResolver);
		filterBuilder.addPropertyValue(BEARER_TOKEN_RESOLVER, bearerTokenResolver);
		filterBuilder.addPropertyValue(AUTHENTICATION_ENTRY_POINT, authenticationEntryPoint);
		return filterBuilder.getBeanDefinition();
	}

	void validateConfiguration(Element oauth2ResourceServer, Element jwt, Element opaqueToken, ParserContext pc) {
		if (!oauth2ResourceServer.hasAttribute(AUTHENTICATION_MANAGER_RESOLVER_REF)) {
			if (jwt == null && opaqueToken == null) {
				pc.getReaderContext().error
						("Didn't find authentication-manager-resolver-ref, <jwt>, or <opaque-token>. " +
								"Please select one.", oauth2ResourceServer);
			}
			return;
		}

		if (jwt != null) {
			pc.getReaderContext().error
					("Found <jwt> as well as authentication-manager-resolver-ref. " +
							"Please select just one.", oauth2ResourceServer);
		}

		if (opaqueToken != null) {
			pc.getReaderContext().error
					("Found <opaque-token> as well as authentication-manager-resolver-ref. " +
							"Please select just one.", oauth2ResourceServer);
		}
	}

	BeanMetadataElement getAuthenticationManagerResolver(Element element) {
		String authenticationManagerResolverRef = element.getAttribute(AUTHENTICATION_MANAGER_RESOLVER_REF);
		if (!StringUtils.isEmpty(authenticationManagerResolverRef)) {
			return new RuntimeBeanReference(authenticationManagerResolverRef);
		}
		BeanDefinitionBuilder authenticationManagerResolver = BeanDefinitionBuilder
				.rootBeanDefinition(StaticAuthenticationManagerResolver.class);
		authenticationManagerResolver.addConstructorArgValue(this.authenticationManager);
		return authenticationManagerResolver.getBeanDefinition();
	}

	BeanMetadataElement getBearerTokenResolver(Element element) {
		String bearerTokenResolverRef = element.getAttribute(BEARER_TOKEN_RESOLVER_REF);
		if (StringUtils.isEmpty(bearerTokenResolverRef)) {
			return new RootBeanDefinition(DefaultBearerTokenResolver.class);
		} else {
			return new RuntimeBeanReference(bearerTokenResolverRef);
		}
	}

	BeanMetadataElement getEntryPoint(Element element) {
		String entryPointRef = element.getAttribute(ENTRY_POINT_REF);
		if (StringUtils.isEmpty(entryPointRef)) {
			return this.authenticationEntryPoint;
		} else {
			return new RuntimeBeanReference(entryPointRef);
		}
	}
}

final class JwtBeanDefinitionParser implements BeanDefinitionParser {
	static final String DECODER_REF = "decoder-ref";
	static final String JWK_SET_URI = "jwk-set-uri";
	static final String JWT_AUTHENTICATION_CONVERTER_REF = "jwt-authentication-converter-ref";
	static final String JWT_AUTHENTICATION_CONVERTER = "jwtAuthenticationConverter";

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		validateConfiguration(element, pc);

		BeanDefinitionBuilder jwtProviderBuilder =
				BeanDefinitionBuilder.rootBeanDefinition(JwtAuthenticationProvider.class);
		jwtProviderBuilder.addConstructorArgValue(getDecoder(element));
		jwtProviderBuilder.addPropertyValue(JWT_AUTHENTICATION_CONVERTER, getJwtAuthenticationConverter(element));

		return jwtProviderBuilder.getBeanDefinition();
	}

	void validateConfiguration(Element element, ParserContext pc) {
		boolean usesDecoder = element.hasAttribute(DECODER_REF);
		boolean usesJwkSetUri = element.hasAttribute(JWK_SET_URI);

		if (usesDecoder == usesJwkSetUri) {
			pc.getReaderContext().error
					("Please specify either decoder-ref or jwk-set-uri.", element);
		}
	}

	Object getDecoder(Element element) {
		String decoderRef = element.getAttribute(DECODER_REF);
		if (!StringUtils.isEmpty(decoderRef)) {
			return new RuntimeBeanReference(decoderRef);
		}

		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.rootBeanDefinition(NimbusJwtDecoderJwkSetUriFactoryBean.class);
		builder.addConstructorArgValue(element.getAttribute(JWK_SET_URI));
		return builder.getBeanDefinition();
	}

	Object getJwtAuthenticationConverter(Element element) {
		String jwtDecoderRef = element.getAttribute(JWT_AUTHENTICATION_CONVERTER_REF);
		if (!StringUtils.isEmpty(jwtDecoderRef)) {
			return new RuntimeBeanReference(jwtDecoderRef);
		}

		return new JwtAuthenticationConverter();
	}

	JwtBeanDefinitionParser() {}
}

final class OpaqueTokenBeanDefinitionParser implements BeanDefinitionParser {
	static final String INTROSPECTOR_REF = "introspector-ref";
	static final String INTROSPECTION_URI = "introspection-uri";
	static final String CLIENT_ID = "client-id";
	static final String CLIENT_SECRET = "client-secret";

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		validateConfiguration(element, pc);

		BeanMetadataElement introspector = getIntrospector(element);
		BeanDefinitionBuilder opaqueTokenProviderBuilder =
				BeanDefinitionBuilder.rootBeanDefinition(OpaqueTokenAuthenticationProvider.class);
		opaqueTokenProviderBuilder.addConstructorArgValue(introspector);

		return opaqueTokenProviderBuilder.getBeanDefinition();
	}

	void validateConfiguration(Element element, ParserContext pc) {
		boolean usesIntrospector = element.hasAttribute(INTROSPECTOR_REF);
		boolean usesEndpoint = element.hasAttribute(INTROSPECTION_URI) ||
				element.hasAttribute(CLIENT_ID) ||
				element.hasAttribute(CLIENT_SECRET);

		if (usesIntrospector == usesEndpoint) {
			pc.getReaderContext().error
					("Please specify either introspector-ref or all of " +
							"introspection-uri, client-id, and client-secret.", element);
			return;
		}

		if (usesEndpoint) {
			if (!(element.hasAttribute(INTROSPECTION_URI) &&
					element.hasAttribute(CLIENT_ID) &&
					element.hasAttribute(CLIENT_SECRET))) {
				pc.getReaderContext().error
						("Please specify introspection-uri, client-id, and client-secret together", element);
			}
		}
	}

	BeanMetadataElement getIntrospector(Element element) {
		String introspectorRef = element.getAttribute(INTROSPECTOR_REF);
		if (!StringUtils.isEmpty(introspectorRef)) {
			return new RuntimeBeanReference(introspectorRef);
		}

		String introspectionUri = element.getAttribute(INTROSPECTION_URI);
		String clientId = element.getAttribute(CLIENT_ID);
		String clientSecret = element.getAttribute(CLIENT_SECRET);

		BeanDefinitionBuilder introspectorBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(NimbusOpaqueTokenIntrospector.class);
		introspectorBuilder.addConstructorArgValue(introspectionUri);
		introspectorBuilder.addConstructorArgValue(clientId);
		introspectorBuilder.addConstructorArgValue(clientSecret);

		return introspectorBuilder.getBeanDefinition();
	}

	OpaqueTokenBeanDefinitionParser() {}
}

final class StaticAuthenticationManagerResolver implements
		AuthenticationManagerResolver<HttpServletRequest> {
	private final AuthenticationManager authenticationManager;

	StaticAuthenticationManagerResolver(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public AuthenticationManager resolve(HttpServletRequest context) {
		return this.authenticationManager;
	}
}

final class NimbusJwtDecoderJwkSetUriFactoryBean implements FactoryBean<JwtDecoder> {
	private final String jwkSetUri;
	private RestOperations restOperations;

	NimbusJwtDecoderJwkSetUriFactoryBean(String jwkSetUri) {
		this.jwkSetUri = jwkSetUri;
	}

	@Override
	public JwtDecoder getObject() {
		final NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri);
		return restOperations == null
				? builder.build()
				: builder.restOperations(restOperations).build();
	}

	@Override
	public Class<?> getObjectType() {
		return JwtDecoder.class;
	}

	@Autowired(required = false)
	public void setRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
	}
}

final class BearerTokenRequestMatcher implements RequestMatcher {
	private final BearerTokenResolver bearerTokenResolver;

	BearerTokenRequestMatcher(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		try {
			return this.bearerTokenResolver.resolve(request) != null;
		} catch (OAuth2AuthenticationException e) {
			return false;
		}
	}
}

