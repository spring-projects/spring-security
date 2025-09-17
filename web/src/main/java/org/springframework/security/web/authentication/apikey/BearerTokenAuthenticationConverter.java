package org.springframework.security.web.authentication.apikey;

import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.apikey.ApiKey;
import org.springframework.security.authentication.apikey.ApiKeyAuthenticationException;
import org.springframework.security.authentication.apikey.ApiKeyToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;

/**
 * @author Alexey Razinkov
 */
public final class BearerTokenAuthenticationConverter implements AuthenticationConverter {

	private final Function<byte[], String> encoder;

	private final Function<String, byte[]> decoder;

	private final AuthenticationDetailsSource<HttpServletRequest, ?> detailsSource;

	public BearerTokenAuthenticationConverter() {
		this(Base64.getEncoder()::encodeToString, Base64.getDecoder()::decode, new WebAuthenticationDetailsSource());
	}

	public BearerTokenAuthenticationConverter(Function<byte[], String> encoder, Function<String, byte[]> decoder,
			AuthenticationDetailsSource<HttpServletRequest, ?> detailsSource) {
		this.encoder = Objects.requireNonNull(encoder);
		this.decoder = Objects.requireNonNull(decoder);
		this.detailsSource = Objects.requireNonNull(detailsSource);
	}

	@Override
	@Nullable public Authentication convert(final HttpServletRequest request) {
		String headerValue = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (!StringUtils.hasText(headerValue)) {
			return null;
		}

		headerValue = headerValue.stripLeading();
		if (!headerValue.startsWith(SCHEME_PREFIX)) {
			throw new ApiKeyAuthenticationException.MissingBearerScheme();
		}

		final String apiKeyToken = headerValue.substring(SCHEME_PREFIX.length());
		if (!StringUtils.hasText(apiKeyToken)) {
			throw new ApiKeyAuthenticationException.MissingBearerToken();
		}

		final ApiKey apiKey;
		try {
			apiKey = ApiKey.parse(apiKeyToken, encoder, decoder);
		}
		catch (final Exception ex) {
			throw new ApiKeyAuthenticationException.Invalid(apiKeyToken, ex);
		}

		final Object details = this.detailsSource.buildDetails(request);
		return new ApiKeyToken(apiKey, details);
	}

	private static final String SCHEME_PREFIX = "Bearer ";

}
