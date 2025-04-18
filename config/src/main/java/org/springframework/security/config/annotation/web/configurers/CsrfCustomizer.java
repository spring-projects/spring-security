package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;

import java.util.function.Supplier;

public class CsrfCustomizer {
	public static Customizer<CsrfConfigurer<HttpSecurity>> spaDefaults() {
		return (csrf) -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
	}

	private static class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
		private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
		private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
			/*
			 * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
			 * the CsrfToken when it is rendered in the response body.
			 */
			this.xor.handle(request, response, csrfToken);
			/*
			 * Render the token value to a cookie by causing the deferred token to be loaded.
			 */
			csrfToken.get();
		}

		@Override
		public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
			String headerValue = request.getHeader(csrfToken.getHeaderName());
			/*
			 * If the request contains a request header, use CsrfTokenRequestAttributeHandler
			 * to resolve the CsrfToken. This applies when a single-page application includes
			 * the header value automatically, which was obtained via a cookie containing the
			 * raw CsrfToken.
			 *
			 * In all other cases (e.g. if the request contains a request parameter), use
			 * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
			 * when a server-side rendered form includes the _csrf request parameter as a
			 * hidden input.
			 */
			return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
		}
	}
}
