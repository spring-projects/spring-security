/**
 * Classes related to the caching of an {@code HttpServletRequest} which requires authentication. While the user is
 * logging in, the request is cached (using the RequestCache implementation) by the ExceptionTranslationFilter.
 * Once the user has been authenticated, the original request is restored following a redirect to a matching URL, and
 * the {@code RequestCache} is queried to obtain the original (matching) request.
 */
package org.springframework.security.web.savedrequest;

