package org.springframework.security.web.headers.frameoptions;

import javax.servlet.http.HttpServletRequest;

/**
 * Strategy interfaces used by the {@code FrameOptionsHeaderWriter} to determine the actual value to use for the
 * X-Frame-Options header when using the ALLOW-FROM directive.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public interface AllowFromStrategy {

    String apply(HttpServletRequest request);
}
