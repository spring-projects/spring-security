package org.springframework.security.web.headers.frameoptions;

import org.springframework.security.web.headers.Header;
import org.springframework.security.web.headers.HeaderFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code HeaderFactory} implementation for the X-Frame-Options headers. When using the ALLOW-FROM directive the actual
 * value is determined by a {@code AllowFromStrategy}.
 *
 * @author Marten Deinum
 * @since 3.2
 *
 * @see AllowFromStrategy
 */
public class FrameOptionsHeaderFactory implements HeaderFactory {

    public static final String FRAME_OPTIONS_HEADER = "X-Frame-Options";

    private static final String ALLOW_FROM = "ALLOW-FROM";

    private final AllowFromStrategy allowFromStrategy;
    private final String mode;

    public FrameOptionsHeaderFactory(String mode) {
        this(mode, new NullAllowFromStrategy());
    }

    public FrameOptionsHeaderFactory(String mode, AllowFromStrategy allowFromStrategy) {
        this.mode=mode;
        this.allowFromStrategy=allowFromStrategy;
    }

    @Override
    public Header create(HttpServletRequest request, HttpServletResponse response) {
        if (ALLOW_FROM.equals(mode)) {
            String value = allowFromStrategy.apply(request);
            return new Header(FRAME_OPTIONS_HEADER, value);
        } else {
            return new Header(FRAME_OPTIONS_HEADER, mode);
        }
    }

}
