package org.springframework.security.web.headers.frameoptions;

import org.springframework.security.web.headers.HeaderWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code HeaderWriter} implementation for the X-Frame-Options headers. When using the ALLOW-FROM directive the actual
 * value is determined by a {@code AllowFromStrategy}.
 *
 * @author Marten Deinum
 * @since 3.2
 *
 * @see AllowFromStrategy
 */
public class FrameOptionsHeaderWriter implements HeaderWriter {

    public static final String FRAME_OPTIONS_HEADER = "X-Frame-Options";

    private static final String ALLOW_FROM = "ALLOW-FROM";

    private final AllowFromStrategy allowFromStrategy;
    private final String mode;

    public FrameOptionsHeaderWriter(String mode) {
        this(mode, new NullAllowFromStrategy());
    }

    public FrameOptionsHeaderWriter(String mode, AllowFromStrategy allowFromStrategy) {
        this.mode=mode;
        this.allowFromStrategy=allowFromStrategy;
    }

    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        if (ALLOW_FROM.equals(mode)) {
            String value = allowFromStrategy.apply(request);
            response.addHeader(FRAME_OPTIONS_HEADER, ALLOW_FROM + " " + value);
        } else {
            response.addHeader(FRAME_OPTIONS_HEADER, mode);
        }
    }

}
