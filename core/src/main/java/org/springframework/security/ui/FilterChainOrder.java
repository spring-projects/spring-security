package org.springframework.security.ui;

import org.springframework.core.Ordered;

/**
 * Stores the default order numbers of all Spring Security filters for use in configuration.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class FilterChainOrder {
    /**
     * The first position at which a Spring Security filter will be found. Any filter with an order less than this will
     * be guaranteed to be placed before the Spring Security filters in the stack.
     */
    public static final int FILTER_CHAIN_FIRST = Ordered.HIGHEST_PRECEDENCE + 1000;
    private static final int INTERVAL = 100;
    private static int i = 1;

    public static final int CHANNEL_PROCESSING_FILTER   = FILTER_CHAIN_FIRST;
    public static final int CONCURRENT_SESSION_FILTER   = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int HTTP_SESSION_CONTEXT_FILTER = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int LOGOUT_FILTER               = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int PRE_AUTH_FILTER             = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int CAS_PROCESSING_FILTER       = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int AUTH_PROCESSING_FILTER      = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int LOGIN_PAGE_FILTER           = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int BASIC_PROCESSING_FILTER     = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int SECURITY_CONTEXT_HOLDER_AWARE_FILTER = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int REMEMBER_ME_FILTER          = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int ANON_PROCESSING_FILTER      = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int EXCEPTION_TRANSLATION_FILTER = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int NTLM_FILTER                 = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int FILTER_SECURITY_INTERCEPTOR = FILTER_CHAIN_FIRST + INTERVAL * i++;
    public static final int SWITCH_USER_FILTER          = FILTER_CHAIN_FIRST + INTERVAL * i++;
}
