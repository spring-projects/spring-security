package org.springframework.security.ui;

import org.springframework.core.Ordered;

/**
 * Stores the default order numbers of all Spring Security filters for use in configuration.
 *
 * @author luke
 * @version $Id$
 */
public class FilterChainOrderUtils {
    /**
     * The first position at which a Spring Security filter will be found. Any filter with an order less than this will
     * be guaranteed to be placed before the Spring Security filters in the stack.
     */
    public static final int FILTER_CHAIN_FIRST = Ordered.HIGHEST_PRECEDENCE + 1000;
    private static final int INTERVAL = 100;

    public static final int CHANNEL_PROCESSING_FILTER_ORDER            = FILTER_CHAIN_FIRST + INTERVAL;
    public static final int CONCURRENT_SESSION_FILTER_ORDER            = FILTER_CHAIN_FIRST + INTERVAL * 2;
    public static final int HTTP_SESSION_CONTEXT_FILTER_ORDER          = FILTER_CHAIN_FIRST + INTERVAL * 3;
    public static final int LOGOUT_FILTER_ORDER                        = FILTER_CHAIN_FIRST + INTERVAL * 4;
    public static final int AUTH_PROCESSING_FILTER_ORDER               = FILTER_CHAIN_FIRST + INTERVAL * 5;
    public static final int CAS_PROCESSING_FILTER_ORDER                = FILTER_CHAIN_FIRST + INTERVAL * 5;
    public static final int LOGIN_PAGE_FILTER_ORDER                    = FILTER_CHAIN_FIRST + INTERVAL * 6;
    public static final int BASIC_PROCESSING_FILTER_ORDER              = FILTER_CHAIN_FIRST + INTERVAL * 7;
    public static final int SECURITY_CONTEXT_HOLDER_AWARE_FILTER_ORDER = FILTER_CHAIN_FIRST + INTERVAL * 8;
    public static final int REMEMBER_ME_FILTER_ORDER                   = FILTER_CHAIN_FIRST + INTERVAL * 9;
    public static final int ANON_PROCESSING_FILTER_ORDER               = FILTER_CHAIN_FIRST + INTERVAL * 10;
    public static final int SWITCH_USER_FILTER_ORDER                   = FILTER_CHAIN_FIRST + INTERVAL * 11;
    public static final int EXCEPTION_TRANSLATION_FILTER_ORDER         = FILTER_CHAIN_FIRST + INTERVAL * 12;
    public static final int NTLM_FILTER_ORDER                          = FILTER_CHAIN_FIRST + INTERVAL * 13;
    public static final int FILTER_SECURITY_INTERCEPTOR_ORDER          = FILTER_CHAIN_FIRST + INTERVAL * 14;
}
