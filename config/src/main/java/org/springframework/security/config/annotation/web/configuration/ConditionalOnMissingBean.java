package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.Conditional;

/**
 * @author Rob Winch
 * @since 4.0
 */
@Conditional(OnMissingBeanCondition.class)
@interface ConditionalOnMissingBean {

	Class<?> value();
}
