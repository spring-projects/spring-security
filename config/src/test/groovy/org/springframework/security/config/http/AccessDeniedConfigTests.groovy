package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.access.ExceptionTranslationFilter

/**
 *
 * @author Luke Taylor
 */
class AccessDeniedConfigTests extends AbstractHttpConfigTests {
	def invalidAccessDeniedUrlIsDetected() {
		when:
		httpAutoConfig() {
			'access-denied-handler'('error-page':'noLeadingSlash')
		}
		createAppContext();
		then:
		thrown(BeanCreationException)
	}

	def accessDeniedHandlerIsSetCorectly() {
		httpAutoConfig() {
			'access-denied-handler'(ref: 'adh')
		}
		bean('adh', AccessDeniedHandlerImpl)
		createAppContext();

		def filter = getFilter(ExceptionTranslationFilter.class);
		def adh = appContext.getBean("adh");

		expect:
		filter.accessDeniedHandler == adh
	}

	def void accessDeniedHandlerPageAndRefAreMutuallyExclusive() {
		when:
		httpAutoConfig {
			'access-denied-handler'('error-page': '/go-away', ref: 'adh')
		}
		createAppContext();
		bean('adh', AccessDeniedHandlerImpl)
		then:
		thrown(BeanDefinitionParsingException)
	}
}
