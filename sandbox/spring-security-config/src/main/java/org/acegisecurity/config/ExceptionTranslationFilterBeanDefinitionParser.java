/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * <p>
 * This class parses the <security:exception-translation /> tag and creates the
 * bean defintion for <code>ExceptionTranslationFilter</code>.</br> The
 * '&lt;security:access-denied .. /&gt;' tag is optional and if not specified
 * <code>ExceptionTranslationFilter</code> <br/> will autodetect the instance
 * of <code>AccessDeniedHandler</code>; alternately if there are > 1 such
 * handlers, <br/>we can nominate the one to use via 'accessDeniedBeanRef'.
 * </p>
 * 
 * <p>
 * The 'entryPointBeanRef' and 'accessDeniedBeanRef' can be specified as
 * attributes or inner bean definitions. <br/> See following sample showing both
 * ways.
 * </p>
 * 
 * <p>
 * Sample: <d1>
 * <dt> &lt;security:exception-translation id="exceptionTranslationFilter"&gt;
 * </dt>
 * <dd> &lt;security:entry-point
 * entryPointBeanRef="authenticationProcessingFilterEntryPoint" /&gt; </dd>
 * <dd> &lt;security:access-denied accessDeniedBeanRef="theBeanToUse" /&gt;
 * </dd>
 * <dt>&lt;/security:exception-translation&gt;</dt>
 * </d1> or <d1>
 * <dt> &lt;security:exception-translation id="exceptionTranslationFilter"
 * entryPointBeanRef="ref" accessDeniedBeanRef="ref" /&gt;</dt>
 * </d1>
 * </p>
 * 
 * @author Vishal Puri
 * @version
 * @see {@link org.acegisecurity.ui.ExceptionTranslationFilter}
 * @see {@link org.acegisecurity.ui.AccessDeniedHandler}
 */
public class ExceptionTranslationFilterBeanDefinitionParser extends AbstractBeanDefinitionParser {

	private static final String ACCESS_DENIED = "access-denied";

	private static final String ACCESS_DENIED_REF = "accessDeniedBeanRef";

	private static final String ACCESS_DENIED_URL = "accessDeniedUrl";

	private static final String ENTRY_POINT = "entry-point";

	private static final String ENTRY_POINT_REF = "entryPointBeanRef";

	private static final String LOGIN_FORM_URL = "loginFormUrl";

	private static final String LOGIN_FORM_URL_VALUE = "/acegilogin.jsp";

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		RootBeanDefinition exceptionFilterDef = new RootBeanDefinition(ExceptionTranslationFilter.class);

		// add handler
		Element accessDeniedElement = DomUtils.getChildElementByTagName(element, ACCESS_DENIED);
		setAccessDeniedHandlerProperty(parserContext, exceptionFilterDef, accessDeniedElement);

		Element entryPointElement = DomUtils.getChildElementByTagName(element, ENTRY_POINT);
		setEntryPointProperty(exceptionFilterDef, entryPointElement);

		return exceptionFilterDef;
	}

	private void setEntryPointProperty(RootBeanDefinition exceptionFilterDef, Element entryPointElement) {
		if (entryPointElement != null) {
			setBeanReferenceOrInnerBeanDefinitions(exceptionFilterDef, entryPointElement, "authenticationEntryPoint",
					entryPointElement.getAttribute(ENTRY_POINT_REF));
		}
	}

	/**
	 * Resolves are reference to 'accessDeniedHandler' property.
	 * @param parserContext
	 * @param exceptionFilterDef The ExceptionFilter BeanDefinition
	 * @param accessDeniedElement The inner tag for accessDeniedHandler
	 * property.
	 */
	private void setAccessDeniedHandlerProperty(ParserContext parserContext, RootBeanDefinition exceptionFilterDef,
			Element accessDeniedElement) {
		if (accessDeniedElement != null) {
			setBeanReferenceOrInnerBeanDefinitions(exceptionFilterDef, accessDeniedElement, "accessDeniedHandler",
					accessDeniedElement.getAttribute(ACCESS_DENIED_REF));
		}
	}

	/**
	 * Add property if it's specified as an attribute or inner tag.
	 * 
	 * @param exceptionFilterDef The ExceptionFilter BeanDefinition
	 * @param element The inner bean element
	 * @param property The property to add
	 * @param beanRef The bean reference to resolve.
	 */
	private void setBeanReferenceOrInnerBeanDefinitions(RootBeanDefinition exceptionFilterDef, Element element,
			String property, String beanRef) {
		// check for encoderBeanRef attribute
		if (StringUtils.hasLength(beanRef)) {
			exceptionFilterDef.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(beanRef));
		}
		else {
			doSetInnerBeanDefinitions(exceptionFilterDef, element, property);
		}
	}

	/**
	 * Add property specified as an inner bean definition.
	 * @param exceptionFilterDef The ExceptionFilter BeanDefinition
	 * @param element The inner bean element
	 * @param property The property to add
	 */
	private void doSetInnerBeanDefinitions(RootBeanDefinition exceptionFilterDef, Element accessDeniedElement,
			String property) {
		RootBeanDefinition accessDeniedHandlerBeanDef = new RootBeanDefinition(AccessDeniedHandlerImpl.class);
		setPropertyIfAvailable(accessDeniedElement, ACCESS_DENIED_URL, "errorPage", accessDeniedHandlerBeanDef);
		exceptionFilterDef.getPropertyValues().addPropertyValue(property, accessDeniedHandlerBeanDef);

	}

	/**
	 * @param element
	 * @param attribute
	 * @param property
	 * @param definition
	 */
	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}

	/**
	 * Creates <code>BeanDefintion</code> for
	 * <code>ExceptionTranslationFilter</code> with it's default properties.
	 * @return beanDefinition The bean defintion configured with default
	 * properties
	 */
	protected static RootBeanDefinition createBeanDefinitionWithDefaults() {
		RootBeanDefinition beanDefinition = new RootBeanDefinition(ExceptionTranslationFilter.class);
		beanDefinition.getPropertyValues().addPropertyValue("authenticationEntryPoint",
				createBeanDefintionForAuthenticationProcessingFilterEntryPoint());
		return beanDefinition;
	}

	/**
	 * Creates <code>BeanDefintion</code> for
	 * <code>AuthenticationProcessingFilterEntryPoint</code> with it's default
	 * properties.
	 * @return beanDefinition The bean defintion configured with default
	 */
	protected static RootBeanDefinition createBeanDefintionForAuthenticationProcessingFilterEntryPoint() {
		RootBeanDefinition beanDefinition = new RootBeanDefinition(AuthenticationProcessingFilterEntryPoint.class);
		beanDefinition.getPropertyValues().addPropertyValue(LOGIN_FORM_URL, LOGIN_FORM_URL_VALUE);
		return beanDefinition;
	}
}
