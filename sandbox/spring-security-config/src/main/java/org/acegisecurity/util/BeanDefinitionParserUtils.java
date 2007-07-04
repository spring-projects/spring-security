/**
 * 
 */
package org.acegisecurity.util;

import org.springframework.beans.factory.config.RuntimeBeanNameReference;
import org.springframework.beans.factory.support.BeanDefinitionReaderUtils;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Vishal Puri
 * 
 */
public class BeanDefinitionParserUtils {
	// ~ Constructor
	// ================================================================================================

	/**
	 * Prevents instantiation
	 */
	private BeanDefinitionParserUtils() {
	}

	// ~ Method
	// ================================================================================================

	public static void setConstructorArgumentIfAvailable(int index, Element element, String attribute,
			boolean isRunTimeBeanReference, RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			if (!isRunTimeBeanReference) {
				definition.getConstructorArgumentValues().addIndexedArgumentValue(index, propertyValue);
			}
			else {
				definition.getConstructorArgumentValues().addIndexedArgumentValue(index,
						new RuntimeBeanNameReference(propertyValue));
			}
		}
	}

	public static void setPropertyIfAvailable(Element element, String attribute, String property,
			boolean isRunTimeBeanReference, RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			if (!isRunTimeBeanReference) {
				definition.getPropertyValues().addPropertyValue(property, propertyValue);
			}
			else {
				definition.getPropertyValues().addPropertyValue(property, new RuntimeBeanNameReference(propertyValue));
			}

		}
	}
}
