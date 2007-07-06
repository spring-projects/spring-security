/**
 * 
 */
package org.acegisecurity.util;

import org.springframework.beans.factory.config.RuntimeBeanNameReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * The convenience methods for the parsing of bean definition xml file.
 * 
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

	/**
	 * <p>
	 * Configure a <code>BeanDefinition</code>with the property value
	 * retrieved from xml attribute. If the attribute is like a standard spring
	 * 'ref' attribute as indicated by 'isRunTimeBeanReference', the property
	 * will be resolved as a reference to the spring bean.
	 * </p>
	 * 
	 * @param element The parent element.
	 * @param attribute The child attribute.
	 * @param property The configuration property for the BeanDefinition
	 * @param isRunTimeBeanReference Indicates if the property is like a
	 * standard spring 'ref' attribute.
	 * @param definition The BeanDefinition to configure with the property
	 * provided.
	 * @return boolean To indicate if BeanDefinition was configured with a
	 * property.
	 */
	public static boolean setPropertyIfAvailable(Element element, String attribute, String property,
			boolean isRunTimeBeanReference, RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			if (!isRunTimeBeanReference) {
				definition.getPropertyValues().addPropertyValue(property, propertyValue);
				return true;
			}
			else {
				definition.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(propertyValue));
				return true;
			}
		}
		return false;
	}
	
	/**
	 * @param parserContext
	 * @param defintion
	 */
	public static  void registerBeanDefinition(ParserContext parserContext, RootBeanDefinition defintion) {
		parserContext.getRegistry().registerBeanDefinition(
				parserContext.getReaderContext().generateBeanName(defintion), defintion);
	}
}
