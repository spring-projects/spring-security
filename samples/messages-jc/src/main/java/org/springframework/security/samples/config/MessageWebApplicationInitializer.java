package org.springframework.security.samples.config;

import javax.servlet.Filter;

import org.springframework.security.samples.mvc.config.WebMvcConfiguration;
import org.springframework.web.filter.HiddenHttpMethodFilter;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

public class MessageWebApplicationInitializer extends
		AbstractAnnotationConfigDispatcherServletInitializer {

	@Override
	protected Class<?>[] getRootConfigClasses() {
		return new Class[] { RootConfiguration.class };
	}

	@Override
	protected Class<?>[] getServletConfigClasses() {
		return new Class[] { WebMvcConfiguration.class };
	}

	@Override
	protected String[] getServletMappings() {
		return new String[] { "/" };
	}

	@Override
	protected Filter[] getServletFilters() {
		return new Filter[] { new HiddenHttpMethodFilter() };
	}
}
