/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.Test;

import org.springframework.security.web.access.channel.ChannelProcessingFilter;

import static org.assertj.core.api.Assertions.assertThat;

public class FilterOrderRegistrationTests {

	private final FilterOrderRegistration filterOrderRegistration = new FilterOrderRegistration();

	@Test
	public void putWhenNewFilterThenInsertCorrect() {
		int position = 153;
		this.filterOrderRegistration.put(MyFilter.class, position);
		Integer order = this.filterOrderRegistration.getOrder(MyFilter.class);
		assertThat(order).isEqualTo(position);
	}

	@Test
	public void putWhenCustomFilterAlreadyExistsThenDoesNotOverride() {
		int position = 160;
		this.filterOrderRegistration.put(MyFilter.class, position);
		this.filterOrderRegistration.put(MyFilter.class, 173);
		Integer order = this.filterOrderRegistration.getOrder(MyFilter.class);
		assertThat(order).isEqualTo(position);
	}

	@Test
	public void putWhenPredefinedFilterThenDoesNotOverride() {
		int position = 100;
		Integer predefinedFilterOrderBefore = this.filterOrderRegistration.getOrder(ChannelProcessingFilter.class);
		this.filterOrderRegistration.put(MyFilter.class, position);
		Integer myFilterOrder = this.filterOrderRegistration.getOrder(MyFilter.class);
		Integer predefinedFilterOrderAfter = this.filterOrderRegistration.getOrder(ChannelProcessingFilter.class);
		assertThat(myFilterOrder).isEqualTo(position);
		assertThat(predefinedFilterOrderAfter).isEqualTo(predefinedFilterOrderBefore).isEqualTo(position);
	}

	static class MyFilter implements Filter {

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			filterChain.doFilter(servletRequest, servletResponse);
		}

	}

}
