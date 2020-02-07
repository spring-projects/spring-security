/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.samples.cas.pages;

import java.util.function.Function;

import org.openqa.selenium.WebDriver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Josh Cummings
 */
public abstract class Page<T extends Page<T>> {
	private final WebDriver driver;
	private final String url;

	protected Page(WebDriver driver, String url) {
		this.driver = driver;
		this.url = url;
	}

	public T assertAt() {
		assertThat(this.driver.getCurrentUrl()).startsWith(this.url);
		return (T) this;
	}

	public T to() {
		this.driver.get(this.url);
		return (T) this;
	}

	public T to(Function<String, String> urlPostProcessor) {
		this.driver.get(urlPostProcessor.apply(this.url));
		return (T) this;
	}
}
