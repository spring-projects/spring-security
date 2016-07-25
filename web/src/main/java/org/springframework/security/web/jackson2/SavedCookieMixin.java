package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.*;

/**
 * @author Jitendra Singh.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
		getterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class SavedCookieMixin {

	@JsonCreator
	public SavedCookieMixin(@JsonProperty("name") String name, @JsonProperty("value") String value,
							@JsonProperty("comment") String comment, @JsonProperty("domain") String domain,
							@JsonProperty("maxAge") int maxAge, @JsonProperty("path") String path,
							@JsonProperty("secure") boolean secure, @JsonProperty("version") int version) {

	}
}
