package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@JsonDeserialize(using = UsernamePasswordAuthenticationTokenDeserializer.class)
public abstract class UsernamePasswordAuthenticationTokenMixin {
}
