package com.furkan.userregistration.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "properties.jwt")
public class JwtProperties {
    private long expiration;
    private String secret;
}
