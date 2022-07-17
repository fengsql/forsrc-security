package com.forsrc.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "security")
@Data
public class ConfigSecurityAuthPath {

  private List<String> permit;

  private List<String> all;

  private List<String> role;

}