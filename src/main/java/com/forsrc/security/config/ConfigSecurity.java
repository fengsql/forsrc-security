package com.forsrc.security.config;

import com.forsrc.common.tool.Tool;
import com.forsrc.common.tool.ToolBean;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.util.*;

@Configuration
@Slf4j
public class ConfigSecurity {

  private static final String sep_path = ",";
  private static final String sep_role = ":";

  public static class security {

    public static boolean enable;
    public static String loginUrl;
    public static String logoutUrl;
    public static String apiPrefix;

    public static class token {
      public static String name;
      public static String secret;
      public static int expire;
    }

    public static List<String> permit;

    public static Map<String, List<String>> role;
  }

  @PostConstruct
  private void setValue() {
    ConfigSecurityAuthPath configSecurityAuthPath = ToolBean.getBean(ConfigSecurityAuthPath.class);
    setSecurity_permit(configSecurityAuthPath.getPermit());
    setSecurity_role(configSecurityAuthPath.getRole());
  }

  @Configuration
  @ConfigurationProperties(prefix = "security")
  @Data
  public class ConfigSecurityAuthPath {

    private List<String> permit;

    public List<String> role;

  }

  //security-enable
  @Value("${security.enable:false}")
  public void setSecurity_enable(String value) {
    security.enable = Tool.toBoolean(value);
  }

  //security-loginUrl
  @Value("${security.login-url:/auth/login}")
  public void setSecurity_loginUrl(String value) {
    security.loginUrl = Tool.toString(value);
  }

  //security-logoutUrl
  @Value("${security.logout-url:/auth/logout}")
  public void setSecurity_logoutUrl(String value) {
    security.logoutUrl = Tool.toString(value);
  }

  //security-logoutUrl
  @Value("${security.api-prefix:/api}")
  public void setSecurity_apiPrefix(String value) {
    security.apiPrefix = Tool.toString(value);
  }

  //security-token
  @Value("${security.token.name:token}")
  public void setSecurity_token_name(String value) {
    security.token.name = Tool.toString(value);
  }

  @Value("${security.token.secret:}")
  public void setSecurity_token_secret(String value) {
    security.token.secret = Tool.toString(value);
  }

  @Value("${security.token.expire:3600}")
  public void setSecurity_token_expire(String value) {
    security.token.expire = Tool.toInt(value);
  }

  private void setSecurity_permit(List<String> value) {
    if (value == null) {
      return;
    }
    security.permit = new ArrayList<>();
    for (String one : value) {
      if (Tool.isNull(one)) {
        continue;
      }
      String[] paths = Tool.split(one, sep_path);
      security.permit.addAll(Arrays.asList(paths));
    }
  }

  private void setSecurity_role(List<String> value) {
    security.role = new HashMap<>();
    if (value == null) {
      return;
    }
    for (String one : value) {
      int pos = one.indexOf(sep_role);
      if (pos <= 0) {
        continue;
      }
      String key = one.substring(0, pos);
      String val = one.substring(pos + 1);
      if (Tool.isNull(val)) {
        continue;
      }
      String[] paths = Tool.split(val, sep_path);
      List<String> list = security.role.get(key);
      if (list == null) {
        security.role.put(key, Arrays.asList(paths));
      } else {
        list.addAll(Arrays.asList(paths));
      }
    }
  }

}

