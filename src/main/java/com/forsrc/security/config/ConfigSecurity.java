package com.forsrc.security.config;

import com.forsrc.common.tool.Tool;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.util.*;

@Configuration
@Slf4j
public class ConfigSecurity {

  private static final String sep_path = ",";
  private static final String sep_role = ":";

  @Resource
  private ConfigSecurityAuthPath configSecurityAuthPath;

  public static class security {

    public static boolean enable;
    public static String loginUrl;
    public static String logoutUrl;
    public static boolean permitAccessUrlUndefine;

    public static class token {
      public static String name;
      public static String secret;
      public static String expire;
    }

    public static List<String> permit;

    public static List<String> all;

    public static Map<String, List<String>> role;
  }

  @PostConstruct
  private void setValue() {
    setSecurity_permit(configSecurityAuthPath.getPermit());
    setSecurity_all(configSecurityAuthPath.getAll());
    setSecurity_role(configSecurityAuthPath.getRole());
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
  @Value("${security.permit_access_url_undefine:false}")
  public void setSecurity_permitAccessUrlUndefine(String value) {
    security.permitAccessUrlUndefine = Tool.toBoolean(value);
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
    security.token.expire = Tool.toString(value);
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

  private void setSecurity_all(List<String> value) {
    if (value == null) {
      return;
    }
    security.all = new ArrayList<>();
    for (String one : value) {
      if (Tool.isNull(one)) {
        continue;
      }
      String[] paths = Tool.split(one, sep_path);
      security.all.addAll(Arrays.asList(paths));
    }
  }

  private void setSecurity_role(List<String> value) {
    security.role = new HashMap<>();
    if (value == null) {
      return;
    }
    for (String one : value) {
      int pos = one.indexOf(sep_role);
      if (pos <= 0 || pos >= one.length() - 1) {
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
        security.role.put(key, newList(paths));
      } else {
        list.addAll(Arrays.asList(paths));
      }
    }
  }

  private List<String> newList(String[] ary) {
    if (ary == null) {
      return null;
    }
    List<String> list = new ArrayList<>();
    Collections.addAll(list, ary);
    return list;
  }

}

