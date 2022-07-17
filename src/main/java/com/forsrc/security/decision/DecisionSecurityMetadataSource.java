package com.forsrc.security.decision;

import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.config.ConstSecurity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Slf4j
public class DecisionSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

  private final AntPathMatcher antPathMatcher = new AntPathMatcher();

  /**
   * 返回访问页面需要的角色。null 时直接通过，且不进入 AccessDecisionManager.decide 方法。
   * @param object 请求的 requset 信息，HttpServletRequest request = ((FilterInvocation) object).getHttpRequest()。
   * @return 返回访问页面需要的角色。
   */
  @Override
  public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
    FilterInvocation filterInvocation = (FilterInvocation) object;
    if (isMatcherAllowedRequest(filterInvocation)) {
      log.debug("getAttributes isMatcherAllowedRequest pass.");
      return null; //return null 表示允许访问，不做拦截
    }

    String url = filterInvocation.getRequestUrl();
    log.debug("getAttributes url: {}", url);

    //    Authentication authentication = ToolSecurity.getAuthentication();
    //    log.debug("getAttributes authentication: {}", authentication);

    List<String> roles = new ArrayList<>();
    addRole(url, roles);
    if (roles.size() > 0) {
      String[] ary = roles.toArray(new String[0]);
      log.debug("getAttributes roles: {}. size: {}", ary, ary.length);
      return SecurityConfig.createList(ary);
    }
    if (ConfigSecurity.security.permitAccessUrlUndefine) {
      log.info("permit access url undefine. url: {}", url);
      return null;
    }
    log.warn("forbid access! url: {}", url);
    return SecurityConfig.createList("ROLE_LOGIN");  //其余需要登录才可以访问
  }

  @Override
  public Collection<ConfigAttribute> getAllConfigAttributes() {
    return null;
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return true;
  }

  private void addRole(String url, List<String> roles) {
    if (!addMatchAll(url, roles)) {
      addMatchRole(url, roles);
    }
  }

  private boolean addMatchAll(String url, List<String> roles) {
    if (ConfigSecurity.security.all == null) {
      return false;
    }
    for (String path : ConfigSecurity.security.all) { //所有角色都可以访问，已登录用户
      if (antPathMatcher.match(path, url)) {
        log.debug("getAttributes all role pass.");
        roles.add(ConstSecurity.role.all);
        return true;
      }
    }
    return false;
  }

  private void addMatchRole(String url, List<String> roles) {
    if (ConfigSecurity.security.role == null) {
      return;
    }
    for (Map.Entry<String, List<String>> entry : ConfigSecurity.security.role.entrySet()) { //指定角色可以访问
      String role = entry.getKey();
      List<String> paths = entry.getValue();
      for (String path : paths) {
        if (antPathMatcher.match(path, url)) {
          roles.add(role);
          break;
        }
      }
    }
  }

  private boolean isMatcherAllowedRequest(FilterInvocation filterInvocation) {
    List<String> allowedRequest = ConfigSecurity.security.permit;
    if (allowedRequest == null) {
      return false;
    }
    return allowedRequest.stream().map(AntPathRequestMatcher::new).filter(requestMatcher ->  //
      requestMatcher.matches(filterInvocation.getHttpRequest())).toArray().length > 0;
  }

}