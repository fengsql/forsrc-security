package com.forsrc.security.decision;

import com.forsrc.security.config.ConstSecurity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Slf4j
public class DecisionAccess implements AccessDecisionManager {

  /**
   * 判定是否拥有权限的决策方法。
   * @param authentication   FilterAuthentication 过滤器中设置，不会为null，未登录时为 AnonymousAuthenticationToken。
   * @param object           请求的 requset 信息，HttpServletRequest request = ((FilterInvocation) object).getHttpRequest()。
   * @param configAttributes FilterInvocationSecurityMetadataSource.getAttributes(Object object) 方法返回的结果，null不会进入此方法。
   */
  @Override
  public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
    log.debug("decide. authentication: {}", authentication);
    if (configAttributes == null || configAttributes.size() == 0) {
      throw new AccessDeniedException("permission denied");
    }
    //所有访问都需要登录，不需要登录的不会进入此方法
    if (isAnonymous(authentication)) {
      log.info("decide denied no login.");
      throw new AccessDeniedException("permission denied");
    }
    for (ConfigAttribute configAttribute : configAttributes) {
      String needRole = configAttribute.getAttribute();
      log.debug("needRole: {} . authentication: {}", needRole, authentication);

      //      if ("ROLE_ANONYMOUS".equalsIgnoreCase(needRole) && authentication instanceof UsernamePasswordAuthenticationToken) {
      //        log.info("decide anonymous.");
      //        return;
      //      }

      if (isRoleAll(needRole)) {  //所有角色都可以访问，已登录用户
        log.debug("decide all.");
        return;
      }
      for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
        if (isRole(needRole, grantedAuthority)) {
          log.debug("decide role.");
          return;
        }
      }
    }
    //未定义的 url 拒绝访问，抛出异常。如果需要可以访问，注释掉下行。
    throw new AccessDeniedException("permission denied");
  }

  @Override
  public boolean supports(ConfigAttribute attribute) {
    return true;
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return true;
  }

  private boolean isAnonymous(Authentication authentication) {
    return authentication == null || authentication instanceof AnonymousAuthenticationToken;
  }

  private boolean isRoleAll(String needRole) {
    return ConstSecurity.role.all.equals(needRole);
  }

  private boolean isRole(String needRole, GrantedAuthority grantedAuthority) {
    return needRole.equals(grantedAuthority.getAuthority());
  }

}