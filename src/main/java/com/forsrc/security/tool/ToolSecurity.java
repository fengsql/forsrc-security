package com.forsrc.security.tool;

import com.forsrc.security.model.UserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class ToolSecurity {

  /**
   * 设置授权信息。
   * @param request 请求。
   */
  public static void setAuthentication(HttpServletRequest request) {
    Authentication authentication = getAuthentication(request);
    SecurityContextHolder.getContext().setAuthentication(authentication); // 设置授权信息到上下文
  }

  /**
   * 获取当前用户信息。
   * @return 当前用户信息。
   */
  public static UserDetail getUserDetail() {
    Authentication authentication = getAuthentication();
    if (authentication == null) {
      return null;
    }
    return getUserDetail(authentication);
  }

  /**
   * 获取当前用户名。
   * @return 当前用户名。
   */
  public static String getUsername() {
    Authentication authentication = getAuthentication();
    if (authentication == null) {
      return null;
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetails) {
      return ((UserDetails) principal).getUsername();
    }
    return null;
  }

  /**
   * 获取当前用户信息。
   * @param authentication 认证信息。
   * @return 当前用户信息。
   */
  public static UserDetail getUserDetail(Authentication authentication) {
    if (authentication == null) {
      return null;
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetail) {
      return (UserDetail) principal;
    }
    return null;
  }

  private static Authentication getAuthentication(HttpServletRequest request) {
    Authentication authentication = getAuthentication();
    if (authentication == null) {
      authentication = ToolToken.getAuthenticationFromToken(request); // 获取令牌并根据令牌获取授权信息
    }
    return authentication;
  }

  /**
   * 获取当前认证信息
   * @return 当前认证信息。
   */
  private static Authentication getAuthentication() {
    if (SecurityContextHolder.getContext() == null) {
      return null;
    }
    return SecurityContextHolder.getContext().getAuthentication();
  }

}
