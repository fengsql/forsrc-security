package com.forsrc.security.tool;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

public class ToolSecurity {

  /**
   * 获取令牌进行认证
   */
  public static void checkAuthentication(HttpServletRequest request) {
    // 获取令牌并根据令牌获取登录认证信息
    Authentication authentication = ToolToken.getAuthenticationeFromToken(request);
    // 设置登录认证信息到上下文
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  /**
   * 获取当前用户名
   */
  public static String getUsername() {
    String username = null;
    Authentication authentication = getAuthentication();
    if (authentication != null) {
      Object principal = authentication.getPrincipal();
      if (principal != null && principal instanceof UserDetails) {
        username = ((UserDetails) principal).getUsername();
      }
    }
    return username;
  }

  /**
   * 获取用户名
   */
  public static String getUsername(Authentication authentication) {
    String username = null;
    if (authentication != null) {
      Object principal = authentication.getPrincipal();
      if (principal != null && principal instanceof UserDetails) {
        username = ((UserDetails) principal).getUsername();
      }
    }
    return username;
  }

  /**
   * 获取当前登录信息
   */
  public static Authentication getAuthentication() {
    if (SecurityContextHolder.getContext() == null) {
      return null;
    }
    return SecurityContextHolder.getContext().getAuthentication();
  }

}
