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
   */
  public static void setAuthentication(HttpServletRequest request) {
    Authentication authentication = ToolToken.getAuthenticationFromToken(request); // 获取令牌并根据令牌获取授权信息
    SecurityContextHolder.getContext().setAuthentication(authentication); // 设置授权信息到上下文
  }

  /**
   * 获取当前用户名
   */
  public static UserDetail getUserDetails() {
    Authentication authentication = getAuthentication();
    if (authentication == null) {
      return null;
    }
    return getUserDetails(authentication);
  }

  /**
   * 获取当前用户名
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
   * 获取用户名
   */
  public static UserDetail getUserDetails(Authentication authentication) {
    if (authentication == null) {
      return null;
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetail) {
      return (UserDetail) principal;
    }
    return null;
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
