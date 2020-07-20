package com.forsrc.security.filter;

import com.forsrc.security.tool.ToolToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationFilter extends BasicAuthenticationFilter {

  public AuthenticationFilter(AuthenticationManager authenticationManager) {
    super(authenticationManager);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    // 获取token, 并检查登录状态
    Authentication authentication = getAuthentication(request);

    SecurityContextHolder.getContext().setAuthentication(authentication);

    chain.doFilter(request, response);
  }

  private Authentication getAuthentication(HttpServletRequest request) throws IOException {
    Authentication authentication = ToolToken.getAuthenticationeFromToken(request);
    if (authentication != null) {
      return authentication;
    }
    return null;
  }

}
