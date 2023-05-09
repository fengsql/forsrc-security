package com.forsrc.security.filter;

import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.tool.ToolSecurity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class FilterAuthentication extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    setAuthentication(request);
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    if (ConfigSecurity.security.permit.size() == 0) {
      return false;
    }
    AntPathMatcher antPathMatcher = new AntPathMatcher();
    String url = request.getServletPath();
    for (String path : ConfigSecurity.security.permit) {
      if (antPathMatcher.match(path, url)) {
        log.debug("permit true.");
        setAuthentication(request);  //如果通过将不经过过滤器，需要设置身份信息
        return true;
      }
    }
    return false;
  }

  private void setAuthentication(HttpServletRequest request) {
    ToolSecurity.setAuthentication(request);
  }
}