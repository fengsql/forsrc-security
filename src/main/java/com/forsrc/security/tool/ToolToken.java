package com.forsrc.security.tool;

import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.model.AuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.*;

public class ToolToken implements Serializable {

  private static final long serialVersionUID = 1L;

  /**
   * 用户名称
   */
  private static final String USERNAME = Claims.SUBJECT;
  /**
   * 创建时间
   */
  private static final String CREATED = "created";
  /**
   * 权限列表
   */
  private static final String AUTHORITIES = "authorities";

  /**
   * 生成令牌
   * @return 令牌
   */
  public static String generateToken(Authentication authentication) {
    Map<String, Object> claims = new HashMap<>(3);
    claims.put(USERNAME, ToolSecurity.getUsername(authentication));
    claims.put(CREATED, new Date());
    claims.put(AUTHORITIES, authentication.getAuthorities());
    return generateToken(claims);
  }

  /**
   * 从数据声明生成令牌
   * @param claims 数据声明
   * @return 令牌
   */
  private static String generateToken(Map<String, Object> claims) {
    int expire = ConfigSecurity.security.token.expire;
    Date expirationDate = new Date(System.currentTimeMillis() + expire);
    String secret = ConfigSecurity.security.token.secret;
    return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, secret).compact();
  }

  /**
   * 从令牌中获取用户名
   * @param token 令牌
   * @return 用户名
   */
  public static String getUsernameFromToken(String token) {
    String username;
    try {
      Claims claims = getClaimsFromToken(token);
      username = claims.getSubject();
    } catch (Exception e) {
      username = null;
    }
    return username;
  }

  /**
   * 根据请求令牌获取登录认证信息
   * @return 用户名
   */
  public static Authentication getAuthenticationeFromToken(HttpServletRequest request) {
    Authentication authentication = null;
    // 获取请求携带的令牌
    String token = ToolToken.getToken(request);
    if (token != null) {
      // 请求令牌不能为空
      if (ToolSecurity.getAuthentication() == null) {
        // 上下文中Authentication为空
        Claims claims = getClaimsFromToken(token);
        if (claims == null) {
          return null;
        }
        String username = claims.getSubject();
        if (username == null) {
          return null;
        }
        if (isTokenExpired(token)) {
          return null;
        }
        Object authors = claims.get(AUTHORITIES);
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (authors instanceof List) {
          for (Object object : (List) authors) {
            authorities.add(new SimpleGrantedAuthority((String) ((Map) object).get("authority")));
          }
        }
        authentication = new AuthenticationToken(username, null, authorities, token);
      } else {
        if (validateToken(token, ToolSecurity.getUsername())) {
          // 如果上下文中Authentication非空，且请求令牌合法，直接返回当前登录认证信息
          authentication = ToolSecurity.getAuthentication();
        }
      }
    }
    return authentication;
  }

  /**
   * 从令牌中获取数据声明
   * @param token 令牌
   * @return 数据声明
   */
  private static Claims getClaimsFromToken(String token) {
    Claims claims;
    try {
      String secret = ConfigSecurity.security.token.secret;
      claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    } catch (Exception e) {
      claims = null;
    }
    return claims;
  }

  /**
   * 验证令牌
   */
  public static Boolean validateToken(String token, String username) {
    String userName = getUsernameFromToken(token);
    return (userName.equals(username) && !isTokenExpired(token));
  }

  /**
   * 刷新令牌
   */
  public static String refreshToken(String token) {
    String refreshedToken;
    try {
      Claims claims = getClaimsFromToken(token);
      claims.put(CREATED, new Date());
      refreshedToken = generateToken(claims);
    } catch (Exception e) {
      refreshedToken = null;
    }
    return refreshedToken;
  }

  /**
   * 判断令牌是否过期
   * @param token 令牌
   * @return 是否过期
   */
  public static Boolean isTokenExpired(String token) {
    try {
      Claims claims = getClaimsFromToken(token);
      Date expiration = claims.getExpiration();
      return expiration.before(new Date());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * 获取请求token
   */
  public static String getToken(HttpServletRequest request) {
    String token = request.getHeader("Authorization");
    String tokenHead = "Bearer ";
    if (token == null) {
      token = request.getHeader("token");
    } else if (token.contains(tokenHead)) {
      token = token.substring(tokenHead.length());
    }
    if ("".equals(token)) {
      token = null;
    }
    return token;
  }

}