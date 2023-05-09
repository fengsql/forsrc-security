package com.forsrc.security.tool;

import com.forsrc.common.constant.Code;
import com.forsrc.common.exception.CommonException;
import com.forsrc.common.tool.Tool;
import com.forsrc.security.base.IUserDetails;
import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.model.AuthenticationToken;
import com.forsrc.security.model.UserDetail;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.*;

@Slf4j
public class ToolToken implements Serializable {
  private static final long serialVersionUID = 1L;
  //
  private static final long expire_default = 3600L; //缺省过期时间，3600秒
  /**
   * 用户名称
   */
  private static final String SUBJECT = Claims.SUBJECT;
  private static final String USERID = "userId";
  private static final String ROLE = "role";
  /**
   * 创建时间
   */
  private static final String CREATED = "created";
  /**
   * 权限列表
   */
  private static final String AUTHORITIES = "authorities";
  private static final String AUTHORITY = "authority";
  private static final String AUTHORIZATION = "Authorization";
  private static final String TOKEN = "token";
  private static final String BEARER = "Bearer ";
  // websocket
  private static final String NAME_CONNECTION = "connection";
  private static final String CONNECTION_UPGRADE = "upgrade";
  private static final String NAME_UPGRADE = "upgrade";
  private static final String UPGRADE_WEBSOCKET = "websocket";
  private static final String SEC_WEBSOCKET_PROTOCOL = "sec-websocket-protocol";

  /**
   * 生成令牌。
   * @param authentication 认证信息。
   * @return 令牌。
   */
  public static String generateToken(Authentication authentication) {
    UserDetail userDetail = ToolSecurity.getUserDetail(authentication);
    return generateToken(userDetail);
  }

  /**
   * 生成令牌。
   * @param userDetails 认证信息。
   * @return 令牌。
   */
  public static String generateToken(IUserDetails userDetails) {
    UserDetail userDetail = (UserDetail) userDetails;
    Map<String, Object> claims = new HashMap<>(5);
    claims.put(USERID, userDetail.getUserId());
    claims.put(SUBJECT, userDetail.getUsername());
    claims.put(ROLE, userDetail.getRoleType());
    claims.put(CREATED, new Date());
    claims.put(AUTHORITIES, userDetail.getAuthorities());
    return generateToken(claims);
  }

  /**
   * 解析 token 获取 subject，即用户名。
   * @param token 令牌。
   * @return subject。
   */
  public static String getUsername(String token) {
    return getSubjectFromToken(token);
  }

  /**
   * 解析 token 获取 userId，即用户编号。
   * @param token 令牌。
   * @return userId。
   */
  public static Object getUserId(String token) {
    return getUserIdFromToken(token);
  }

  /**
   * 根据请求令牌获取授权信息。
   * @param request 请求。
   * @return 授权信息。
   */
  public static Authentication getAuthenticationFromToken(HttpServletRequest request) {
    String token = getToken(request);
    if (token == null) {
      //      throw new ErrorException(Code.AUTHENTICATION_EXCEPTION);
      return null;
    }
    return newAuthentication(token);
  }

  /**
   * 验证令牌。
   * @param token    令牌。
   * @param username 用户名。
   * @return true 有效，false 无效。
   */
  public static Boolean validateToken(String token, String username) {
    String userName = getSubjectFromToken(token);
    return userName != null && userName.equals(username);
  }

  /**
   * 刷新令牌。
   * @param token 令牌。
   * @return 新的令牌。
   */
  public static String refreshToken(String token) {
    String refreshedToken;
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return null;
      }
      claims.put(CREATED, new Date());
      refreshedToken = generateToken(claims);
    } catch (Exception e) {
      refreshedToken = null;
    }
    return refreshedToken;
  }

  /**
   * 判断令牌是否过期。
   * @param token 令牌
   * @return true 过期，false 未过期。
   */
  public static Boolean isTokenExpired(String token) {
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return true;
      }
      Date expiration = claims.getExpiration();
      return expiration.before(new Date());
    } catch (Exception e) {
      return true;
    }
  }

  private static String getToken(HttpServletRequest request) {
    String token = getTokenByHttp(request);
    if (Tool.isNull(token)) {
      token = getTokenByWebsocket(request);
    }
    return token;
  }

  private static String getTokenByWebsocket(HttpServletRequest request) {
    String token = request.getHeader(SEC_WEBSOCKET_PROTOCOL);
    if (token == null) {
      return null;
    }
    String connection = request.getHeader(NAME_CONNECTION);
    String upgrade = request.getHeader(NAME_UPGRADE);
    if (Tool.equalIgnore(connection, CONNECTION_UPGRADE) && Tool.equalIgnore(upgrade, UPGRADE_WEBSOCKET)) {
      return token;
    }
    return null;
  }

  private static String getTokenByHttp(HttpServletRequest request) {
    String token = request.getHeader(AUTHORIZATION);
    if (token == null) {
      token = request.getHeader(TOKEN);
    } else if (token.startsWith(BEARER)) {
      token = token.substring(BEARER.length());
    }
    if ("".equals(token)) {
      token = null;
    }
    return token;
  }

  private static Authentication newAuthentication(String token) {
    UserDetail userDetails = getUserDetailsFromToken(token);
    if (userDetails == null) {
      return null;
    }
    return new AuthenticationToken(userDetails, null, userDetails.getAuthorities(), token);
  }

  private static UserDetail getUserDetailsFromToken(String token) {
    Claims claims = getClaimsFromToken(token);
    if (claims == null) {
      return null;
    }
    String username = claims.getSubject();
    if (username == null) {
      return null;
    }
    Object userId = claims.get(USERID);
    int roleType = Tool.toInt(claims.get(ROLE));
    Object authors = claims.get(AUTHORITIES);
    List<GrantedAuthority> authorities = new ArrayList<>();
    if (authors instanceof List) {
      for (Object object : (List) authors) {
        authorities.add(new SimpleGrantedAuthority((String) ((Map) object).get(AUTHORITY)));
      }
    }
    UserDetail userDetails = new UserDetail();
    userDetails.setUserId(userId);
    userDetails.setRoleType(roleType);
    userDetails.setUsername(username);
    //    userDetails.setPassword(passwordEncoder.encode(user.getPassword()));
    userDetails.setAuthorities(authorities);
    return userDetails;
  }

  /**
   * 从令牌中获取数据声明
   * @param token 令牌
   * @return 数据声明
   */
  private static Claims getClaimsFromToken(String token) {
    try {
      String secret = ConfigSecurity.security.token.secret;
      return Jwts.parser(). //
        setSigningKey(secret). //
        parseClaimsJws(token). //
        getBody();
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * 从数据声明生成令牌
   * @param claims 数据声明
   * @return 令牌
   */
  private static String generateToken(Map<String, Object> claims) {
    long expire = getExpire();
    Date expirationDate = new Date(System.currentTimeMillis() + expire);
    String secret = ConfigSecurity.security.token.secret;
    return Jwts.builder(). //
      setClaims(claims).   //
      setExpiration(expirationDate). //
      signWith(SignatureAlgorithm.HS512, secret). //
      compact();
  }

  private static long getExpire() {
    String expire = ConfigSecurity.security.token.expire;
    Long value = Tool.getConfigTime(expire);
    if (Tool.isNull(value)) {
      value = expire_default;
    }
    if (value < 0) {
      throw new CommonException(Code.SETTING_ERROR, "时间配置无效! expire: " + expire);
    }
    return value * 1000L;
  }

  /**
   * 从令牌中获取用户名
   * @param token 令牌
   * @return 用户名
   */
  private static String getSubjectFromToken(String token) {
    if (token == null) {
      return null;
    }
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return null;
      }
      return claims.getSubject();
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * 从令牌中获取用户编号
   * @param token 令牌
   * @return 用户编号
   */
  private static Object getUserIdFromToken(String token) {
    if (token == null) {
      return null;
    }
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return null;
      }
      return claims.get(USERID);
    } catch (Exception e) {
      return null;
    }
  }

}