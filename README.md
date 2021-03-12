#   spring-security-jwt-auth-teach

##  簡述

用 `spring boot + spring security + jwt(json web token)` 實作登入認証(authentication)與授權(authorization) 功能

##  有哪些 restful api ?

`cloudtu.controller` package 有全部的 restful api

api 列表如下

| 路徑                      | 功能                                     | 用戶要是什麼角色才能存取 | 
| ------------------------- |-----------------------------------------|-----------------------|
| /auth/register            | 用戶註冊                                 | 沒限制，所有人都可存取   |
| /auth/login               | 用戶登入，登入後可取得 jwt(json web token) | 沒限制，所有人都可存取   |
| /auth/logout              | 用戶登出                                 | 沒限制，所有人都可存取   |
| /user/myInfo              | 用戶個人資料                              | USER 跟 ADMIN 角色     |
| /user/findUser/{userName} | 查詢特定用戶資料                          | ADMIN 角色             |
| /user//findAllUsers       | 查詢所有用戶資料                          | ADMIN 角色             |

##  關鍵程式碼

程式關鍵處都有加上註解說明，有興趣的人可以看 code 研究細節。其中最關鍵的部份在下列儿個 class，看懂後就有能力自己實作 jwt(json web token) base auth

### WebSecurityConfig class

關鍵處如下

```java
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    // 這個 filter 利用 http request header 帶的 JWT(Json Web Token) 進行用戶認証與授權
    @Autowired private JwtAuthFilter jwtAuthFilter;
    
    ...etc
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
            .csrf().disable()
            
            // 存取到未授權的 restful api 時，會導到 UnauthEntryPoint class 進行後續處理
            .exceptionHandling().authenticationEntryPoint(new UnauthEntryPoint()).and()
            
            // 因為走 jwt(json web token) auth，所以不用 http session，要設成 SessionCreationPolicy.STATELESS
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            
            .authorizeRequests().antMatchers("/auth/**").permitAll()
            .anyRequest().authenticated();

        // jwtAuthFilter 放在 UsernamePasswordAuthenticationFilter 之前，代表先用 JWT(Json Web Token)對用戶進行認証與授權
        // 如果失敗的話會經由 UsernamePasswordAuthenticationFilter 使用用戶帳號密碼再次進行認証與授權
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```


### JwtAuthFilter class

關鍵處如下

```java
public class JwtAuthFilter extends OncePerRequestFilter {
    // JwtUtil 用來產生或是解析 JWT(Json Web Token)
    @Autowired private JwtUtil jwtUtil;

    ...etc
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = retriveJwt(request); // 從 http header 取出 JWT(Json Web Token)
            if (token != null){
                // 因為 WebSecurityConfig 設定 sessionCreationPolicy(SessionCreationPolicy.STATELESS)，所以
                // 不用 http session 記錄資料，因此 SecurityContextHolder 不會將登入認証成功後的 Authentication 記到
                // http session。也就是說登入認証成功後的 Authentication 不會被記錄到系統，每次的 http request 都必需重新
                // 進行一次登入認証，不然從 SecurityContextHolder.getContext().getAuthentication() 取回登入認証成功後
                // 的 Authentication instance 一定是 null。

                //region 當 token 變數可以成功解析出 userName 與 userRoles 時，代表是合法 token，這時可以用 token 裡的資料產生
                //       登入認証成功後的 Authentication，並將它存放到 SecurityContextHolder.getContext().setAuthentication(...) method
                //       讓系統知道用戶已登入認証成功
                String userName = jwtUtil.parseUserNameFromToken(token); // 解析失敗時會丟出 exception
                List<SimpleGrantedAuthority> userAuthorities = jwtUtil.parseUserAuthoritiesFromToken(token); // 解析失敗時會丟出 exception
                UserDetails userDetails = new UserDetailsImpl(userName, null, userAuthorities);

                UsernamePasswordAuthenticationToken authAfterSuccessLogin = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authAfterSuccessLogin.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authAfterSuccessLogin);
                //endregion
            }
        }
        catch (Exception e) {
            ...etc
            
            return;
        }

        filterChain.doFilter(request, response);
    }
}
```

##  reference doc

*   重拾後端之Spring Boot（四）：使用JWT和Spring Security保護REST API

    *   文章在[這裡](https://www.jianshu.com/p/6307c89fe3fa)
    *   sample code 在 [git project](https://github.com/wpcfan/spring-boot-tut/tree/chap04) 裡的 `chap04` branch

*   Spring Boot Token based Authentication with Spring Security & JWT

    *   文章在[這裡](https://bezkoder.com/spring-boot-jwt-authentication/)
    *   sample code 在[這裡](https://github.com/bezkoder/spring-boot-spring-security-jwt-authentication)

*   [Spring Boot 2 JWT Authentication with Spring Security](https://bezkoder.com/spring-boot-jwt-mysql-spring-security-architecture/)

*   Vincent Zheng blog 裡跟 Spring Security 相關系列文章

    *   [Spring Boot-第17課-Spring Security的驗證與授權](https://medium.com/chikuwa-tech-study/spring-boot-%E7%AC%AC17%E8%AA%B2-spring-security%E7%9A%84%E9%A9%97%E8%AD%89%E8%88%87%E6%8E%88%E6%AC%8A-263afe44ac20)
    *   [Spring Boot-第18課-帳密驗證與產生Token](https://medium.com/chikuwa-tech-study/spring-boot-%E7%AC%AC18%E8%AA%B2-%E5%B8%B3%E5%AF%86%E9%A9%97%E8%AD%89%E8%88%87%E7%94%A2%E7%94%9Ftoken-79d9ccc2b6fd)
    *   [Spring Boot-第19課-從Token驗證使用者身份](https://medium.com/chikuwa-tech-study/spring-boot-%E7%AC%AC19%E8%AA%B2-%E5%BE%9Etoken%E9%A9%97%E8%AD%89%E4%BD%BF%E7%94%A8%E8%80%85%E8%BA%AB%E4%BB%BD-8818cca1361d)