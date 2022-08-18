package per.wsk.gateway.security.filter;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import per.wsk.gateway.security.security.TokenManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class TokenAuthFilter extends BasicAuthenticationFilter {

    //token工具类
    private TokenManager tokenManager;
    //redis工具类
    private RedisTemplate redisTemplate;


    public TokenAuthFilter(AuthenticationManager authenticationManager, TokenManager tokenManager,
                           RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //获取当前认证成功的用户的权限信息
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        //判断如果有权限信息，就放到权限的上下文中
        if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        //过滤器放行
        chain.doFilter(request,response);
    }


    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request){
        //从header中获取token
        String token = request.getHeader("token");

        if (token != null) {
            //从token获取用户名
            String username = tokenManager.getUserInfoFromToken(token);
            //从redis中获取对应的权限列表
            List<String> permissionValueList = (List<String>) redisTemplate.opsForValue().get(username);

            Collection<GrantedAuthority> authority = new ArrayList<>();

            permissionValueList.forEach(permissionValue->{
                SimpleGrantedAuthority auth = new SimpleGrantedAuthority(permissionValue);
                authority.add(auth);
            });
            //参数1：主体，具体指jwt中存放的内容   参数2：令牌，这里具体指token   参数3：权限列表
            return new UsernamePasswordAuthenticationToken(username,token,authority);
        }
        return null;
    }

}
