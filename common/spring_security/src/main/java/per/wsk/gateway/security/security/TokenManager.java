package per.wsk.gateway.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class TokenManager {


    //token有效时长
    private long tokenEcpiration = 24 * 60 * 60 * 1000;//一天毫秒数


    //编码秘钥
    private String tokenSignKey = "123456";
    //1. 使用JWT根据用户名生成token
    public String createToekn(String username){
        //setSubject方法里面传的是字符串，这里面是只将用户名放到了token中，也可以将对象放到token中，先将对象变成字符串，再传到setSubject方法里面
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis()+tokenEcpiration))
                .signWith(SignatureAlgorithm.HS512,tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
        return token;
    }

    //2. 根据token字符串得到用户信息
    public String getUserInfoFromToken(String token){
        String userInfo = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        return userInfo;
    }

    //3 删除token  其实删除token方法可以不写，客户端直接不携带token即可
    public void removeToken(String token) { }
}
