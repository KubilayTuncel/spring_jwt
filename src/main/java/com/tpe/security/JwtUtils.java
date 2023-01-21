package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    //1: JWT generate
    //2: JWT valide ediecek
    //3: JWT --> icerisinden username i cekecegiz.

    private String jwtSecret = "sboot"; //secret key jwt token bizden bu degeri istiyor ve sistemi daha karmasik hala getirmemizi sagliyor.
    private long jwtExpritaonMs =  86400000; //24*60*60*1000 milisaniye cinsinden.

    //**********GENERATE TOKEN*******

    public String generateToken(Authentication authentication) {
        UserDetailsImpl userDetails =
                (UserDetailsImpl) authentication.getPrincipal(); //getPrincipal() methodu anlik olarak giris yapan
                                                                // kullaniciyi getiriyor. (ama userDetails türünde)
        return Jwts.builder().
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date()).
                setExpiration(new Date(new Date().getTime()+jwtExpritaonMs)).
                //ilk new Date() bizim buraya bir tarih giricegimizi belirtiyoruz. ikinci new Date olusturulma tarihini aliyoruz.
                        //sonra da üyerine expiration date i ekledik.
                signWith(SignatureAlgorithm.HS512,jwtSecret).compact();//en iyi token üretim algoritmasi ise HS512

    }


    //*************Validate Token
    public boolean valideToken(String token){
        //ilk olarak tüm code'u sectik. sonra asagidaki isleme devam ettik.
        //bu try catch i yukarida code tikladik sonra surrond with sectik orada da try catch i secerek yaptik
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token); //bu secret key ile token i bu isleme tabi tutup
            //bu token in bizim tarafimizdan olusturdugumuz token olup olmadigina bakiyoruz.
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }

    //!!!***********JWT tokenden userName'i alaim *********
    public String getUserNameFromJwtToken(String token){

        return Jwts.parser().setSigningKey(jwtSecret).
                    parseClaimsJws(token).getBody().
                    getSubject(); //yukarida builder methodunda setSubject icerisinde userName'i
                                  //ekledigimiz icin ayni body icerisinden userName ini alabiliriz.
                                  //getBody() methodu bu builder methodunun icerisine girdi.
                                 // getSubject'te userName e ulasmamizi sagladi.
    }

}
