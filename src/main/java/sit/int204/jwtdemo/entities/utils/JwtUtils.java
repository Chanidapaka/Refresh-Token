package sit.int204.jwtdemo.entities.utils;



import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import sit.int204.jwtdemo.entities.Dto.AccessToken;
import sit.int204.jwtdemo.entities.entities.AuthUserDetail;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;


//ที่ใช้สำหรับการจัดการ JSON Web Token (JWT)
@Component
public class JwtUtils {

    @Value("#{${app.security.jwt.token-max-interval-in-minute}*1000*60}")//ใช้เพื่อดึงค่าจากไฟล์ application.properties
    private long MAX_TOKEN_INTERVAL; //แล้วเอามาเก็บไว้ในนี้ คำนวณให้เป็นเวลาสูงสุดที่อนุญาตให้ใช้ JWT (ในหน่วยมิลลิวินาที)

    @Value("${app.security.jwt.key-id}") //คำนวนแล้วเอามาเก็บไว้
    private String KEY_ID; //ใช้เป็นตัวระบุของ RSA Key ที่ใช้ในการเข้ารหัส JWT

    //เก็บ RSA Key Pair สำหรับการเซ็นต์และตรวจสอบ JWT โดย RSA Key ถูกสร้างด้วย
    private RSAKey rsaPrivateJWK; //ถูกใช้ในการเซ็นต์ JWT
    private RSAKey rsaPublicJWK; // ถูกใช้ในการตรวจสอบ JWT

    public RSAKey getRsaPublicJWK() {
        return this.rsaPublicJWK;
    }

    //ตอนสตักเตอร์
    public JwtUtils() {
        try {
            rsaPrivateJWK = new RSAKeyGenerator(2048) //ขนาด
                    .keyID(KEY_ID).generate();
            rsaPublicJWK = rsaPrivateJWK.toPublicJWK();
            System.out.println(rsaPublicJWK.toJSONString());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    //สร้าง JWT โดยเซ็นต์ JWT ด้วย RSA Private Key และเพิ่มข้อมูลลงใน Claims ของ JWT
    //generateToken
    public AccessToken generateToken(UserDetails user) {
        try {
            JWSSigner signer = new RSASSASigner(rsaPrivateJWK); //Private key มาสร้างลายเซนต์
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUsername()) //เอา username ใส่ใน subject
                    .issuer("https://int204.sit.kmutt.ac.th") //เราเป็นเว็บไซต์อันนี้
                    .expirationTime(new Date(new Date().getTime() + MAX_TOKEN_INTERVAL)) //token จะมีอายุเท่าไหร่ เอาเวลาปัจจุบัน + MAX_TOKEN_INTERVAL(30 นาที)
                    .issueTime(new Date(new Date().getTime())) //เวลาที่เราสร้าง
                    .claim("authorities", user.getAuthorities()) //จะใส่ไม่ใส่ก็ได้
                    .claim("uid", ((AuthUserDetail) user).getId())
                    .build(); //ได้ 1ชิ้น.header claim มาหนึ่งชุด

            //เริ่มสร้าง JWT
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256) //ใช้ อัลกอริทึม RS256 ที่ใช้สร้าง token
                    .keyID(rsaPrivateJWK.getKeyID()).build(), claimsSet); //2ชิ้น.แล้วเอามา + กับ claimsSet(play load)
            signedJWT.sign(signer); //3ชิ้น.เติมลายเซนต์เข้าไป
            return new AccessToken(signedJWT.serialize()); //token ส่งแบบ text ดังนั้นจึงเอา serialize() คือการเอา string มาต่อกัน แล้วเอาไปใส่ AccessToken ให้เป็น Json
        } catch (JOSEException e) {
            throw new RuntimeException(e); //ถ้า error ก็ส่ง run time ออกไป
        }
    }

    //ใช้ในการตรวจสอบความถูกต้องของ JWT โดยการใช้ RSA Public Key
    public void verifyToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK); // เพื่อตรวจสอบว่า JWT ถูกเซ็นต์ด้วย RSA Private Key หรือไม่
            System.out.println("verify method: " + signedJWT.verify(verifier));
        } catch (JOSEException | ParseException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified Error, Invalid JWT", ex);
        }
    }


    //ดึงข้อมูล Claims จาก JWT ที่ให้มา เช่น subject, issuer, exp (เวลาหมดอายุ), และ uid (ID ของผู้ใช้)
    public Map<String, Object> getJWTClaimsSet(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getClaims();
        } catch (ParseException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT (Can't parsed)", ex);
        }
    }

    //ตรวจสอบว่า JWT หมดอายุหรือไม่โดยการตรวจสอบว่า exp (เวลาหมดอายุ) นั้นก่อนวันที่ปัจจุบัน
    public boolean isExpired(Map<String, Object> jwtClaims) {
        Date expDate = (Date) jwtClaims.get("exp");
        return expDate.before(new Date());
    }

    //ตรวจสอบว่า Claims ที่ได้จาก JWT มีค่าครบถ้วนและถูกต้อง เช่น iat (เวลาที่สร้าง), iss (ผู้สร้าง), และ uid (ID ของผู้ใช้)
    public boolean isValidClaims(Map<String, Object> jwtClaims) {
        System.out.println(jwtClaims);
        return jwtClaims.containsKey("iat")
                && "https://int204.sit.kmutt.ac.th"
                .equals(jwtClaims.get("iss"))
                && jwtClaims.containsKey("uid")
                && (Long) jwtClaims.get("uid") > 0;
    }
}