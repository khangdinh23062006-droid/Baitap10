package vn.iotstar.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service xử lý JSON Web Token sử dụng thư viện Nimbus JOSE + JWT
 * Thay thế cho thư viện JJWT (io.jsonwebtoken) trong bài giảng.
 */
@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    /**
     * Trích xuất username (subject) từ JWT token
     */
    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    /**
     * Trích xuất một claim cụ thể từ token thông qua claimsResolver
     */
    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Sinh token với userDetails và không có extra claims
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Sinh token với extra claims và userDetails
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Lấy thời gian hết hạn cấu hình (ms)
     */
    public long getExpirationTime() {
        return jwtExpiration;
    }

    /**
     * Xây dựng và ký JWT sử dụng Nimbus JOSE + JWT (HMAC-SHA256)
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        try {
            // 1. Tạo JWT Claims
            Date now = new Date(System.currentTimeMillis());
            Date validity = new Date(now.getTime() + expiration);

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(validity);

            if (extraClaims != null) {
                extraClaims.forEach(claimsBuilder::claim);
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // 2. Tạo JWS Header với thuật toán HS256
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            // 3. Tạo SignedJWT và ký với Secret Key (HMAC Signer)
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner signer = new MACSigner(getSigningKey());
            signedJWT.sign(signer);

            // 4. Serialize ra chuỗi JWT dạng Bearer compact
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error signing JWT token with Nimbus", e);
        }
    }

    /**
     * Kiểm tra tính hợp lệ của token đối với UserDetails
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Kiểm tra token đã hết hạn chưa
     */
    public boolean isTokenExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Trích xuất thời gian hết hạn từ token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    /**
     * Phân tích và xác thực toàn bộ Claims từ token sử dụng Nimbus JWSVerifier
     */
    public JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(getSigningKey());

            if (!signedJWT.verify(verifier)) {
                throw new java.security.SignatureException("The JWT signature is invalid");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                throw new RuntimeException("The JWT token has expired");
            }

            return claimsSet;
        } catch (ParseException e) {
            throw new RuntimeException("Invalid JWT token format", e);
        } catch (JOSEException e) {
            throw new RuntimeException("Invalid JWT signature", e);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Lấy khóa bí mật dạng byte array cho HMAC-SHA256 (tối thiểu 256 bits)
     */
    private byte[] getSigningKey() {
        return secretKey.getBytes(StandardCharsets.UTF_8);
    }
}
