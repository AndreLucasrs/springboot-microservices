package academy.devdojo.security.token.converter;

import academy.devdojo.core.property.JwtConfiguration;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @_(@Autowired))
public class TokenConverter {
    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public String descryptToken(String encryptedToken) {
        log.info("Decrypting token");

        JWEObject jweObject = JWEObject.parse(encryptedToken);

        DirectDecrypter directDecrypter = new DirectDecrypter(jwtConfiguration.getPrivateKey().getBytes());

        jweObject.decrypt(directDecrypter);

        log.info("Token decrypted, returning signed token ...");

        return jweObject.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public void validateTokenSignature(String signedToken) {
        log.info("Starting method to validate token signature ...");

        SignedJWT signedJWT = SignedJWT.parse(signedToken);

        log.info("Token parsed! Retrivieving public key from signred token");

        RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());

        log.info("Public key retrieved, validating signature...");

        if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
            throw new AccessDeniedException("Invalid token signature");
        }

        log.info("the token has a valid signature");

    }
}
