import * as jose from 'jose';
import fs from 'fs';

const keysetRaw = fs.readFileSync('keyset.json', 'utf8'); 
const keyset = JSON.parse(keysetRaw);


const ecKey = keyset.keys.find(k => k.kty === 'EC');
const rsaKey = keyset.keys.find(k => k.kty === 'RSA');

if (!ecKey && !rsaKey) {
  throw new Error("EC and RSA keys were not found from keyset.json.");
}


async function testEncryption() {
  const ecPrivateKey = await jose.importJWK(ecKey, ecKey.alg);
  const { d, ...ecPublicKeyJWK } = ecKey; // Remove 'd' to make it public key
  const ecPublicKey = await jose.importJWK(ecPublicKeyJWK, ecKey.alg);

  const encoder = new TextEncoder();
  const message = encoder.encode("Lorem ipsum dolor sit amet");
  
  const encrypted = await new jose.CompactEncrypt(message)
    .setProtectedHeader({ alg: ecKey.alg, enc: 'A128GCM' })
    .encrypt(ecPublicKey);
  
  console.log("🔐 Encrypted message: ", encrypted);

  const { plaintext } = await jose.compactDecrypt(encrypted, ecPrivateKey);

  console.log("🔓 Decrypted message:", new TextDecoder().decode(plaintext));
}


async function testSigning() {
  const rsaPrivateKey = await jose.importJWK(rsaKey, rsaKey.alg);
  const { d, p, q, dp, dq, qi, ...rsaPublicKeyJWK } = rsaKey; 
  const rsaPublicKey = await jose.importJWK(rsaPublicKeyJWK, rsaKey.alg);

  const encoder = new TextEncoder();
  const message = encoder.encode("Consectetur adipiscing elit");

  const jwt = await new jose.SignJWT({ msg: "Consectetur adipiscing elit" })
    .setProtectedHeader({ alg: rsaKey.alg })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(rsaPrivateKey);
  
  console.log("✍️ Signed JWT:", jwt);

  const { payload } = await jose.jwtVerify(jwt, rsaPublicKey);

  console.log("✅ Signature verified");
  console.log(payload.msg);
}


(async () => {
  await testEncryption();
  await testSigning();
})();

