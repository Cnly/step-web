import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

const encoder = new TextEncoder();
const OID = {
  commonName: '2.5.4.3',
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId: '1.2.840.113549.1.9.21',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
};
const iterations = 100_000;

function pem(label, der) {
  const bytes = new Uint8Array(der);
  let binary = '';

  for (const byte of bytes) binary += String.fromCharCode(byte);
  const lines = btoa(binary).match(/.{1,64}/g).join('\n');

  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function certificateFromPem(value) {
  const match = /^-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*$/.exec(value);
  if (!match) throw new Error('invalid PEM certificate');

  const der = Uint8Array.from(atob(match[1].replace(/\s/g, '')), c => c.charCodeAt(0));

  return pkijs.Certificate.fromBER(der);
}

function bagAttributes(friendlyName, localKeyId) {
  return [
    new pkijs.Attribute({
      type: OID.friendlyName,
      values: [new asn1js.BmpString({ value: friendlyName })],
    }),
    new pkijs.Attribute({
      type: OID.localKeyId,
      values: [new asn1js.OctetString({ valueHex: localKeyId })],
    }),
  ];
}

const encryption = password => ({
  password,
  contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256 },
  hmacHashAlgorithm: 'SHA-256',
  iterationCount: iterations,
});

export async function createIdentity(commonName) {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );

  const request = new pkijs.CertificationRequest({ attributes: [] });
  request.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: OID.commonName,
    value: new asn1js.Utf8String({ value: commonName }),
  }));

  await request.subjectPublicKeyInfo.importKey(pair.publicKey);
  await request.sign(pair.privateKey, 'SHA-256');

  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    csrPem: pem('CERTIFICATE REQUEST', request.toSchema().toBER(false)),
  };
}

export async function createPkcs12({ privateKey, publicKey, certificateChainPem, password, friendlyName }) {
  const chain = certificateChainPem.map(certificateFromPem);
  const leaf = chain[0];
  const expected = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  const actual = new Uint8Array(leaf.subjectPublicKeyInfo.toSchema().toBER(false));

  if (expected.length !== actual.length || expected.some((byte, i) => byte !== actual[i])) {
    throw new Error('leaf certificate public key does not match generated public key');
  }

  const passwordBytes = encoder.encode(password).buffer;
  const leafDer = leaf.toSchema().toBER(false);
  const localKeyId = await crypto.subtle.digest('SHA-1', leafDer);

  const certBags = chain.map((certificate, index) => new pkijs.SafeBag({
    bagId: OID.certBag,
    bagValue: new pkijs.CertBag({ parsedValue: certificate }),
    ...(index === 0 ? { bagAttributes: bagAttributes(friendlyName, localKeyId) } : {}),
  }));

  const privateKeyDer = await crypto.subtle.exportKey('pkcs8', privateKey);
  const shrouded = new pkijs.PKCS8ShroudedKeyBag({
    parsedValue: pkijs.PrivateKeyInfo.fromBER(privateKeyDer),
  });
  await shrouded.makeInternalValues(encryption(passwordBytes));

  const keyBag = new pkijs.SafeBag({
    bagId: OID.pkcs8ShroudedKeyBag,
    bagValue: shrouded,
    bagAttributes: bagAttributes(friendlyName, localKeyId),
  });

  const safe = new pkijs.AuthenticatedSafe({
    parsedValue: {
      safeContents: [
        { privacyMode: 1, value: new pkijs.SafeContents({ safeBags: certBags }) },
        { privacyMode: 0, value: new pkijs.SafeContents({ safeBags: [keyBag] }) },
      ],
    },
  });
  await safe.makeInternalValues({ safeContents: [encryption(passwordBytes), {}] });

  const pfx = new pkijs.PFX({ parsedValue: { integrityMode: 0, authenticatedSafe: safe } });
  await pfx.makeInternalValues({
    password: passwordBytes,
    iterations,
    pbkdf2HashAlgorithm: 'SHA-256',
    hmacHashAlgorithm: 'SHA-256',
  });

  return new Uint8Array(pfx.toSchema().toBER(false));
}
