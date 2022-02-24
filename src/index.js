import forge from "node-forge";
import crypto from "crypto";
import fs from "fs";

export class VerifyPdf {
  getSignature(pdf) {
    let byteRangePos = pdf.lastIndexOf("/ByteRange[");
    if (byteRangePos === -1) byteRangePos = pdf.lastIndexOf("/ByteRange [");

    const byteRangeEnd = pdf.indexOf("]", byteRangePos);
    const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();
    const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRange);
    const byteRangeArr = byteRangeNumbers[0].split(" ");

    const signedData = Buffer.concat([
      pdf.slice(parseInt(byteRangeArr[0]), parseInt(byteRangeArr[1])),
      pdf.slice(
        parseInt(byteRangeArr[2]),
        parseInt(byteRangeArr[2]) + parseInt(byteRangeArr[3])
      ),
    ]);
    let signatureHex = pdf
      .slice(
        parseInt(byteRangeArr[0]) + (parseInt(byteRangeArr[1]) + 1),
        parseInt(byteRangeArr[2]) - 1
      )
      .toString("binary");
    signatureHex = signatureHex.replace(/(?:00)*$/, "");
    const signature = Buffer.from(signatureHex, "hex").toString("binary");
    return { signature, signedData };
  }

  verify(pdf) {
    // Extracting the message from the signature
    const extractedData = this.getSignature(pdf);
    const p7Asn1 = forge.asn1.fromDer(extractedData.signature);
    const message = forge.pkcs7.messageFromAsn1(p7Asn1);
    const {
      signature: sig,
      digestAlgorithm,
      authenticatedAttributes: attrs, // get list of list of auth attrs
    } = message.rawCapture;
    const set = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      attrs
    );

    // Find hash algo
    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toUpperCase();

    // Create verifier
    const buf = Buffer.from(forge.asn1.toDer(set).data, "binary");
    const verifier = crypto.createVerify(`RSA-${hashAlgorithm}`);
    verifier.update(buf);

    // Verify stuff
    const cert = forge.pki.certificateToPem(message.certificates[0]);

    const validAuthenticatedAttributes = verifier.verify(cert, sig, "binary");
    if (!validAuthenticatedAttributes)
      throw new Error("Wrong authenticated attributes");

    // Hash of non signature part of PDF
    const pdfHash = crypto.createHash(hashAlgorithm);
    const data = extractedData.signedData;
    pdfHash.update(data);

    // Extracting the message digest
    const oids = forge.pki.oids;
    const fullAttrDigest = attrs.find(
      (attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest
    );
    const attrDigest = fullAttrDigest.value[1].value[0].value;

    // Compare to message digest to our PDF pdfHash
    const dataDigest = pdfHash.digest();
    const validContentDigest = dataDigest.toString("binary") === attrDigest;
    if (validContentDigest) {
      const greenText = "\x1b[32m%s\x1b[0m";
      console.log(greenText, "Signature is valid!!!");
    } else {
      throw new Error("Wrong content digest");
    }
  }
}

function main() {
  const sign = new VerifyPdf();
  sign.verify(fs.readFileSync("/Users/richardoliverbray/pdf_verify/test3.pdf"));
}
main();
