/**
 * Synthetic PIX "copia e cola" payloads for tests, with a CRC computed
 * independently of the library.
 */

/** CRC-16/CCITT-FALSE, written independently of the library to build test payloads. */
export function crc16(text: string): string {
  let crc = 0xffff;
  for (const byte of new TextEncoder().encode(text)) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc & 0x8000) !== 0 ? (crc << 1) ^ 0x1021 : crc << 1;
      crc &= 0xffff;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}

/** A PIX "copia e cola" payload for a synthetic key, with a correct CRC. */
export function pixPayload(key = "fulano@example.com", gui = "br.gov.bcb.pix"): string {
  const field = (id: string, value: string): string =>
    `${id}${String(value.length).padStart(2, "0")}${value}`;
  const account = field("00", gui) + field("01", key);
  const body =
    field("00", "01") +
    field("26", account) +
    field("52", "0000") +
    field("53", "986") +
    field("58", "BR") +
    field("59", "FULANO DE TAL") +
    field("60", "SAO PAULO") +
    field("62", field("05", "***")) +
    "6304";
  return body + crc16(body);
}
