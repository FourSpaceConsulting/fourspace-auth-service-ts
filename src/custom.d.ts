declare module "d64" {
  export function encode(s: Buffer): string;
  export function decode(s: string): Buffer;
}
