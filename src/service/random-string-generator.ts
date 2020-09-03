/**
 * Creates random strings of given length
 */
export interface RandomStringGenerator {
  generateRandom(length: number): Promise<string>;
}
