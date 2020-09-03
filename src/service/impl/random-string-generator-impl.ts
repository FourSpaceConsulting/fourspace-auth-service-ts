import { RandomStringGenerator } from "../random-string-generator";
import SecureRandomString from "secure-random-string";

export class RandomStringGeneratorImpl implements RandomStringGenerator {
  public generateRandom(length: number): Promise<string> {
    return new Promise(resolve => {
      SecureRandomString({ length }, (err, result) => {
        resolve(result);
      });
    });
  }
}
