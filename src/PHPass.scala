/**
 * Scala implementation of Portable PHP password hashing. (crypt_private password check only!)
 * Written by Anton Fagerberg <anton at antonfagerberg dot com>, 2012.
 *
 * Based on the original code from Portable PHP password hashing framework
 * written by Solar Designer <solar at openwall.com>.
 * Original PHP implementation: http://www.openwall.com/phpass/
 *
 * Note that this code has not been peer-reviewed and any potential user should proceed with
 * caution before implementing this in a production system. With that said, I have tested the code myself
 * and used it in production.
 *
 * The cryptPrivate method is used in phpass when CRYPT_BLOWFISH and CRYPT_EXT_DES
 * is not available in PHP. This piece of Scala code can verify those passwords.
 *
 * No license, do what you want.
 */
import java.security.MessageDigest

class PHPass(var icl2: Int) {
  val itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  val iterationCountLog2 =
    if (icl2 < 4 || icl2 > 31) 8
    else icl2

  def cryptPrivate(password: String, hashMatch: String): String = {
    val countLog2 = try {
      itoa64.indexOf(hashMatch(3))
    } catch {
      case e: IndexOutOfBoundsException => -1
    }

    val salt = hashMatch.slice(4, 12)

    if ((hashMatch.slice(0, 3) != "$P$" && hashMatch.slice(0, 3) != "$H$") || countLog2 < 7 || countLog2 > 30 || salt.length != 8) {
      if (hashMatch.slice(0, 2) == "*0") "*1" else "*0"
    } else {
      val md5 = MessageDigest.getInstance("MD5")

      def md5Recursion(md5hash: Array[Byte], count: Int): Array[Int] = {
        if (count == 0) md5hash.map((signed: Byte) => (signed & 0xFF))
        else md5Recursion(md5.digest(md5hash ++ password.getBytes), count - 1)
      }

      hashMatch.slice(0, 12) + encode64(md5Recursion(md5.digest((salt + password).getBytes), 1 << countLog2), 16)
    }
  }

  private def encode64(input: Array[Int], count: Int): String = {
    def encode(i: Int = 0, output: StringBuilder = new StringBuilder): String = {
      val firstValue =
        if (i + 1 < count) input(i) | (input(i + 1) << 8)
        else input(i)

      output += itoa64(input(i) & 0x3f)
      output += itoa64((firstValue >> 6) & 0x3f)

      if (i + 1 >= count)
        return output.toString()

      val secondValue =
        if (i + 2 < count) firstValue | (input(i + 2) << 16)
        else firstValue

      output += itoa64((secondValue >> 12) & 0x3f)

      if (i + 2 >= count)
        return output.toString()

      output += itoa64((secondValue >> 18) & 0x3f)

      if (i + 3 >= count)
        return output.toString()

      encode(i + 3, output)
    }

    encode()
  }
}

object PHPass {
  def main(args: Array[String]) {
    val hasher = new PHPass(8)

    val correctPassword = "test1"
    val correctHash = "$P$B1a/OYrhRoAOrq.4b8460yt976nD/y0"

    val wrongPassword = "test2"
    val wrongSaltHash = "$P$B1a/OY2hR0AOrq.4b8460yt976nD/y0"

    println("Should be true: " + (hasher.cryptPrivate(correctPassword, correctHash) == correctHash))
    println("Should be false: " + (hasher.cryptPrivate(correctPassword, wrongSaltHash) == correctHash))
    println("Should be false: " + (hasher.cryptPrivate(correctPassword, wrongSaltHash) == wrongSaltHash))
    println("Should be false: " + (hasher.cryptPrivate(wrongPassword, correctHash) == correctHash))
  }
}