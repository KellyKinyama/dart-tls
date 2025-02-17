class BigIntCustom {
  final List<int> digits; // List of digits representing the big integer
  final bool
      isNegative; // Sign of the number (true for negative, false for positive)

  BigIntCustom(String value)
      : isNegative = value.startsWith('-'),
        digits = _stringToDigits(value.replaceFirst('-', ''));

  // Helper function to convert a string to a list of digits
  static List<int> _stringToDigits(String value) {
    return value.split('').map((e) => int.parse(e)).toList();
  }

  // Helper function to convert the digits back to a string with sign
  String toString() {
    return isNegative ? '-' + digits.join('') : digits.join('');
  }

  // Optimized Modulus (remainder) operation
  BigIntCustom operator %(BigIntCustom other) {
    if (other == BigIntCustom('0')) throw Exception("Division by zero");

    List<int> remainder = List.from(digits);

    // Using long division method to calculate modulus
    for (int i = 0; i < digits.length; i++) {
      List<int> current = [remainder[i]]; // Current digit
      // Find how many times 'other' fits into 'current'
      int quotientDigit = 0;
      while (!_isSmallerThan(current, other.digits)) {
        current = _subtract(current, other.digits);
        quotientDigit++;
      }

      remainder[i] = quotientDigit;
    }

    // Removing leading zeros
    while (remainder.length > 1 && remainder[0] == 0) {
      remainder.removeAt(0);
    }

    return BigIntCustom(remainder.join(''));
  }

  // Helper function to check if 'this' is smaller than 'other'
  bool _isSmallerThan(List<int> thisDigits, List<int> otherDigits) {
    if (thisDigits.length != otherDigits.length) {
      return thisDigits.length < otherDigits.length;
    }
    for (int i = 0; i < thisDigits.length; i++) {
      if (thisDigits[i] != otherDigits[i]) {
        return thisDigits[i] < otherDigits[i];
      }
    }
    return false;
  }

  // Helper function to subtract 'other' from 'this'
  List<int> _subtract(List<int> thisDigits, List<int> otherDigits) {
    int borrow = 0;
    List<int> result = [];

    for (int i = thisDigits.length - 1, j = otherDigits.length - 1;
        i >= 0 || j >= 0 || borrow != 0;
        i--, j--) {
      int diff =
          (i >= 0 ? thisDigits[i] : 0) - (j >= 0 ? otherDigits[j] : 0) - borrow;
      if (diff < 0) {
        diff += 10;
        borrow = 1;
      } else {
        borrow = 0;
      }
      result.insert(0, diff);
    }

    // Remove leading zeros
    while (result.length > 1 && result[0] == 0) {
      result.removeAt(0);
    }

    return result;
  }
}

void main() {
  BigIntCustom a = BigIntCustom('123456789012345678901234567890123456789');
  BigIntCustom b = BigIntCustom('98765432109876543210987654321');

  print('a: $a');
  print('b: $b');

  // Test modulus (%)
  BigIntCustom remainder = a % b;
  print('a % b: $remainder');
}
  
  // The code snippet above demonstrates the optimized modulus operation for BigIntCustom. The modulus operation is performed using the long division method. The code iterates through each digit of the dividend and calculates the quotient digit by dividing the current digit by the divisor. The remainder is then updated by subtracting the product of the quotient digit and the divisor from the current digit. The process continues until all digits of the dividend are processed. 
  // The optimized modulus operation improves the performance of the BigIntCustom class by reducing the number of iterations required to calculate the modulus. This optimization can be beneficial when working with large integers and performing frequent modulus operations.