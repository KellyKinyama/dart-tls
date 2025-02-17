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

  // Integer Division (using the ~/)
  BigIntCustom operator ~/(BigIntCustom other) {
    if (other == BigIntCustom('0')) throw Exception("Division by zero");

    bool resultNegative = isNegative != other.isNegative;

    List<int> quotient = [];
    List<int> remainder = [];

    for (int digit in digits) {
      remainder.add(digit);
      int quotientDigit = 0;

      while (!_isSmallerThan(remainder, other.digits)) {
        remainder = _subtract(remainder, other.digits);
        quotientDigit++;
      }

      quotient.add(quotientDigit);
    }

    return BigIntCustom((resultNegative ? '-' : '') + quotient.join(''));
  }

  // Modulus (remainder) operation
  BigIntCustom operator %(BigIntCustom other) {
    if (other == BigIntCustom('0')) throw Exception("Division by zero");

    List<int> remainder = List.from(digits);

    while (!_isSmallerThan(remainder, other.digits)) {
      remainder = _subtract(remainder, other.digits);
    }

    // Adjust remainder to have the same sign as the divisor
    if (isNegative) {
      remainder = _subtract(other.digits, remainder);
    }

    return BigIntCustom(remainder.join(''));
  }

  // Comparison (basic)
  bool operator <(BigIntCustom other) {
    if (isNegative != other.isNegative) {
      return isNegative;
    }

    if (digits.length != other.digits.length) {
      return isNegative
          ? digits.length > other.digits.length
          : digits.length < other.digits.length;
    }

    for (int i = 0; i < digits.length; i++) {
      if (digits[i] != other.digits[i]) {
        return isNegative
            ? digits[i] > other.digits[i]
            : digits[i] < other.digits[i];
      }
    }

    return false;
  }

  bool operator >(BigIntCustom other) {
    return other < this;
  }

  bool operator ==(Object other) {
    if (other is! BigIntCustom) return false;
    return digits.join('') == other.digits.join('') &&
        isNegative == other.isNegative;
  }

  bool operator <=(BigIntCustom other) {
    return !(this > other);
  }

  bool operator >=(BigIntCustom other) {
    return !(this < other);
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

  // Helper function to check if the number is even
  bool get isEven => digits.last % 2 == 0;

  // Helper function to check if the number is odd
  bool get isOdd => digits.last % 2 != 0;
}

void main() {
  BigIntCustom a = BigIntCustom('123456789012345678901234567890123456789');
  BigIntCustom b = BigIntCustom('98765432109876543210987654321');

  print('a: $a');
  print('b: $b');

  // Test integer division (~/)
  BigIntCustom result = a ~/ b;
  print('a ~/ b: $result');

  // Test modulus (%)
  BigIntCustom remainder = a % b;
  print('a % b: $remainder');
}
